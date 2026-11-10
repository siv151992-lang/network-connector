package client

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/siv151992-lang/network-connector/pkg/client/magicsock"
	"github.com/siv151992-lang/network-connector/pkg/protocol"
)

// DefaultMTU leaves room for WireGuard overhead over IPv6 paths with a 1280
// minimum MTU; it is what most mesh VPNs use.
const DefaultMTU = 1280

// OSConfigurator applies addresses and routes to the tunnel interface.
// Implemented per platform (Linux: netlink; Windows: winipcfg in Phase 8;
// Android: VpnService.Builder in Phase 7).
type OSConfigurator interface {
	Set(addrs, routes []netip.Prefix) error
	Close() error
}

// EngineConfig configures a tunnel.
type EngineConfig struct {
	InterfaceName string // e.g. "wm0"
	PrivateKey    protocol.PrivateKey
	DiscoPrivate  protocol.PrivateKey
	RelayToken    func(ctx context.Context) (string, error)
	ListenPort    uint16 // 0 picks a random port
	MTU           int
	Log           *slog.Logger
}

// peerConfig is what we last told WireGuard about a peer. The endpoint is
// always the peer's identity (wm:<key>); magicsock picks the actual path.
type peerConfig struct {
	allowedIPs []netip.Prefix
}

// Engine is a running WireGuard tunnel plus its packet filter.
type Engine struct {
	log    *slog.Logger
	tun    tun.Device
	dev    *device.Device
	Filter *Filter
	ifname string
	osc    OSConfigurator
	uapi   io.Closer
	ms     *magicsock.Conn
	dns    DNSServer
	dnsIP  netip.Addr

	mu      sync.Mutex
	peers   map[protocol.Key]peerConfig
	addrs   []netip.Prefix
	routes  []netip.Prefix
	closed  bool
	stopped chan struct{}
}

// NewEngine creates the TUN interface and starts WireGuard on it.
func NewEngine(cfg EngineConfig) (*Engine, error) {
	if cfg.MTU == 0 {
		cfg.MTU = DefaultMTU
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.ListenPort == 0 {
		// Choose the random port ourselves so it is known before binding.
		var b [2]byte
		_, _ = rand.Read(b[:])
		cfg.ListenPort = 49152 + binary.BigEndian.Uint16(b[:])%16000
	}
	tdev, err := tun.CreateTUN(cfg.InterfaceName, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("create TUN %q: %w (are you root / have CAP_NET_ADMIN?)", cfg.InterfaceName, err)
	}
	name, err := tdev.Name()
	if err != nil {
		tdev.Close()
		return nil, err
	}
	e := &Engine{log: cfg.Log.With("iface", name), tun: tdev, Filter: NewFilter(), ifname: name,
		peers: map[protocol.Key]peerConfig{}, stopped: make(chan struct{})}
	e.ms = magicsock.New(magicsock.Options{Port: cfg.ListenPort, DiscoPrivate: cfg.DiscoPrivate,
		NodeKey: cfg.PrivateKey.Public(), ExcludeIface: name, Log: e.log, RelayToken: cfg.RelayToken})

	logger := &device.Logger{
		Verbosef: func(format string, args ...any) { e.log.Debug("wireguard: " + fmt.Sprintf(format, args...)) },
		Errorf:   func(format string, args ...any) { e.log.Warn("wireguard: " + fmt.Sprintf(format, args...)) },
	}
	e.dev = device.NewDevice(&filteredTUN{Device: tdev, f: e.Filter}, e.ms, logger)
	fail := func(err error) (*Engine, error) {
		e.dev.Close()
		e.ms.Shutdown()
		return nil, err
	}
	if err := e.dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", cfg.PrivateKey.Hex(), cfg.ListenPort)); err != nil {
		return fail(fmt.Errorf("configure wireguard: %w", err))
	}
	if err := e.dev.Up(); err != nil {
		return fail(fmt.Errorf("wireguard up: %w", err))
	}
	if e.osc, err = newOSConfigurator(name, tdev, e.log); err != nil {
		return fail(err)
	}
	// Expose the standard UAPI socket so `wg show` and `wiremesh status` work.
	if e.uapi, err = startUAPI(name, e.dev, e.log); err != nil {
		e.log.Warn("UAPI socket unavailable; `wg show` won't see this interface", "error", err)
	}
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-e.stopped:
				return
			case <-t.C:
				e.Filter.ct.expire()
			}
		}
	}()
	e.log.Info("tunnel up", "listen_port", e.ListenPort(), "mtu", cfg.MTU)
	return e, nil
}

// Name returns the OS interface name.
func (e *Engine) Name() string { return e.ifname }

// ListenPort returns the UDP port WireGuard (and disco/STUN) use.
func (e *Engine) ListenPort() uint16 { return e.ms.Port() }

// Magic exposes the transport for the run loop (endpoints, call-me-maybe).
func (e *Engine) Magic() *magicsock.Conn { return e.ms }

// Apply reconfigures the tunnel for a network map: interface addresses and
// routes, WireGuard peers (incrementally, so existing sessions survive) and
// the inbound packet filter.
func (e *Engine) Apply(nm *protocol.NetworkMap) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return errors.New("engine closed")
	}

	routes := []netip.Prefix{nm.Network.IPv4CIDR, nm.Network.IPv6CIDR}
	for _, p := range nm.Peers {
		for _, a := range p.AllowedIPs {
			if !nm.Network.IPv4CIDR.Contains(a.Addr()) && !nm.Network.IPv6CIDR.Contains(a.Addr()) {
				routes = append(routes, a) // approved subnet routes (Phase 9)
			}
		}
	}
	if !slices.Equal(e.addrs, nm.Self.Addresses) || !slices.Equal(e.routes, routes) {
		if err := e.osc.Set(nm.Self.Addresses, routes); err != nil {
			return fmt.Errorf("configure interface: %w", err)
		}
		e.addrs, e.routes = slices.Clone(nm.Self.Addresses), routes
		e.log.Info("interface configured", "addresses", fmt.Sprint(nm.Self.Addresses))
	}

	// Filter first, so newly added peers are never unfiltered; then the
	// transport's peer table, so WireGuard never sends to an unknown peer.
	e.Filter.SetRules(nm.PacketFilter, nm.Self.Addresses)
	e.ms.SetPeers(nm.Peers, nm.STUNServers, nm.Relays)

	e.applyDNS(nm)

	uapi, next := peerDiff(e.peers, nm.Peers)
	if uapi != "" {
		if err := e.dev.IpcSet(uapi); err != nil {
			return fmt.Errorf("configure peers: %w", err)
		}
		e.log.Info("peers updated", "count", len(next))
	}
	e.peers = next
	return nil
}

// peerDiff builds the UAPI commands that move WireGuard from the current
// peer set to the desired one, touching only what changed.
func peerDiff(cur map[protocol.Key]peerConfig, desired []protocol.Node) (string, map[protocol.Key]peerConfig) {
	next := make(map[protocol.Key]peerConfig, len(desired))
	var b strings.Builder
	for _, p := range desired {
		if p.NodeKey.IsZero() {
			continue
		}
		allowed := slices.Clone(p.AllowedIPs)
		sort.Slice(allowed, func(i, j int) bool { return allowed[i].String() < allowed[j].String() })
		pc := peerConfig{allowedIPs: allowed}
		next[p.NodeKey] = pc
		old, existed := cur[p.NodeKey]
		ipsChanged := !slices.Equal(old.allowedIPs, pc.allowedIPs)
		if existed && !ipsChanged {
			continue
		}
		fmt.Fprintf(&b, "public_key=%s\n", p.NodeKey.Hex())
		if !existed {
			// Identity endpoint: magicsock resolves it to the best path per packet.
			fmt.Fprintf(&b, "endpoint=wm:%s\n", p.NodeKey.Hex())
			// Keepalives hold NAT mappings open and make liveness visible.
			b.WriteString("persistent_keepalive_interval=25\n")
		}
		if ipsChanged || !existed {
			b.WriteString("replace_allowed_ips=true\n")
			for _, a := range pc.allowedIPs {
				fmt.Fprintf(&b, "allowed_ip=%s\n", a)
			}
		}
	}
	var removed []string
	for k := range cur {
		if _, ok := next[k]; !ok {
			removed = append(removed, k.Hex())
		}
	}
	sort.Strings(removed)
	for _, k := range removed {
		fmt.Fprintf(&b, "public_key=%s\nremove=true\n", k)
	}
	return b.String(), next
}

// PeerStats is runtime state for one peer, read from WireGuard.
type PeerStats struct {
	Endpoint      string
	LastHandshake time.Time
	RxBytes       uint64
	TxBytes       uint64
}

// Stats reads per-peer runtime statistics.
func (e *Engine) Stats() (map[protocol.Key]PeerStats, error) {
	s, err := e.dev.IpcGet()
	if err != nil {
		return nil, err
	}
	return ParseUAPIStats(s), nil
}

// ParseUAPIStats parses the output of a UAPI "get=1" operation.
func ParseUAPIStats(s string) map[protocol.Key]PeerStats {
	out := map[protocol.Key]PeerStats{}
	var cur protocol.Key
	var st PeerStats
	var sec, nsec int64
	flush := func() {
		if !cur.IsZero() {
			if sec > 0 {
				st.LastHandshake = time.Unix(sec, nsec)
			}
			out[cur] = st
		}
	}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			flush()
			var key protocol.Key
			if b, err := hexDecode32(v); err == nil {
				key = b
			}
			cur, st, sec, nsec = key, PeerStats{}, 0, 0
		case "endpoint":
			st.Endpoint = v
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(v, 10, 64)
		case "rx_bytes":
			st.RxBytes, _ = strconv.ParseUint(v, 10, 64)
		case "tx_bytes":
			st.TxBytes, _ = strconv.ParseUint(v, 10, 64)
		}
	}
	flush()
	return out
}

func hexDecode32(s string) (protocol.Key, error) {
	var k protocol.Key
	if len(s) != 64 {
		return k, errors.New("bad key length")
	}
	for i := 0; i < 32; i++ {
		v, err := strconv.ParseUint(s[2*i:2*i+2], 16, 8)
		if err != nil {
			return k, err
		}
		k[i] = byte(v)
	}
	return k, nil
}

// Close tears down the tunnel and removes the interface.
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	close(e.stopped)
	if e.uapi != nil {
		e.uapi.Close()
	}
	if e.osc != nil {
		_ = e.osc.Close()
	}
	e.dns.Close()
	e.dev.Close() // also closes the TUN device, which deletes the interface
	e.ms.Shutdown()
	e.log.Info("tunnel down")
	return nil
}

// applyDNS keeps the MagicDNS server current and, when our tunnel address
// changes, (re)binds it there and points the OS resolver at it for the
// network's domain only.
func (e *Engine) applyDNS(nm *protocol.NetworkMap) {
	if nm.Network.Domain == "" {
		return
	}
	e.dns.Update(nm)
	var v4 netip.Addr
	for _, p := range nm.Self.Addresses {
		if p.Addr().Is4() {
			v4 = p.Addr()
		}
	}
	if !v4.IsValid() || v4 == e.dnsIP {
		return
	}
	e.dns.Close()
	if err := e.dns.Listen(netip.AddrPortFrom(v4, 53)); err != nil {
		e.log.Warn("MagicDNS server not started", "error", err)
		return
	}
	e.dnsIP = v4
	if err := configureSystemDNS(e.ifname, v4, nm.Network.Domain); err != nil {
		e.log.Info("MagicDNS is running, but the system resolver was not configured", "server", v4, "domain", nm.Network.Domain, "reason", err)
	} else {
		e.log.Info("MagicDNS configured", "server", v4, "domain", nm.Network.Domain)
	}
}

// DNSAddr returns where the MagicDNS server listens (invalid if not running).
func (e *Engine) DNSAddr() netip.Addr { return e.dnsIP }
