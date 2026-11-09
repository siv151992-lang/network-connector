// Package magicsock is WireMesh's WireGuard transport (a wireguard-go
// conn.Bind). One UDP socket per address family carries WireGuard, disco
// path-discovery messages and STUN. That's the property NAT traversal needs:
// the public mapping STUN discovers is the one WireGuard traffic uses, and
// disco pings sent from it punch holes that WireGuard then rides through.
//
// WireGuard is configured with identity endpoints ("wm:<node key hex>"), not
// addresses. On every send, magicsock picks the peer's current best path:
//
//   - a path is a peer address confirmed by an authenticated disco pong (or
//     ping) within the last pathTTL;
//   - the best path is the lowest-latency confirmed one (with hysteresis);
//   - with no confirmed path, WireGuard packets are held back (dropped; WireGuard
//     retries) while magicsock discovers one. Spraying them at unconfirmed
//     public addresses would break hole punching (see below).
//
// Hole punching through Linux-style NATs (most home routers): if our first
// packet reaches the peer's NAT before the peer has an outbound mapping to us,
// conntrack records it, and the peer's own mapping is then forced onto a
// different port that our NAT rejects. That deadlock lasts as long as either
// side keeps sending. To avoid it, path discovery first sends disco pings with
// a small TTL (2..4). They create our NAT mapping but expire in the network
// before reaching the peer's NAT, and a peer on the same LAN still receives
// them. Then a call-me-maybe goes over the control stream. The peer answers
// with normal pings, which pass our NAT because our mapping now exists. Normal
// TTL is used toward an unconfirmed address only in reply to the peer, or as a
// fallback while the control stream is down.
//
// Deadlocks can still happen when a path dies while traffic is flowing: a peer
// whose public IP changed keeps sending on the old path for a moment, which
// poisons the other NAT the same way. Linux drops such unanswered entries
// after 30 s of silence. So when 3 normal pings to a peer go unanswered, both
// sides quiesce together. We send a call-me-maybe with Quiesce set through
// the control server, and both peers send nothing to each other for
// QuiesceFor. Every stale entry on both NATs expires, and the two sides
// resume within milliseconds of each other with fresh punches, which map
// cleanly.
//
// Inbound WireGuard packets are attributed to a peer only if they come from a
// disco-verified address. Candidate addresses alone aren't trusted, because
// private LAN addresses collide across sites. Packets from unknown addresses
// are dropped until disco verifies them, which takes milliseconds.
//
// Relay fallback (when no direct path can be found) arrives in Phase 6.
package magicsock

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.zx2c4.com/wireguard/conn"

	"github.com/siv151992-lang/network-connector/pkg/disco"
	"github.com/siv151992-lang/network-connector/pkg/protocol"
	"github.com/siv151992-lang/network-connector/pkg/stun"
)

// Timing (exported for documentation; tests shorten them via Options).
const (
	DefaultPathTTL     = 15 * time.Second // a path with no pong for this long is stale
	DefaultHeartbeat   = 5 * time.Second  // ping the best path this often
	DefaultProbeEvery  = 5 * time.Second  // while pathless, re-probe all candidates this often
	DefaultCMMEvery    = 5 * time.Second  // and send call-me-maybe at most this often
	DefaultSTUNEvery   = 20 * time.Second
	reflexiveTTL       = 45 * time.Second // > 2 STUN rounds: stale public addresses age out fast after roaming
	pingTimeout        = 10 * time.Second
	maxPendingPerPeer  = 64
	maxCandidates      = 16
	switchImprovement  = 0.7 // switch paths only if the new one is 30% faster
	localCheckInterval = 5 * time.Second
)

// fallbackRounds: after this many punch rounds without a path, also send
// normal-TTL pings (helps when the peer has no NAT or no control stream).
const fallbackRounds = 3

// Synchronized quiescing (see package doc).
const quarantineAfter = 3

// QuiesceFor must exceed Linux conntrack's UDP unreplied timeout (30 s).
var QuiesceFor = 32 * time.Second

// PunchTTLs are the TTLs of hole-punching probes: enough to leave our own
// NAT(s), too few to reach a peer NAT several hops away.
var PunchTTLs = []int{2, 3, 4}

// Options configures a Conn.
type Options struct {
	Port         uint16
	DiscoPrivate protocol.PrivateKey
	// NodeKey is this device's WireGuard public key; pings carry it so the
	// receiver can bind our disco key to our WireGuard identity.
	NodeKey protocol.Key
	// ExcludeIface is the tunnel interface, never reported as an endpoint.
	ExcludeIface string
	Log          *slog.Logger

	PathTTL, Heartbeat, ProbeEvery, CMMEvery, STUNEvery time.Duration
	// LocalAddrs overrides interface enumeration (tests).
	LocalAddrs func() []netip.Addr
}

// Conn is the magic socket.
type Conn struct {
	o        Options
	log      *slog.Logger
	discoPub protocol.Key

	mu       sync.Mutex
	writeMu  sync.RWMutex // TTL changes for punch packets take it exclusively
	pc4, pc6 *net.UDPConn
	stunNow  atomic.Bool
	peers    map[protocol.Key]*peer // by node key
	byDisco  map[protocol.Key]*peer
	verified map[netip.AddrPort]*peer // disco-verified address -> peer

	stunServers []string
	stunTx      map[stun.TxID]time.Time
	reflexive   map[netip.AddrPort]time.Time
	lastLocal   []netip.AddrPort

	onEndpoints func()
	sendCMM     func(to protocol.Key, eps []netip.AddrPort, quiesce bool)

	wake   chan struct{}
	stop   chan struct{}
	closed atomic.Bool
	now    func() time.Time

	// Counters for status and tests.
	DroppedUnknown atomic.Uint64
	DiscoRx        atomic.Uint64
	Direct         atomic.Uint64 // WireGuard packets sent over a confirmed path
	NoPath         atomic.Uint64 // WireGuard packets held back while no path is confirmed
	Punches        atomic.Uint64 // low-TTL hole-punching probes sent
}

type path struct {
	lastPing time.Time
	lastPong time.Time
	latency  time.Duration
}

// unanswered counts recent normal-TTL pings to an address that got no pong.
// Counts older than unansweredReset are stale (the peer may have been quiet
// in the meantime, so a new attempt starts from zero).
type unanswered struct {
	n    int
	last time.Time
}

const unansweredReset = 20 * time.Second

type pending struct {
	to   netip.AddrPort
	sent time.Time
	ttl  int
}

type peer struct {
	nodeKey    protocol.Key
	discoKey   protocol.Key
	shared     disco.SharedKey
	ep         *peerEndpoint
	candidates []netip.AddrPort
	paths      map[netip.AddrPort]*path
	best       netip.AddrPort
	pending    map[disco.TxID]pending
	lastProbe  time.Time
	lastCMM    time.Time
	rounds     int                           // probe rounds since the last confirmed path
	sendQuiet  bool                          // tell the peer to quiesce on the next loop tick
	unanswered map[netip.AddrPort]unanswered // normal-TTL pings without a pong
	quiet      map[netip.AddrPort]time.Time  // quarantined until
}

// New creates a Conn. Sockets are opened by wireguard-go via Open.
func New(o Options) *Conn {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	def := func(d *time.Duration, v time.Duration) {
		if *d == 0 {
			*d = v
		}
	}
	def(&o.PathTTL, DefaultPathTTL)
	def(&o.Heartbeat, DefaultHeartbeat)
	def(&o.ProbeEvery, DefaultProbeEvery)
	def(&o.CMMEvery, DefaultCMMEvery)
	def(&o.STUNEvery, DefaultSTUNEvery)
	c := &Conn{
		o: o, log: o.Log, discoPub: o.DiscoPrivate.Public(),
		peers: map[protocol.Key]*peer{}, byDisco: map[protocol.Key]*peer{}, verified: map[netip.AddrPort]*peer{},
		stunTx: map[stun.TxID]time.Time{}, reflexive: map[netip.AddrPort]time.Time{},
		wake: make(chan struct{}, 1), stop: make(chan struct{}), now: time.Now,
	}
	go c.loop()
	return c
}

// OnEndpointsChanged registers a callback for when this device's reachable
// endpoints change (new STUN mapping, interface change).
func (c *Conn) OnEndpointsChanged(f func()) { c.mu.Lock(); c.onEndpoints = f; c.mu.Unlock() }

// SetCallMeMaybeSender registers how call-me-maybe reaches peers (the control
// stream). nil disables it while the stream is down.
func (c *Conn) SetCallMeMaybeSender(f func(to protocol.Key, eps []netip.AddrPort, quiesce bool)) {
	c.mu.Lock()
	c.sendCMM = f
	c.mu.Unlock()
}

// Shutdown stops background work (Close is wireguard-go's socket close).
func (c *Conn) Shutdown() {
	if c.closed.CompareAndSwap(false, true) {
		close(c.stop)
		_ = c.Close()
	}
}

// ---------------------------------------------------------------------------
// conn.Bind
// ---------------------------------------------------------------------------

var _ conn.Bind = (*Conn)(nil)

// Open binds UDP sockets on the configured port (IPv6 is optional).
func (c *Conn) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	if port == 0 {
		port = c.o.Port
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pc4 != nil || c.pc6 != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	var fns []conn.ReceiveFunc
	pc4, err := net.ListenUDP("udp4", &net.UDPAddr{Port: int(port)})
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		return nil, 0, err
	}
	if pc4 != nil {
		if port == 0 {
			port = uint16(pc4.LocalAddr().(*net.UDPAddr).Port)
		}
		c.pc4 = pc4
		fns = append(fns, c.receiver(pc4))
	}
	pc6, err := net.ListenUDP("udp6", &net.UDPAddr{Port: int(port)})
	if err == nil {
		c.pc6 = pc6
		fns = append(fns, c.receiver(pc6))
	}
	if len(fns) == 0 {
		return nil, 0, syscall.EAFNOSUPPORT
	}
	c.o.Port = port
	c.stunNow.Store(true) // sockets exist now: discover our public endpoint immediately
	c.poke()
	return fns, port, nil
}

// Close closes the sockets (wireguard-go reopens them on rebind).
func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pc4 != nil {
		c.pc4.Close()
		c.pc4 = nil
	}
	if c.pc6 != nil {
		c.pc6.Close()
		c.pc6 = nil
	}
	return nil
}

func (c *Conn) SetMark(uint32) error { return nil }
func (c *Conn) BatchSize() int       { return 1 }

// Port returns the bound UDP port.
func (c *Conn) Port() uint16 { c.mu.Lock(); defer c.mu.Unlock(); return c.o.Port }

// ParseEndpoint accepts "wm:<node key hex>" (identity) or "ip:port".
func (c *Conn) ParseEndpoint(s string) (conn.Endpoint, error) {
	if hexKey, ok := strings.CutPrefix(s, "wm:"); ok {
		var k protocol.Key
		if len(hexKey) != 64 {
			return nil, fmt.Errorf("magicsock: bad endpoint %q", s)
		}
		for i := 0; i < 32; i++ {
			v, err := strconv.ParseUint(hexKey[2*i:2*i+2], 16, 8)
			if err != nil {
				return nil, fmt.Errorf("magicsock: bad endpoint %q", s)
			}
			k[i] = byte(v)
		}
		return &peerEndpoint{c: c, key: k}, nil
	}
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return addrEndpoint(ap), nil
}

// receiver demultiplexes one socket: STUN and disco are handled here; only
// WireGuard packets from verified peer addresses reach wireguard-go.
func (c *Conn) receiver(pc *net.UDPConn) conn.ReceiveFunc {
	return func(pkts [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			n, src, err := pc.ReadFromUDPAddrPort(pkts[0])
			if err != nil {
				return 0, err
			}
			src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
			b := pkts[0][:n]
			switch {
			case stun.Is(b):
				c.handleSTUN(b, src)
				continue
			case disco.Is(b):
				c.handleDisco(b, src)
				continue
			}
			c.mu.Lock()
			p := c.verified[src]
			c.mu.Unlock()
			if p == nil {
				c.DroppedUnknown.Add(1)
				continue
			}
			sizes[0] = n
			eps[0] = p.ep
			return 1, nil
		}
	}
}

// Send transmits WireGuard packets to a peer over its best path, or sprays
// them to all candidates while no path is confirmed.
func (c *Conn) Send(bufs [][]byte, ep conn.Endpoint) error {
	switch e := ep.(type) {
	case addrEndpoint:
		for _, b := range bufs {
			if err := c.writeTo(netip.AddrPort(e), b); err != nil {
				return err
			}
		}
		return nil
	case *peerEndpoint:
		c.mu.Lock()
		p := c.peers[e.key]
		var best netip.AddrPort
		if p != nil && c.fresh(p, p.best) {
			best = p.best
		}
		c.mu.Unlock()
		if p == nil {
			return fmt.Errorf("magicsock: unknown peer")
		}
		if !best.IsValid() {
			// No confirmed path yet: hold back (see package doc) and make
			// sure discovery is running. WireGuard retransmits.
			c.NoPath.Add(uint64(len(bufs)))
			c.poke()
			return nil
		}
		for _, b := range bufs {
			if err := c.writeTo(best, b); err != nil {
				return err
			}
			c.Direct.Add(1)
		}
		return nil
	default:
		return conn.ErrWrongEndpointType
	}
}

func (c *Conn) writeTo(to netip.AddrPort, b []byte) error {
	c.writeMu.RLock()
	defer c.writeMu.RUnlock()
	c.mu.Lock()
	pc := c.pc4
	if to.Addr().Is6() {
		pc = c.pc6
	}
	c.mu.Unlock()
	if pc == nil {
		return net.ErrClosed
	}
	_, err := pc.WriteToUDPAddrPort(b, to)
	return err
}

// writeTTL sends b with a specific TTL/hop limit (hole punching). Normal
// writes pause for the microseconds the socket option is changed.
func (c *Conn) writeTTL(to netip.AddrPort, b []byte, ttl int) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.Lock()
	pc4, pc6 := c.pc4, c.pc6
	c.mu.Unlock()
	if to.Addr().Is4() {
		if pc4 == nil {
			return net.ErrClosed
		}
		ic := ipv4.NewConn(pc4)
		orig, err := ic.TTL()
		if err != nil {
			return err
		}
		if err := ic.SetTTL(ttl); err != nil {
			return err
		}
		defer ic.SetTTL(orig)
		_, err = pc4.WriteToUDPAddrPort(b, to)
		return err
	}
	if pc6 == nil {
		return net.ErrClosed
	}
	ic := ipv6.NewConn(pc6)
	orig, err := ic.HopLimit()
	if err != nil {
		return err
	}
	if err := ic.SetHopLimit(ttl); err != nil {
		return err
	}
	defer ic.SetHopLimit(orig)
	_, err = pc6.WriteToUDPAddrPort(b, to)
	return err
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

type peerEndpoint struct {
	c   *Conn
	key protocol.Key
}

func (e *peerEndpoint) ClearSrc()           {}
func (e *peerEndpoint) SrcToString() string { return "" }
func (e *peerEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e *peerEndpoint) DstToBytes() []byte  { return e.key[:] }
func (e *peerEndpoint) best() netip.AddrPort {
	e.c.mu.Lock()
	defer e.c.mu.Unlock()
	if p := e.c.peers[e.key]; p != nil && e.c.fresh(p, p.best) {
		return p.best
	}
	return netip.AddrPort{}
}

// DstToString shows the current direct path (what `wg show` / status print).
func (e *peerEndpoint) DstToString() string {
	if b := e.best(); b.IsValid() {
		return b.String()
	}
	return "wm:" + e.key.Hex()
}
func (e *peerEndpoint) DstIP() netip.Addr { return e.best().Addr() }

type addrEndpoint netip.AddrPort

func (e addrEndpoint) ClearSrc()           {}
func (e addrEndpoint) SrcToString() string { return "" }
func (e addrEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e addrEndpoint) DstToString() string { return netip.AddrPort(e).String() }
func (e addrEndpoint) DstIP() netip.Addr   { return netip.AddrPort(e).Addr() }
func (e addrEndpoint) DstToBytes() []byte {
	b, _ := netip.AddrPort(e).MarshalBinary()
	return b
}

// ---------------------------------------------------------------------------
// Peers
// ---------------------------------------------------------------------------

// SetPeers replaces the peer table from a network map. Paths to peers that
// remain are kept, so a map update never interrupts traffic.
func (c *Conn) SetPeers(nodes []protocol.Node, stunServers []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	seen := map[protocol.Key]bool{}
	for _, n := range nodes {
		if n.NodeKey.IsZero() || n.DiscoKey.IsZero() {
			continue
		}
		seen[n.NodeKey] = true
		p := c.peers[n.NodeKey]
		if p == nil {
			p = &peer{nodeKey: n.NodeKey, paths: map[netip.AddrPort]*path{}, pending: map[disco.TxID]pending{},
				unanswered: map[netip.AddrPort]unanswered{}, quiet: map[netip.AddrPort]time.Time{}}
			p.ep = &peerEndpoint{c: c, key: n.NodeKey}
			c.peers[n.NodeKey] = p
		}
		if p.discoKey != n.DiscoKey {
			if !p.discoKey.IsZero() {
				delete(c.byDisco, p.discoKey)
				c.forgetPathsLocked(p) // new disco key: old verifications are void
			}
			p.discoKey = n.DiscoKey
			p.shared = disco.Shared(c.o.DiscoPrivate, n.DiscoKey)
			c.byDisco[n.DiscoKey] = p
		}
		eps := slices.Clone(n.Endpoints)
		if len(eps) > maxCandidates {
			eps = eps[:maxCandidates]
		}
		p.candidates = eps
	}
	for k, p := range c.peers {
		if !seen[k] {
			c.forgetPathsLocked(p)
			delete(c.byDisco, p.discoKey)
			delete(c.peers, k)
		}
	}
	if !slices.Equal(c.stunServers, stunServers) {
		c.stunServers = slices.Clone(stunServers)
		c.stunNow.Store(true) // learn our public endpoint right away
	}
	c.poke()
}

func (c *Conn) forgetPathsLocked(p *peer) {
	for a := range p.paths {
		if c.verified[a] == p {
			delete(c.verified, a)
		}
	}
	p.paths = map[netip.AddrPort]*path{}
	p.best = netip.AddrPort{}
}

func (c *Conn) fresh(p *peer, a netip.AddrPort) bool {
	if !a.IsValid() {
		return false
	}
	pt := p.paths[a]
	return pt != nil && !pt.lastPong.IsZero() && c.now().Sub(pt.lastPong) < c.o.PathTTL
}

// allAddrs is every address worth trying: candidates plus learned paths.
func (c *Conn) allAddrs(p *peer) []netip.AddrPort {
	set := map[netip.AddrPort]bool{}
	var out []netip.AddrPort
	add := func(a netip.AddrPort) {
		if a.IsValid() && !set[a] {
			set[a] = true
			out = append(out, a)
		}
	}
	for _, a := range p.candidates {
		add(a)
	}
	for a := range p.paths {
		add(a)
	}
	return out
}

// PeerPath reports a peer's current best direct path (invalid if none).
func (c *Conn) PeerPath(k protocol.Key) (netip.AddrPort, time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.peers[k]
	if p == nil || !c.fresh(p, p.best) {
		return netip.AddrPort{}, 0
	}
	return p.best, p.paths[p.best].latency
}

// HandleCallMeMaybe is called when a peer (via the control server) asks us
// to probe it now. Probing immediately, while the peer probes us, opens
// mappings on both NATs at the same moment.
func (c *Conn) HandleCallMeMaybe(from protocol.Key, eps []netip.AddrPort, quiesce bool) {
	c.mu.Lock()
	p := c.peers[from]
	if p == nil {
		c.mu.Unlock()
		return
	}
	if quiesce {
		if !c.fresh(p, p.best) {
			c.quiesceLocked(p, c.now(), "peer asked")
		}
		c.mu.Unlock()
		return
	}
	for _, e := range eps {
		if len(p.candidates) < maxCandidates && !slices.Contains(p.candidates, e) {
			p.candidates = append(p.candidates, e)
		}
	}
	targets := eps
	if len(targets) > maxCandidates {
		targets = targets[:maxCandidates]
	}
	pings := c.preparePingsLocked(p, targets)
	c.mu.Unlock()
	c.log.Debug("call-me-maybe received; probing", "peer", from.String()[:8], "endpoints", fmt.Sprint(eps))
	c.sendAll(pings)
}

// quiesceLocked silences everything we send to p for QuiesceFor.
func (c *Conn) quiesceLocked(p *peer, now time.Time, why string) {
	until := now.Add(QuiesceFor)
	for _, a := range c.allAddrs(p) {
		p.quiet[a] = until
	}
	p.unanswered = map[netip.AddrPort]unanswered{}
	p.lastProbe = until.Add(-c.o.ProbeEvery) // probe again as soon as the quiet period ends
	c.log.Info("quiescing toward peer so stale NAT state can expire", "peer", p.nodeKey.String()[:8], "for", QuiesceFor, "reason", why)
}

// ---------------------------------------------------------------------------
// Disco
// ---------------------------------------------------------------------------

type outPkt struct {
	to  netip.AddrPort
	b   []byte
	ttl int // 0 = socket default
}

func (c *Conn) sendAll(pkts []outPkt) {
	for _, p := range pkts {
		if p.ttl > 0 {
			if err := c.writeTTL(p.to, p.b, p.ttl); err != nil {
				c.log.Debug("punch write failed", "to", p.to, "error", err)
			}
			c.Punches.Add(1)
			continue
		}
		_ = c.writeTo(p.to, p.b)
	}
}

// preparePunchesLocked builds low-TTL pings (one per TTL in PunchTTLs).
func (c *Conn) preparePunchesLocked(p *peer, targets []netip.AddrPort) []outPkt {
	var out []outPkt
	for _, ttl := range PunchTTLs {
		out = append(out, c.preparePingsTTLLocked(p, targets, ttl)...)
	}
	return out
}

// preparePingsLocked builds sealed normal-TTL pings to targets and records
// them as pending. Quarantined addresses are skipped.
func (c *Conn) preparePingsLocked(p *peer, targets []netip.AddrPort) []outPkt {
	return c.preparePingsTTLLocked(p, targets, 0)
}

func (c *Conn) quietLocked(p *peer, t netip.AddrPort, now time.Time) bool {
	until, ok := p.quiet[t]
	if !ok {
		return false
	}
	if now.Before(until) {
		return true
	}
	delete(p.quiet, t)
	return false
}

func (c *Conn) preparePingsTTLLocked(p *peer, targets []netip.AddrPort, ttl int) []outPkt {
	now := c.now()
	var out []outPkt
	for _, t := range targets {
		if len(p.pending) >= maxPendingPerPeer {
			break
		}
		if c.quietLocked(p, t, now) {
			continue
		}
		if ttl == 0 && t != p.best {
			u := p.unanswered[t]
			if now.Sub(u.last) > unansweredReset {
				u.n = 0
			}
			u.n++
			u.last = now
			p.unanswered[t] = u
			if u.n >= quarantineAfter {
				c.quiesceLocked(p, now, "unanswered pings to "+t.String())
				p.sendQuiet = true
				return out
			}
		}
		tx := disco.NewTxID()
		pkt, err := disco.Seal(disco.Message{Type: disco.TypePing, TxID: tx, NodeKey: c.o.NodeKey}, c.discoPub, p.shared)
		if err != nil {
			continue
		}
		p.pending[tx] = pending{to: t, sent: now, ttl: ttl}
		if pt := p.paths[t]; pt != nil {
			pt.lastPing = now
		}
		out = append(out, outPkt{to: t, b: pkt, ttl: ttl})
	}
	return out
}

func (c *Conn) handleDisco(b []byte, src netip.AddrPort) {
	sender, _ := disco.Sender(b)
	c.mu.Lock()
	p := c.byDisco[sender]
	if p == nil {
		c.mu.Unlock()
		return // not a peer: ignore (also stops reflection by strangers)
	}
	msg, err := disco.Open(b, p.shared)
	if err != nil {
		c.mu.Unlock()
		return
	}
	c.DiscoRx.Add(1)
	now := c.now()
	var out []outPkt
	switch msg.Type {
	case disco.TypePing:
		if msg.NodeKey != p.nodeKey {
			c.mu.Unlock()
			return // disco key not bound to this WireGuard identity
		}
		// An authenticated ping proves src reaches us. Learn it, answer,
		// and (if we have no path yet) probe it back right away.
		c.learnLocked(p, src)
		if pong, err := disco.Seal(disco.Message{Type: disco.TypePong, TxID: msg.TxID, Src: src}, c.discoPub, p.shared); err == nil {
			out = append(out, outPkt{to: src, b: pong})
		}
		if !c.fresh(p, src) {
			// New or stale address (peer roamed, or a NAT hole just opened):
			// probe it back so it becomes a confirmed path right away.
			out = append(out, c.preparePingsLocked(p, []netip.AddrPort{src})...)
		}
	case disco.TypePong:
		pd, ok := p.pending[msg.TxID]
		if !ok || pd.to != src {
			c.mu.Unlock()
			return // unsolicited, or answered from an unexpected address
		}
		delete(p.pending, msg.TxID)
		delete(p.unanswered, src)
		delete(p.quiet, src)
		pt := c.learnLocked(p, src)
		pt.lastPong = now
		pt.latency = now.Sub(pd.sent)
		c.chooseBestLocked(p)
		// How the peer sees us is a usable public endpoint for ourselves.
		if msg.Src.IsValid() && !msg.Src.Addr().IsPrivate() {
			c.addReflexiveLocked(msg.Src)
		}
	}
	c.mu.Unlock()
	c.sendAll(out)
}

func (c *Conn) learnLocked(p *peer, a netip.AddrPort) *path {
	pt := p.paths[a]
	if pt == nil {
		pt = &path{}
		p.paths[a] = pt
	}
	if old := c.verified[a]; old != nil && old != p {
		// The address moved to another peer (e.g. NAT port reuse).
		delete(old.paths, a)
		if old.best == a {
			old.best = netip.AddrPort{}
		}
	}
	c.verified[a] = p
	return pt
}

func (c *Conn) chooseBestLocked(p *peer) {
	var best netip.AddrPort
	var bestLat time.Duration
	for a, pt := range p.paths {
		if !c.fresh(p, a) {
			continue
		}
		if !best.IsValid() || pt.latency < bestLat {
			best, bestLat = a, pt.latency
		}
	}
	cur := p.best
	if c.fresh(p, cur) && best != cur {
		// Hysteresis: only move if clearly better.
		if float64(bestLat) > switchImprovement*float64(p.paths[cur].latency) {
			return
		}
	}
	if best != cur {
		p.best = best
		if best.IsValid() {
			c.log.Info("direct path selected", "peer", p.nodeKey.String()[:8], "path", best.String(), "latency", bestLat.Round(time.Microsecond))
		}
	}
}

// ---------------------------------------------------------------------------
// STUN and local endpoints
// ---------------------------------------------------------------------------

func (c *Conn) addReflexiveLocked(a netip.AddrPort) {
	_, known := c.reflexive[a]
	c.reflexive[a] = c.now()
	if !known && c.onEndpoints != nil {
		go c.onEndpoints()
	}
}

func (c *Conn) handleSTUN(b []byte, src netip.AddrPort) {
	tx, mapped, err := stun.ParseResponse(b)
	if err != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.stunTx[tx]; !ok {
		return // not ours (or replayed)
	}
	delete(c.stunTx, tx)
	if mapped.Port() == 0 || mapped.Addr().IsUnspecified() {
		return
	}
	c.addReflexiveLocked(mapped)
}

func (c *Conn) sendSTUN() {
	c.mu.Lock()
	servers := slices.Clone(c.stunServers)
	now := c.now()
	for tx, t := range c.stunTx {
		if now.Sub(t) > time.Minute {
			delete(c.stunTx, tx)
		}
	}
	c.mu.Unlock()
	for _, s := range servers {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", hostOf(s))
		cancel()
		if err != nil {
			c.log.Debug("stun: resolve failed", "server", s, "error", err)
			continue
		}
		port := portOf(s)
		for _, ip := range ips {
			tx := stun.NewTxID()
			c.mu.Lock()
			c.stunTx[tx] = now
			c.mu.Unlock()
			_ = c.writeTo(netip.AddrPortFrom(ip.Unmap(), port), stun.Request(tx))
		}
	}
}

func hostOf(hp string) string { h, _, _ := net.SplitHostPort(hp); return h }
func portOf(hp string) uint16 {
	_, p, _ := net.SplitHostPort(hp)
	n, _ := strconv.Atoi(p)
	return uint16(n)
}

// Endpoints returns this device's candidate endpoints: STUN-discovered public
// addresses first, then local interface addresses, all on the WireGuard port.
func (c *Conn) Endpoints() []netip.AddrPort {
	c.mu.Lock()
	now := c.now()
	port := c.o.Port
	var out []netip.AddrPort
	for a, t := range c.reflexive {
		if now.Sub(t) < reflexiveTTL {
			out = append(out, a)
		} else {
			delete(c.reflexive, a)
		}
	}
	c.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	for _, ip := range c.localAddrs() {
		ap := netip.AddrPortFrom(ip, port)
		if !slices.Contains(out, ap) {
			out = append(out, ap)
		}
	}
	if len(out) > maxCandidates {
		out = out[:maxCandidates]
	}
	return out
}

func (c *Conn) localAddrs() []netip.Addr {
	if c.o.LocalAddrs != nil {
		return c.o.LocalAddrs()
	}
	var out []netip.Addr
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if ifc.Name == c.o.ExcludeIface || ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
				continue
			}
			out = append(out, ip)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Is4() != out[j].Is4() {
			return out[i].Is4()
		}
		return out[i].Less(out[j])
	})
	return out
}

// ---------------------------------------------------------------------------
// Background loop
// ---------------------------------------------------------------------------

func (c *Conn) poke() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *Conn) loop() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var lastSTUN, lastLocalCheck time.Time
	for {
		select {
		case <-c.stop:
			return
		case <-tick.C:
		case <-c.wake:
		}
		now := c.now()

		// Roaming: if our local addresses changed, every path may be dead.
		if now.Sub(lastLocalCheck) >= localCheckInterval {
			lastLocalCheck = now
			local := c.localAddrPorts()
			c.mu.Lock()
			changed := c.lastLocal != nil && !slices.Equal(local, c.lastLocal)
			first := c.lastLocal == nil
			c.lastLocal = local
			if changed {
				c.log.Info("local addresses changed; re-discovering paths", "addresses", fmt.Sprint(local))
				for _, p := range c.peers {
					p.best = netip.AddrPort{}
					p.lastProbe = time.Time{}
				}
				c.reflexive = map[netip.AddrPort]time.Time{}
			}
			cb := c.onEndpoints
			c.mu.Unlock()
			if changed || first {
				lastSTUN = time.Time{}
				if cb != nil {
					go cb()
				}
			}
		}

		if c.stunNow.Swap(false) {
			lastSTUN = time.Time{}
		}
		if now.Sub(lastSTUN) >= c.o.STUNEvery {
			lastSTUN = now
			go c.sendSTUN()
		}

		c.mu.Lock()
		var out []outPkt
		type cmm struct {
			to protocol.Key
		}
		var cmms []cmm
		var quiesces []protocol.Key
		for _, p := range c.peers {
			if p.sendQuiet {
				p.sendQuiet = false
				quiesces = append(quiesces, p.nodeKey)
			}
			for tx, pd := range p.pending {
				if now.Sub(pd.sent) > pingTimeout {
					delete(p.pending, tx)
				}
			}
			if c.fresh(p, p.best) {
				p.rounds = 0
				if pt := p.paths[p.best]; now.Sub(pt.lastPing) >= c.o.Heartbeat {
					out = append(out, c.preparePingsLocked(p, []netip.AddrPort{p.best})...)
				}
				continue
			}
			if p.best.IsValid() {
				c.log.Info("direct path lost", "peer", p.nodeKey.String()[:8], "path", p.best.String())
				p.best = netip.AddrPort{}
			}
			if now.Sub(p.lastProbe) >= c.o.ProbeEvery {
				p.lastProbe = now
				p.rounds++
				targets := c.allAddrs(p)
				// Punch first (opens our NAT without poisoning theirs), then
				// ask the peer to probe us via the control server.
				punches := c.preparePunchesLocked(p, targets)
				out = append(out, punches...)
				// Ask the peer to probe us only if we really just punched:
				// its normal-TTL reply must find a fresh mapping on our NAT,
				// or it poisons our NAT (see package doc).
				if len(punches) > 0 && c.sendCMM != nil && now.Sub(p.lastCMM) >= c.o.CMMEvery {
					p.lastCMM = now
					cmms = append(cmms, cmm{p.nodeKey})
				}
				if c.sendCMM == nil && p.rounds > fallbackRounds {
					out = append(out, c.preparePingsLocked(p, targets)...)
				}
			}
		}
		send := c.sendCMM
		c.mu.Unlock()
		c.sendAll(out)
		if send != nil {
			for _, k := range quiesces {
				send(k, nil, true)
			}
			if len(cmms) > 0 {
				eps := c.Endpoints()
				for _, m := range cmms {
					send(m.to, eps, false)
				}
			}
		}
	}
}

func (c *Conn) localAddrPorts() []netip.AddrPort {
	var out []netip.AddrPort
	for _, ip := range c.localAddrs() {
		out = append(out, netip.AddrPortFrom(ip, c.Port()))
	}
	return out
}
