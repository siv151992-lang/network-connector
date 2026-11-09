package magicsock

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/siv151992-lang/network-connector/pkg/disco"
	"github.com/siv151992-lang/network-connector/pkg/protocol"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// node is one WireGuard device on loopback using a magicsock.
type node struct {
	ms      *Conn
	dev     *device.Device
	tun     *tuntest.ChannelTUN
	node    protocol.PrivateKey
	disco   protocol.PrivateKey
	tunAddr netip.Addr
}

func freePort(t *testing.T) uint16 {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port)
}

func newNode(t *testing.T, tunAddr string) *node {
	t.Helper()
	nk, _ := protocol.NewPrivateKey()
	dk, _ := protocol.NewPrivateKey()
	n := &node{node: nk, disco: dk, tun: tuntest.NewChannelTUN(), tunAddr: netip.MustParseAddr(tunAddr)}
	n.ms = New(Options{
		Port: freePort(t), DiscoPrivate: dk, NodeKey: nk.Public(), Log: quiet,
		PathTTL: 3 * time.Second, Heartbeat: 500 * time.Millisecond, ProbeEvery: 300 * time.Millisecond,
		LocalAddrs: func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("127.0.0.1")} },
	})
	n.dev = device.NewDevice(n.tun.TUN(), n.ms, device.NewLogger(device.LogLevelSilent, ""))
	if err := n.dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", nk.Hex(), n.ms.Port())); err != nil {
		t.Fatal(err)
	}
	if err := n.dev.Up(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.dev.Close(); n.ms.Shutdown() })
	return n
}

func (n *node) asPeer(eps ...netip.AddrPort) protocol.Node {
	return protocol.Node{NodeKey: n.node.Public(), DiscoKey: n.disco.Public(),
		AllowedIPs: []netip.Prefix{netip.PrefixFrom(n.tunAddr, 32)}, Endpoints: eps}
}

func (n *node) addr() netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), n.ms.Port())
}

// connect configures a and b as WireGuard peers through their magicsocks.
func connect(t *testing.T, a, b *node, aSeesB, bSeesA []netip.AddrPort) {
	t.Helper()
	a.ms.SetPeers([]protocol.Node{b.asPeer(aSeesB...)}, nil)
	b.ms.SetPeers([]protocol.Node{a.asPeer(bSeesA...)}, nil)
	for _, pair := range [][2]*node{{a, b}, {b, a}} {
		self, peer := pair[0], pair[1]
		cfg := fmt.Sprintf("public_key=%s\nendpoint=wm:%s\npersistent_keepalive_interval=1\nallowed_ip=%s/32\n",
			peer.node.Public().Hex(), peer.node.Public().Hex(), peer.tunAddr)
		if err := self.dev.IpcSet(cfg); err != nil {
			t.Fatal(err)
		}
	}
}

func ping(t *testing.T, from, to *node) {
	t.Helper()
	pkt := tuntest.Ping(to.tunAddr, from.tunAddr)
	deadline := time.After(10 * time.Second)
	for {
		select {
		case from.tun.Outbound <- pkt:
		case <-deadline:
			t.Fatalf("ping %s -> %s timed out", from.tunAddr, to.tunAddr)
		}
		select {
		case got := <-to.tun.Inbound:
			if bytes.Equal(got, pkt) {
				return
			}
		case <-time.After(300 * time.Millisecond):
		case <-deadline:
			t.Fatalf("ping %s -> %s timed out", from.tunAddr, to.tunAddr)
		}
	}
}

func TestWireGuardOverMagicsock(t *testing.T) {
	a, b := newNode(t, "100.64.0.1"), newNode(t, "100.64.0.2")
	connect(t, a, b, []netip.AddrPort{b.addr()}, []netip.AddrPort{a.addr()})

	ping(t, a, b)
	ping(t, b, a)

	// Both sides found and verified the direct path.
	waitFor(t, "direct path a->b", func() bool { p, _ := a.ms.PeerPath(b.node.Public()); return p == b.addr() })
	waitFor(t, "direct path b->a", func() bool { p, _ := b.ms.PeerPath(a.node.Public()); return p == a.addr() })
	if a.ms.Direct.Load() == 0 {
		t.Fatal("no packets sent over the confirmed direct path")
	}
	// wg show-style output reports the real path, not the identity.
	st, _ := a.dev.IpcGet()
	if !bytes.Contains([]byte(st), []byte("endpoint="+b.addr().String())) {
		t.Fatalf("UAPI endpoint not the direct path:\n%s", st)
	}
}

// One side knows nothing about the other's address: the peer's pings
// (learned via call-me-maybe in production) let it discover the path.
func TestOneSidedCandidates(t *testing.T) {
	a, b := newNode(t, "100.64.0.1"), newNode(t, "100.64.0.2")
	connect(t, a, b, []netip.AddrPort{b.addr()}, nil) // b has no candidate for a
	ping(t, a, b)
	ping(t, b, a)
	waitFor(t, "b learned a's address from its ping", func() bool { p, _ := b.ms.PeerPath(a.node.Public()); return p == a.addr() })
}

func TestCallMeMaybeTriggersProbe(t *testing.T) {
	a, b := newNode(t, "100.64.0.1"), newNode(t, "100.64.0.2")
	connect(t, a, b, nil, nil) // nobody has candidates
	b.ms.HandleCallMeMaybe(a.node.Public(), []netip.AddrPort{a.addr()}, false)
	waitFor(t, "path after call-me-maybe", func() bool { p, _ := b.ms.PeerPath(a.node.Public()); return p.IsValid() })
	ping(t, b, a)
}

func TestDropsUnverifiedAndForeignTraffic(t *testing.T) {
	a := newNode(t, "100.64.0.1")
	stranger, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer stranger.Close()
	to := net.UDPAddrFromAddrPort(a.addr())

	// A WireGuard-looking packet from an unverified address is dropped.
	wg := append([]byte{1, 0, 0, 0}, make([]byte, 144)...)
	_, _ = stranger.WriteToUDP(wg, to)
	// A disco ping from a non-peer is ignored (no pong, no learning).
	sk, _ := protocol.NewPrivateKey()
	pkt, _ := disco.Seal(disco.Message{Type: disco.TypePing, TxID: disco.NewTxID()}, sk.Public(), disco.Shared(sk, a.disco.Public()))
	_, _ = stranger.WriteToUDP(pkt, to)

	waitFor(t, "unknown WireGuard packet dropped", func() bool { return a.ms.DroppedUnknown.Load() == 1 })
	_ = stranger.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, _, err := stranger.ReadFromUDP(make([]byte, 1500)); err == nil {
		t.Fatal("magicsock answered a stranger")
	}
	if a.ms.DiscoRx.Load() != 0 {
		t.Fatal("disco from non-peer was accepted")
	}
}

func TestPathExpiresWhenPeerVanishes(t *testing.T) {
	a, b := newNode(t, "100.64.0.1"), newNode(t, "100.64.0.2")
	connect(t, a, b, []netip.AddrPort{b.addr()}, []netip.AddrPort{a.addr()})
	ping(t, a, b)
	waitFor(t, "path up", func() bool { p, _ := a.ms.PeerPath(b.node.Public()); return p.IsValid() })
	b.dev.Close()
	b.ms.Shutdown()
	waitFor(t, "path expired after PathTTL", func() bool { p, _ := a.ms.PeerPath(b.node.Public()); return !p.IsValid() })
}

func TestEndpoints(t *testing.T) {
	ms := New(Options{Port: 51820, Log: quiet, LocalAddrs: func() []netip.Addr {
		return []netip.Addr{netip.MustParseAddr("192.168.1.2")}
	}})
	defer ms.Shutdown()
	ms.mu.Lock()
	ms.reflexive[netip.MustParseAddrPort("203.0.113.9:40000")] = time.Now()
	ms.reflexive[netip.MustParseAddrPort("203.0.113.8:1")] = time.Now().Add(-time.Hour) // stale
	ms.mu.Unlock()
	eps := ms.Endpoints()
	if len(eps) != 2 || eps[0].String() != "203.0.113.9:40000" || eps[1].String() != "192.168.1.2:51820" {
		t.Fatalf("endpoints: %v", eps)
	}
}

func waitFor(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
