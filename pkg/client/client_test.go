package client

import (
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/siv151992-lang/network-connector/pkg/protocol"
)

// --- packet builders -------------------------------------------------------

func ipv4(src, dst string, proto byte, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	b[8] = 64
	b[9] = proto
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	copy(b[20:], payload)
	return b
}

func ipv6(src, dst string, next byte, payload []byte) []byte {
	b := make([]byte, 40+len(payload))
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], uint16(len(payload)))
	b[6] = next
	b[7] = 64
	s, d := netip.MustParseAddr(src).As16(), netip.MustParseAddr(dst).As16()
	copy(b[8:24], s[:])
	copy(b[24:40], d[:])
	copy(b[40:], payload)
	return b
}

func l4(sport, dport uint16) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:2], sport)
	binary.BigEndian.PutUint16(b[2:4], dport)
	return b
}

func icmp(typ byte, id uint16) []byte {
	b := make([]byte, 8)
	b[0] = typ
	binary.BigEndian.PutUint16(b[4:6], id)
	return b
}

const (
	me   = "100.64.0.1"
	peer = "100.64.0.2"
	me6  = "fd7a::6440:1"
	pr6  = "fd7a::6440:2"
)

// --- parsing ---------------------------------------------------------------

func TestParsePacket(t *testing.T) {
	p, ok := parsePacket(ipv4(peer, me, 6, l4(40000, 22)))
	if !ok || p.proto != 6 || p.srcPort != 40000 || p.dstPort != 22 || p.src.String() != peer {
		t.Fatalf("ipv4 tcp: %+v %v", p, ok)
	}
	// IPv6 with a hop-by-hop extension header before UDP.
	hbh := append([]byte{17, 0, 0, 0, 0, 0, 0, 0}, l4(5353, 53)...)
	p, ok = parsePacket(ipv6(pr6, me6, 0, hbh))
	if !ok || p.proto != 17 || p.dstPort != 53 {
		t.Fatalf("ipv6 ext header: %+v %v", p, ok)
	}
	// IPv6 non-first fragment.
	frag := []byte{6, 0, 0x00, 0x08, 0, 0, 0, 1} // offset 1 (x8)
	p, ok = parsePacket(ipv6(pr6, me6, 44, frag))
	if !ok || !p.nonFirstFrag {
		t.Fatalf("ipv6 fragment: %+v %v", p, ok)
	}
	// IPv4 non-first fragment.
	b := ipv4(peer, me, 6, l4(1, 2))
	binary.BigEndian.PutUint16(b[6:8], 10)
	if p, ok = parsePacket(b); !ok || !p.nonFirstFrag {
		t.Fatal("ipv4 fragment")
	}
	p, ok = parsePacket(ipv4(peer, me, 1, icmp(8, 77)))
	if !ok || p.icmpType != 8 || p.srcPort != 77 {
		t.Fatalf("icmp echo: %+v", p)
	}
	for name, bad := range map[string][]byte{
		"empty": {}, "short v4": make([]byte, 10), "bad version": {0x20, 0, 0, 0},
		"truncated tcp": ipv4(peer, me, 6, []byte{1}), "short v6": append([]byte{0x60}, make([]byte, 20)...),
		"bad ihl": func() []byte { b := ipv4(peer, me, 6, l4(1, 2)); b[0] = 0x41; return b }(),
	} {
		if _, ok := parsePacket(bad); ok {
			t.Errorf("%s: parsed malformed packet", name)
		}
	}
}

// --- filter ----------------------------------------------------------------

func newTestFilter(rules []protocol.FilterRule) *Filter {
	f := NewFilter()
	f.SetRules(rules, []netip.Prefix{netip.MustParsePrefix(me + "/32"), netip.MustParsePrefix(me6 + "/128")})
	return f
}

func TestFilterDefaultDeny(t *testing.T) {
	f := newTestFilter(nil)
	if f.AllowInbound(ipv4(peer, me, 6, l4(1234, 22))) || f.AllowInbound(ipv4(peer, me, 1, icmp(8, 1))) {
		t.Fatal("empty rules must drop new inbound flows")
	}
}

func TestFilterRules(t *testing.T) {
	f := newTestFilter([]protocol.FilterRule{
		{SrcIPs: []netip.Prefix{netip.MustParsePrefix(peer + "/32")}, Protos: []int{6}, Ports: []protocol.PortRange{{First: 22, Last: 22}}},
		{SrcIPs: []netip.Prefix{netip.MustParsePrefix(pr6 + "/128")}, Ports: []protocol.PortRange{protocol.AllPorts}},
	})
	cases := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"allowed tcp port", ipv4(peer, me, 6, l4(5000, 22)), true},
		{"other port", ipv4(peer, me, 6, l4(5000, 23)), false},
		{"udp to allowed port number", ipv4(peer, me, 17, l4(5000, 22)), false},
		{"other source", ipv4("100.64.0.9", me, 6, l4(5000, 22)), false},
		{"not addressed to me", ipv4(peer, "100.64.0.50", 6, l4(5000, 22)), false},
		{"icmp echo not allowed for v4 peer", ipv4(peer, me, 1, icmp(8, 1)), false},
		{"v6 peer any proto", ipv6(pr6, me6, 17, l4(1, 9999)), true},
		{"v6 echo request", ipv6(pr6, me6, 58, icmp(128, 1)), true},
		{"unsolicited echo reply", ipv6(pr6, me6, 58, icmp(129, 1)), false},
		{"unsolicited icmp error", ipv4(peer, me, 1, icmp(3, 0)), false},
		{"garbage", []byte{0x45, 1, 2}, false},
	}
	for _, c := range cases {
		if got := f.AllowInbound(c.pkt); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestConntrackAllowsReplies(t *testing.T) {
	f := newTestFilter(nil) // nothing allowed inbound
	now := time.Unix(1000, 0)
	f.ct.now = func() time.Time { return now }

	// We connect out to peer:443; its reply must come back in.
	f.Outbound(ipv4(me, peer, 6, l4(50000, 443)))
	if !f.AllowInbound(ipv4(peer, me, 6, l4(443, 50000))) {
		t.Fatal("tcp reply dropped")
	}
	if f.AllowInbound(ipv4(peer, me, 6, l4(443, 50001))) {
		t.Fatal("reply to a different local port allowed")
	}
	// Ping out, echo reply back, ICMP error from that peer allowed.
	f.Outbound(ipv4(me, peer, 1, icmp(8, 42)))
	if !f.AllowInbound(ipv4(peer, me, 1, icmp(0, 42))) {
		t.Fatal("echo reply dropped")
	}
	if f.AllowInbound(ipv4(peer, me, 1, icmp(0, 43))) {
		t.Fatal("echo reply with wrong id allowed")
	}
	if !f.AllowInbound(ipv4(peer, me, 1, icmp(3, 0))) {
		t.Fatal("icmp error for tracked peer dropped")
	}
	// UDP flows expire after 2 minutes idle.
	f.Outbound(ipv4(me, peer, 17, l4(6000, 53)))
	now = now.Add(3 * time.Minute)
	if f.AllowInbound(ipv4(peer, me, 17, l4(53, 6000))) {
		t.Fatal("expired udp flow allowed")
	}
	f.ct.expire()
	if len(f.ct.flows) != 1 { // only the 30-minute TCP flow remains
		t.Fatalf("expire left %d flows", len(f.ct.flows))
	}
}

func TestFilterRulesSwapAtomically(t *testing.T) {
	f := newTestFilter(nil)
	pkt := ipv4(peer, me, 6, l4(1, 80))
	if f.AllowInbound(pkt) {
		t.Fatal("allowed before rules")
	}
	f.SetRules([]protocol.FilterRule{{SrcIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}},
		[]netip.Prefix{netip.MustParsePrefix(me + "/32")})
	if !f.AllowInbound(pkt) {
		t.Fatal("not allowed after rules")
	}
}

// --- engine helpers ---------------------------------------------------------

func key(b byte) protocol.Key { var k protocol.Key; k[0] = b; k[31] = 1; return k }

func node(k protocol.Key, ip string, eps ...string) protocol.Node {
	n := protocol.Node{NodeKey: k, AllowedIPs: []netip.Prefix{netip.MustParsePrefix(ip + "/32")}}
	for _, e := range eps {
		n.Endpoints = append(n.Endpoints, netip.MustParseAddrPort(e))
	}
	return n
}

func TestPeerDiff(t *testing.T) {
	a, b := key(1), key(2)
	uapi, cur := peerDiff(map[protocol.Key]peerConfig{}, []protocol.Node{
		node(a, "100.64.0.2", "10.0.0.2:51820"), node(b, "100.64.0.3"),
	})
	for _, want := range []string{
		"public_key=" + a.Hex() + "\nendpoint=wm:" + a.Hex() + "\npersistent_keepalive_interval=25\nreplace_allowed_ips=true\nallowed_ip=100.64.0.2/32\n",
		"public_key=" + b.Hex() + "\nendpoint=wm:" + b.Hex() + "\n",
	} {
		if !strings.Contains(uapi, want) {
			t.Errorf("initial config missing:\n%s\n---got---\n%s", want, uapi)
		}
	}

	// Endpoint changes are magicsock's business: no WireGuard reconfiguration,
	// so established sessions are never touched.
	if uapi, _ := peerDiff(cur, []protocol.Node{node(a, "100.64.0.2", "10.0.0.9:51820"), node(b, "100.64.0.3")}); uapi != "" {
		t.Fatalf("endpoint-only change produced:\n%s", uapi)
	}

	// Allowed IPs change for a, b removed.
	uapi, cur = peerDiff(cur, []protocol.Node{node(a, "100.64.0.20")})
	want := "public_key=" + a.Hex() + "\nreplace_allowed_ips=true\nallowed_ip=100.64.0.20/32\npublic_key=" + b.Hex() + "\nremove=true\n"
	if uapi != want {
		t.Fatalf("diff:\n%s\nwant:\n%s", uapi, want)
	}
	if len(cur) != 1 {
		t.Fatal("removed peer still tracked")
	}
}

func TestParseUAPIStats(t *testing.T) {
	a := key(9)
	s := "private_key=abc\nlisten_port=51820\npublic_key=" + a.Hex() +
		"\nendpoint=10.0.0.2:51820\nlast_handshake_time_sec=1700000000\nlast_handshake_time_nsec=5\nrx_bytes=100\ntx_bytes=200\nallowed_ip=100.64.0.2/32\n"
	st := ParseUAPIStats(s)[a]
	if st.Endpoint != "10.0.0.2:51820" || st.RxBytes != 100 || st.TxBytes != 200 || st.LastHandshake.Unix() != 1700000000 {
		t.Fatalf("stats: %+v", st)
	}
}

func TestStateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "state.json")
	st, err := LoadOrCreateState(path, "https://vpn.example.com")
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("state mode %o", fi.Mode().Perm())
	}
	st.Credential = "wmd_x"
	if err := st.Save(path); err != nil {
		t.Fatal(err)
	}
	again, err := LoadOrCreateState(path, "https://vpn.example.com")
	if err != nil || again.NodePrivate != st.NodePrivate || again.Credential != "wmd_x" {
		t.Fatalf("reload: %v", err)
	}
	if _, err := LoadOrCreateState(path, "https://other.example.com"); err == nil {
		t.Fatal("state for another server accepted")
	}
	if runtime.GOOS == "windows" {
		return // protected by the directory ACL, not mode bits
	}
	_ = os.Chmod(path, 0o644)
	if _, err := LoadOrCreateState(path, ""); err == nil || !strings.Contains(err.Error(), "readable by other users") {
		t.Fatalf("world-readable state accepted: %v", err)
	}
}
