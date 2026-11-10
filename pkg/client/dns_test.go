package client

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/siv151992-lang/network-connector/pkg/protocol"
)

func query(name string, qtype uint16) []byte {
	q := []byte{0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0)
	q = binary.BigEndian.AppendUint16(q, qtype)
	return binary.BigEndian.AppendUint16(q, 1)
}

func testDNS() *DNSServer {
	d := &DNSServer{}
	d.Update(&protocol.NetworkMap{
		Network: protocol.NetworkInfo{Domain: "home.wm.internal"},
		Self:    protocol.Node{Name: "laptop", Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32"), netip.MustParsePrefix("fd7a::1/128")}},
		Peers:   []protocol.Node{{Name: "nas", Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}}},
	})
	return d
}

func TestDNSAnswers(t *testing.T) {
	d := testDNS()
	r := d.Answer(query("NAS.home.wm.internal", dnsTypeA))
	if r[0] != 0xab || r[3]&0x0f != 0 || binary.BigEndian.Uint16(r[6:]) != 1 || r[2]&0x04 == 0 {
		t.Fatalf("A nas: % x", r)
	}
	if got := netip.AddrFrom4([4]byte(r[len(r)-4:])); got.String() != "100.64.0.2" {
		t.Fatalf("A nas = %s", got)
	}
	r = d.Answer(query("laptop.home.wm.internal", dnsTypeAAAA))
	if binary.BigEndian.Uint16(r[6:]) != 1 || netip.AddrFrom16([16]byte(r[len(r)-16:])).String() != "fd7a::1" {
		t.Fatalf("AAAA laptop: % x", r)
	}
	if r := d.Answer(query("nas.home.wm.internal", dnsTypeAAAA)); r[3]&0x0f != 0 || binary.BigEndian.Uint16(r[6:]) != 0 {
		t.Fatal("existing name without AAAA must be NOERROR/empty")
	}
	if r := d.Answer(query("ghost.home.wm.internal", dnsTypeA)); r[3]&0x0f != 3 {
		t.Fatal("unknown name must be NXDOMAIN")
	}
	if r := d.Answer(query("example.com", dnsTypeA)); r[3]&0x0f != 5 {
		t.Fatal("outside zone must be REFUSED")
	}
	for name, bad := range map[string][]byte{"short": {1, 2}, "truncated": query("nas.home.wm.internal", 1)[:20], "compressed": append([]byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}, 0xc0, 12, 0, 1, 0, 1)} {
		if r := d.Answer(bad); r != nil && r[3]&0x0f == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDNSOverUDP(t *testing.T) {
	d := testDNS()
	if err := d.Listen(netip.MustParseAddrPort("127.0.0.1:0")); err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	c, err := net.Dial("udp", d.conn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write(query("nas.home.wm.internal", dnsTypeA))
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil || netip.AddrFrom4([4]byte(buf[n-4:n])).String() != "100.64.0.2" {
		t.Fatalf("udp answer: %v % x", err, buf[:n])
	}
}

func FuzzDNSAnswer(f *testing.F) {
	d := testDNS()
	f.Add(query("nas.home.wm.internal", 1))
	f.Fuzz(func(t *testing.T, b []byte) { _ = d.Answer(b) })
}
