package stun

import (
	"context"
	"encoding/hex"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	for _, a := range []string{"192.0.2.1:32853", "[2001:db8:1234:5678:11:2233:4455:6677]:32853"} {
		tx := NewTxID()
		req := Request(tx)
		got, err := ParseRequest(req)
		if err != nil || got != tx {
			t.Fatalf("request: %v", err)
		}
		ap := netip.MustParseAddrPort(a)
		rtx, mapped, err := ParseResponse(Response(tx, ap))
		if err != nil || rtx != tx || mapped != ap {
			t.Fatalf("%s: got %s %v", a, mapped, err)
		}
	}
}

// RFC 5769 §2.2 sample IPv4 response (with SOFTWARE, MESSAGE-INTEGRITY and
// FINGERPRINT attributes we must skip): mapped address 192.0.2.1:32853.
func TestRFC5769Vector(t *testing.T) {
	b, _ := hex.DecodeString("0101003c2112a442b7e7a701bc34d686fa87dfae" +
		"8022000b7465737420766563746f7220" +
		"002000080001a147e112a643" +
		"00080014" + "2b91f599fd9e90c38c7489f92af9ba53f06be7d7" +
		"80280004c07d4c96")
	tx, ap, err := ParseResponse(b)
	if err != nil {
		t.Fatal(err)
	}
	if ap.String() != "192.0.2.1:32853" || hex.EncodeToString(tx[:]) != "b7e7a701bc34d686fa87dfae" {
		t.Fatalf("got %s", ap)
	}
}

func TestRejectsMalformed(t *testing.T) {
	tx := NewTxID()
	good := Response(tx, netip.MustParseAddrPort("192.0.2.1:1"))
	cases := map[string][]byte{
		"short":         good[:10],
		"no cookie":     append([]byte{1, 1, 0, 0, 0, 0, 0, 0}, make([]byte, 12)...),
		"length lie":    func() []byte { b := append([]byte{}, good...); b[3] = 200; return b }(),
		"truncated att": good[:len(good)-2],
		"wg packet":     append([]byte{1, 0, 0, 0}, make([]byte, 144)...),
		"request type":  Request(tx),
	}
	for name, b := range cases {
		if _, _, err := ParseResponse(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if Is([]byte{1, 0, 0, 0}) || Is(append([]byte{0x57, 0x4d}, make([]byte, 30)...)) {
		t.Fatal("Is() misclassified non-STUN")
	}
}

func FuzzParseResponse(f *testing.F) {
	f.Add(Response(NewTxID(), netip.MustParseAddrPort("10.0.0.1:5")))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = ParseResponse(b)
		_, _ = ParseRequest(b)
	})
}

func TestServer(t *testing.T) {
	s := &Server{}
	if err := s.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Serve(ctx)

	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	srv := s.Addr().(*net.UDPAddr)
	_, _ = c.WriteToUDP([]byte("garbage"), srv)
	tx := NewTxID()
	_, _ = c.WriteToUDP(Request(tx), srv)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	rtx, ap, err := ParseResponse(buf[:n])
	if err != nil || rtx != tx || ap.Port() != uint16(c.LocalAddr().(*net.UDPAddr).Port) {
		t.Fatalf("server response: %s %v", ap, err)
	}
	if s.Invalid.Load() != 1 || s.Requests.Load() != 1 {
		t.Fatalf("counters: %d %d", s.Invalid.Load(), s.Requests.Load())
	}
}
