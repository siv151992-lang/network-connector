package stun

import (
	"net/netip"
	"testing"
)

// FuzzParse: STUN packets arrive on the shared WireGuard socket from anyone.
func FuzzParse(f *testing.F) {
	tx := NewTxID()
	f.Add(Request(tx))
	f.Add(Response(tx, netip.MustParseAddrPort("203.0.113.7:41641")))
	f.Add(Response(tx, netip.MustParseAddrPort("[2001:db8::1]:9")))
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = Is(b)
		_, _ = ParseRequest(b)
		if id, ap, err := ParseResponse(b); err == nil {
			if got, ap2, err := ParseResponse(Response(id, ap)); err != nil || got != id || ap2 != ap {
				t.Fatalf("round trip mismatch: %v %v %v", err, ap, ap2)
			}
		}
	})
}
