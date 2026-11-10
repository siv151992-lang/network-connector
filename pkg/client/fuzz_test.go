package client

import (
	"net/netip"
	"testing"

	"github.com/siv151992-lang/network-connector/pkg/protocol"
)

// FuzzInboundFilter: decrypted packets from peers are attacker-controlled.
func FuzzInboundFilter(f *testing.F) {
	f.Add(ipv4("100.64.0.2", "100.64.0.1", 6, l4(1, 22)))
	f.Add(ipv6("fd7a::6440:2", "fd7a::6440:1", 44, []byte{6, 0, 0, 8, 0, 0, 0, 1}))
	flt := NewFilter()
	flt.SetRules([]protocol.FilterRule{{SrcIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, Ports: []protocol.PortRange{{First: 22, Last: 22}}}},
		[]netip.Prefix{netip.MustParsePrefix("100.64.0.1/32"), netip.MustParsePrefix("fd7a::6440:1/128")})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = parsePacket(b)
		flt.Outbound(b)
		_ = flt.AllowInbound(b)
	})
}
