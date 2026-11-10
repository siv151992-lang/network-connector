package acl

import (
	"net/netip"
	"testing"
)

// FuzzParse: any input must either be rejected or compile into a policy whose
// evaluation doesn't panic.
func FuzzParse(f *testing.F) {
	f.Add([]byte(DefaultPolicyJSON))
	f.Add([]byte(`{"groups":{"group:a":["x@y.z"]},"hosts":{"h":"10.0.0.0/8"},"acls":[{"action":"accept","src":["group:a","h"],"dst":["tag:web:80,443","[fd7a::1]:1-9","autogroup:self:*"],"proto":"tcp"}]}`))
	devs := []Device{
		{ID: "1", User: "x@y.z", Addrs: []netip.Addr{netip.MustParseAddr("100.64.0.1")}},
		{ID: "2", Tags: []string{"tag:web"}, Addrs: []netip.Addr{netip.MustParseAddr("100.64.0.2")}},
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := Parse(b)
		if err != nil {
			return
		}
		c, err := Compile(p)
		if err != nil {
			t.Fatalf("Parse accepted but Compile failed: %v", err)
		}
		for _, d := range devs {
			_ = c.Peers(d, devs)
			_ = c.Filter(d, devs)
		}
	})
}
