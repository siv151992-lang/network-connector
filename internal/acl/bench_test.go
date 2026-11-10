package acl

import (
	"fmt"
	"net/netip"
	"testing"
)

// BenchmarkNetmap1000 measures the per-device work the control server does
// when a 1000-device network changes: visibility + packet filter for every node.
func BenchmarkNetmap1000(b *testing.B) {
	p, err := Parse([]byte(`{"groups":{"group:eng":["u0@x.io","u1@x.io","u2@x.io"]},"acls":[
	 {"action":"accept","src":["group:eng"],"dst":["*:*"]},
	 {"action":"accept","src":["autogroup:member"],"dst":["autogroup:self:*","tag:web:80,443"]},
	 {"action":"accept","src":["tag:mon"],"dst":["*:9100"]}]}`))
	if err != nil {
		b.Fatal(err)
	}
	c, err := Compile(p)
	if err != nil {
		b.Fatal(err)
	}
	devs := make([]Device, 1000)
	for i := range devs {
		devs[i] = Device{ID: fmt.Sprint(i), User: fmt.Sprintf("u%d@x.io", i%50),
			Addrs: []netip.Addr{netip.AddrFrom4([4]byte{100, 64, byte(i >> 8), byte(i)})}}
		if i%10 == 0 {
			devs[i].User, devs[i].Tags = "", []string{"tag:web"}
		}
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		for _, d := range devs {
			_ = c.Peers(d, devs)
			_ = c.Filter(d, devs)
		}
	}
}
