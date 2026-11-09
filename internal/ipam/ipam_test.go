package ipam

import (
	"errors"
	"net/netip"
	"testing"
)

func TestAllocateIPv4(t *testing.T) {
	pfx := netip.MustParsePrefix("100.64.0.0/10")
	used := map[netip.Addr]bool{}
	a, err := AllocateIPv4(pfx, used)
	if err != nil || a.String() != "100.64.0.1" {
		t.Fatalf("first: %s %v", a, err)
	}
	used[a] = true
	used[netip.MustParseAddr("100.64.0.2")] = true
	b, _ := AllocateIPv4(pfx, used)
	if b.String() != "100.64.0.3" {
		t.Fatalf("second: %s", b)
	}
	delete(used, a) // released addresses are reused
	c, _ := AllocateIPv4(pfx, used)
	if c != a {
		t.Fatalf("released address not reused: %s", c)
	}
}

func TestAllocateIPv4Exhaustion(t *testing.T) {
	pfx := netip.MustParsePrefix("10.0.0.0/30") // hosts .1 and .2 only
	used := map[netip.Addr]bool{}
	for _, want := range []string{"10.0.0.1", "10.0.0.2"} {
		a, err := AllocateIPv4(pfx, used)
		if err != nil || a.String() != want {
			t.Fatalf("got %s %v want %s", a, err, want)
		}
		used[a] = true
	}
	if _, err := AllocateIPv4(pfx, used); !errors.Is(err, ErrExhausted) {
		t.Fatalf("want ErrExhausted, got %v", err)
	}
	if _, err := AllocateIPv4(netip.MustParsePrefix("fd00::/48"), used); err == nil {
		t.Fatal("IPv6 prefix accepted")
	}
}

func TestIPv6For(t *testing.T) {
	v6, err := IPv6For(netip.MustParsePrefix("fd7a:1234:5678::/48"), netip.MustParseAddr("100.64.0.7"))
	if err != nil || v6.String() != "fd7a:1234:5678::6440:7" {
		t.Fatalf("got %s %v", v6, err)
	}
	if _, err := IPv6For(netip.MustParsePrefix("100.64.0.0/10"), netip.MustParseAddr("100.64.0.7")); err == nil {
		t.Fatal("IPv4 prefix accepted")
	}
}

func TestRandomULA48(t *testing.T) {
	a, _ := RandomULA48()
	b, _ := RandomULA48()
	if a.Bits() != 48 || a.Addr().As16()[0] != 0xfd || a == b || a.Masked() != a {
		t.Fatalf("bad ULA %s %s", a, b)
	}
}
