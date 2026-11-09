// Package ipam allocates private addresses for devices.
//
// IPv4: the lowest free host address in the network's range (default
// 100.64.0.0/10, the CGNAT block, which rarely collides with home/office LANs).
// The network and broadcast addresses are never assigned.
//
// IPv6: derived from the IPv4 address by placing its 32 bits in the low bits
// of the network's ULA /48 (fdXX:XXXX:XXXX::100.64.0.7). The two addresses are
// paired, so IPv6 uniqueness follows from IPv4 uniqueness and humans can map
// one to the other.
//
// Callers must serialize allocation per network (the device registrar holds a
// row lock on the network) — the database's UNIQUE constraints are the backstop.
package ipam

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// ErrExhausted means the range has no free address.
var ErrExhausted = errors.New("ipam: address range exhausted")

// AllocateIPv4 returns the lowest host address in pfx not present in used.
func AllocateIPv4(pfx netip.Prefix, used map[netip.Addr]bool) (netip.Addr, error) {
	if !pfx.Addr().Is4() || pfx.Bits() > 30 {
		return netip.Addr{}, fmt.Errorf("ipam: need an IPv4 prefix of /30 or larger, got %s", pfx)
	}
	pfx = pfx.Masked()
	base := u32(pfx.Addr())
	size := uint32(1) << (32 - pfx.Bits())
	broadcast := base + size - 1
	for v := base + 1; v < broadcast; v++ {
		a := fromU32(v)
		if !used[a] {
			return a, nil
		}
	}
	return netip.Addr{}, ErrExhausted
}

// IPv6For maps an IPv4 address into the IPv6 /48 (or larger) prefix.
func IPv6For(v6 netip.Prefix, v4 netip.Addr) (netip.Addr, error) {
	if !v6.Addr().Is6() || v6.Addr().Is4In6() || v6.Bits() > 96 {
		return netip.Addr{}, fmt.Errorf("ipam: need an IPv6 prefix of /96 or larger, got %s", v6)
	}
	if !v4.Is4() {
		return netip.Addr{}, fmt.Errorf("ipam: %s is not IPv4", v4)
	}
	b := v6.Masked().Addr().As16()
	a4 := v4.As4()
	copy(b[12:], a4[:])
	return netip.AddrFrom16(b), nil
}

// RandomULA48 returns a random RFC 4193 unique-local /48 (fdXX:XXXX:XXXX::/48),
// so two WireMesh deployments (or a VPN on the same host) are unlikely to clash.
func RandomULA48() (netip.Prefix, error) {
	var b [16]byte
	b[0] = 0xfd
	if _, err := rand.Read(b[1:6]); err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(netip.AddrFrom16(b), 48), nil
}

func u32(a netip.Addr) uint32 { b := a.As4(); return binary.BigEndian.Uint32(b[:]) }

func fromU32(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}
