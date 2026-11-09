// Package stun implements the subset of STUN (RFC 5389/8489) needed for
// NAT traversal: Binding requests and responses with XOR-MAPPED-ADDRESS.
// Clients use it to learn the public ip:port their NAT assigned to their
// WireGuard socket. No authentication or other methods are supported.
package stun

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	headerLen     = 20
	magicCookie   = 0x2112A442
	bindingReq    = 0x0001
	bindingResp   = 0x0101
	attrXorMapped = 0x0020
	attrMapped    = 0x0001
	attrSoftware  = 0x8022
	attrFinger    = 0x8028
	familyV4      = 0x01
	familyV6      = 0x02
)

// TxID is a 96-bit transaction ID.
type TxID [12]byte

// NewTxID returns a random transaction ID.
func NewTxID() TxID {
	var t TxID
	_, _ = rand.Read(t[:])
	return t
}

var (
	ErrNotSTUN   = errors.New("stun: not a STUN message")
	ErrMalformed = errors.New("stun: malformed message")
)

// Is reports whether b looks like a STUN message: top two bits zero and the
// magic cookie at bytes 4-8. Used to demultiplex STUN from WireGuard and
// disco traffic on the shared socket.
func Is(b []byte) bool {
	return len(b) >= headerLen && b[0]&0xc0 == 0 && binary.BigEndian.Uint32(b[4:8]) == magicCookie
}

// Request builds a Binding request.
func Request(tx TxID) []byte {
	b := make([]byte, headerLen)
	binary.BigEndian.PutUint16(b[0:2], bindingReq)
	binary.BigEndian.PutUint32(b[4:8], magicCookie)
	copy(b[8:20], tx[:])
	return b
}

// ParseRequest validates a Binding request and returns its transaction ID.
func ParseRequest(b []byte) (TxID, error) {
	var tx TxID
	if !Is(b) {
		return tx, ErrNotSTUN
	}
	if binary.BigEndian.Uint16(b[0:2]) != bindingReq {
		return tx, ErrMalformed
	}
	if err := checkLength(b); err != nil {
		return tx, err
	}
	copy(tx[:], b[8:20])
	return tx, nil
}

func checkLength(b []byte) error {
	l := int(binary.BigEndian.Uint16(b[2:4]))
	if l%4 != 0 || headerLen+l != len(b) {
		return ErrMalformed
	}
	return nil
}

// Response builds a Binding success response carrying addr as XOR-MAPPED-ADDRESS.
func Response(tx TxID, addr netip.AddrPort) []byte {
	ip := addr.Addr().Unmap()
	alen := 8
	fam := byte(familyV4)
	if ip.Is6() {
		alen, fam = 20, familyV6
	}
	b := make([]byte, headerLen+4+alen)
	binary.BigEndian.PutUint16(b[0:2], bindingResp)
	binary.BigEndian.PutUint16(b[2:4], uint16(4+alen))
	binary.BigEndian.PutUint32(b[4:8], magicCookie)
	copy(b[8:20], tx[:])
	a := b[headerLen:]
	binary.BigEndian.PutUint16(a[0:2], attrXorMapped)
	binary.BigEndian.PutUint16(a[2:4], uint16(alen))
	a[5] = fam
	binary.BigEndian.PutUint16(a[6:8], addr.Port()^uint16(magicCookie>>16))
	xorAddr(a[8:], ip.AsSlice(), tx)
	return b
}

// xorAddr XORs an address with the magic cookie (and, for IPv6, the transaction ID).
func xorAddr(dst, ip []byte, tx TxID) {
	var key [16]byte
	binary.BigEndian.PutUint32(key[0:4], magicCookie)
	copy(key[4:], tx[:])
	for i := range ip {
		dst[i] = ip[i] ^ key[i]
	}
}

// ParseResponse validates a Binding success response and returns its
// transaction ID and mapped address (XOR-MAPPED-ADDRESS, falling back to
// MAPPED-ADDRESS from older servers).
func ParseResponse(b []byte) (TxID, netip.AddrPort, error) {
	var tx TxID
	if !Is(b) {
		return tx, netip.AddrPort{}, ErrNotSTUN
	}
	if binary.BigEndian.Uint16(b[0:2]) != bindingResp {
		return tx, netip.AddrPort{}, ErrMalformed
	}
	if err := checkLength(b); err != nil {
		return tx, netip.AddrPort{}, err
	}
	copy(tx[:], b[8:20])
	var mapped, xorMapped netip.AddrPort
	attrs := b[headerLen:]
	for len(attrs) >= 4 {
		typ := binary.BigEndian.Uint16(attrs[0:2])
		l := int(binary.BigEndian.Uint16(attrs[2:4]))
		padded := (l + 3) &^ 3
		if 4+padded > len(attrs) {
			return tx, netip.AddrPort{}, ErrMalformed
		}
		v := attrs[4 : 4+l]
		switch typ {
		case attrXorMapped:
			if ap, ok := parseAddr(v, true, tx); ok {
				xorMapped = ap
			}
		case attrMapped:
			if ap, ok := parseAddr(v, false, tx); ok {
				mapped = ap
			}
		}
		attrs = attrs[4+padded:]
	}
	switch {
	case xorMapped.IsValid():
		return tx, xorMapped, nil
	case mapped.IsValid():
		return tx, mapped, nil
	}
	return tx, netip.AddrPort{}, ErrMalformed
}

func parseAddr(v []byte, xor bool, tx TxID) (netip.AddrPort, bool) {
	if len(v) < 4 {
		return netip.AddrPort{}, false
	}
	var n int
	switch v[1] {
	case familyV4:
		n = 4
	case familyV6:
		n = 16
	default:
		return netip.AddrPort{}, false
	}
	if len(v) != 4+n {
		return netip.AddrPort{}, false
	}
	port := binary.BigEndian.Uint16(v[2:4])
	ip := make([]byte, n)
	copy(ip, v[4:])
	if xor {
		port ^= uint16(magicCookie >> 16)
		xorAddr(ip, ip, tx)
	}
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(a.Unmap(), port), true
}
