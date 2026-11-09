// Package disco implements WireMesh's path-discovery messages ("disco"),
// exchanged over the same UDP socket as WireGuard to find and verify direct
// paths between peers and to punch through NATs.
//
// Wire format:
//
//	magic(6) "WM\xd1sc\x01" | sender disco public key(32) | nonce(24) | NaCl box
//
// The box (Curve25519 + XSalsa20-Poly1305) is sealed from the sender's disco
// private key to the recipient's disco public key, so only real peers can
// produce messages, and on-path attackers or relays can't forge or read
// them. A disco key is distinct from the WireGuard key: the WireGuard key never
// signs anything outside WireGuard.
//
// Plaintext: type(1) | version(1) | body
//
//	Ping (1): txid(12) | sender node key(32)
//	Pong (2): txid(12) | observed source address: ip(16) | port(2)
package disco

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"

	"golang.org/x/crypto/nacl/box"

	"github.com/siv151992-lang/network-connector/pkg/protocol"
)

// Magic prefixes every disco packet. Its first byte (0x57) can't start a
// WireGuard message (types 1-4) or a STUN message (top bits 00).
var Magic = []byte{'W', 'M', 0xd1, 's', 'c', 0x01}

const (
	keyLen    = 32
	nonceLen  = 24
	headerLen = 6 + keyLen + nonceLen
	version   = 0

	TypePing = 1
	TypePong = 2
)

// TxID identifies a ping and its pong.
type TxID [12]byte

// NewTxID returns a random transaction ID.
func NewTxID() TxID {
	var t TxID
	_, _ = rand.Read(t[:])
	return t
}

// Message is a decoded disco message.
type Message struct {
	Type    byte
	TxID    TxID
	NodeKey protocol.Key   // Ping: sender's WireGuard key
	Src     netip.AddrPort // Pong: where the ping came from, as seen by the responder
}

var ErrInvalid = errors.New("disco: invalid message")

// Is reports whether b looks like a disco packet.
func Is(b []byte) bool {
	return len(b) >= headerLen && string(b[:6]) == string(Magic)
}

// Sender returns the claimed sender disco key (unauthenticated until Open).
func Sender(b []byte) (protocol.Key, bool) {
	var k protocol.Key
	if !Is(b) {
		return k, false
	}
	copy(k[:], b[6:6+keyLen])
	return k, true
}

func (m Message) marshal() ([]byte, error) {
	out := []byte{m.Type, version}
	out = append(out, m.TxID[:]...)
	switch m.Type {
	case TypePing:
		out = append(out, m.NodeKey[:]...)
	case TypePong:
		a := m.Src.Addr().As16()
		out = append(out, a[:]...)
		out = binary.BigEndian.AppendUint16(out, m.Src.Port())
	default:
		return nil, ErrInvalid
	}
	return out, nil
}

func unmarshal(b []byte) (Message, error) {
	var m Message
	if len(b) < 2+12 || b[1] != version {
		return m, ErrInvalid
	}
	m.Type = b[0]
	copy(m.TxID[:], b[2:14])
	body := b[14:]
	switch m.Type {
	case TypePing:
		if len(body) != keyLen {
			return m, ErrInvalid
		}
		copy(m.NodeKey[:], body)
	case TypePong:
		if len(body) != 18 {
			return m, ErrInvalid
		}
		a := netip.AddrFrom16([16]byte(body[:16])).Unmap()
		m.Src = netip.AddrPortFrom(a, binary.BigEndian.Uint16(body[16:18]))
	default:
		return m, ErrInvalid
	}
	return m, nil
}

// SharedKey is a precomputed box key for one peer (speeds up seal/open).
type SharedKey [32]byte

// Shared precomputes the key between our private and their public disco key.
func Shared(priv protocol.PrivateKey, peer protocol.Key) SharedKey {
	var k [32]byte
	pk, pr := [32]byte(peer), [32]byte(priv)
	box.Precompute(&k, &pk, &pr)
	return SharedKey(k)
}

// Seal encrypts m for a peer. ourPub is placed in the header so the receiver
// can find the right shared key.
func Seal(m Message, ourPub protocol.Key, shared SharedKey) ([]byte, error) {
	pt, err := m.marshal()
	if err != nil {
		return nil, err
	}
	var nonce [nonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	out := make([]byte, 0, headerLen+len(pt)+box.Overhead)
	out = append(out, Magic...)
	out = append(out, ourPub[:]...)
	out = append(out, nonce[:]...)
	k := [32]byte(shared)
	return box.SealAfterPrecomputation(out, pt, &nonce, &k), nil
}

// Open authenticates and decrypts a packet using the shared key for its sender.
func Open(b []byte, shared SharedKey) (Message, error) {
	if !Is(b) || len(b) < headerLen+box.Overhead {
		return Message{}, ErrInvalid
	}
	var nonce [nonceLen]byte
	copy(nonce[:], b[6+keyLen:headerLen])
	k := [32]byte(shared)
	pt, ok := box.OpenAfterPrecomputation(nil, b[headerLen:], &nonce, &k)
	if !ok {
		return Message{}, ErrInvalid
	}
	return unmarshal(pt)
}
