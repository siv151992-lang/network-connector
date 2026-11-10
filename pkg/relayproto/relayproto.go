// Package relayproto defines the WireMesh relay protocol and relay tokens.
//
// Transport: a WebSocket (over HTTPS in production, so it passes firewalls
// and proxies). The first message is a text frame holding the client's relay
// token. After that, every message is a binary frame:
//
//	type(1) | peer node key(32) | payload
//
//	client -> relay  FrameSend (1): peer = destination
//	relay  -> client FrameRecv (2): peer = source (stamped by the relay)
//
// Payloads are WireGuard ciphertext or sealed disco messages: the relay never
// sees plaintext and never holds keys.
//
// Relay tokens are minted by the control server and signed with Ed25519. The
// relay verifies them offline with the control server's public key. A token
// binds a node key to a network, so the relay only forwards between devices
// of the same network.
package relayproto

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/siv151992-lang/network-connector/pkg/protocol"
)

// Frame types.
const (
	FrameSend byte = 1
	FrameRecv byte = 2
)

// MaxPayload bounds a relayed packet (WireGuard MTU plus headers).
const MaxPayload = 2048

const hdrLen = 1 + 32

var (
	ErrFrame = errors.New("relay: malformed frame")
	ErrToken = errors.New("relay: invalid token")
)

// Encode builds a frame.
func Encode(typ byte, peer protocol.Key, payload []byte) []byte {
	b := make([]byte, hdrLen+len(payload))
	b[0] = typ
	copy(b[1:hdrLen], peer[:])
	copy(b[hdrLen:], payload)
	return b
}

// Decode parses a frame. The payload aliases b.
func Decode(b []byte) (typ byte, peer protocol.Key, payload []byte, err error) {
	if len(b) < hdrLen || len(b) > hdrLen+MaxPayload {
		return 0, peer, nil, ErrFrame
	}
	copy(peer[:], b[1:hdrLen])
	return b[0], peer, b[hdrLen:], nil
}

// Claims are the contents of a relay token.
type Claims struct {
	NodeKey   protocol.Key `json:"nk"`
	NetworkID string       `json:"net"`
	Expires   int64        `json:"exp"` // unix seconds
}

// SigningKey derives the control server's relay-token signing key from its
// 32-byte secret (WIREMESH_SECRET_KEY). Deterministic, so no extra key to manage.
func SigningKey(secret []byte) (ed25519.PrivateKey, error) {
	seed, err := hkdf.Key(sha256.New, secret, nil, "wiremesh relay token v1", ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

var b64 = base64.RawURLEncoding.Strict()

// Sign mints a token: base64url(json claims) "." base64url(signature).
func Sign(key ed25519.PrivateKey, c Claims) (string, error) {
	body, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	p := b64.EncodeToString(body)
	return p + "." + b64.EncodeToString(ed25519.Sign(key, []byte(p))), nil
}

// Verify checks a token's signature and expiry.
func Verify(pub ed25519.PublicKey, token string, now time.Time) (Claims, error) {
	var c Claims
	p, sig, ok := strings.Cut(token, ".")
	if !ok || len(token) > 1024 || !canonical(token) {
		return c, ErrToken
	}
	s, err := b64.DecodeString(sig)
	if err != nil || !ed25519.Verify(pub, []byte(p), s) {
		return c, ErrToken
	}
	body, err := b64.DecodeString(p)
	if err != nil || json.Unmarshal(body, &c) != nil {
		return c, ErrToken
	}
	if c.NodeKey.IsZero() || c.NetworkID == "" || now.Unix() >= c.Expires {
		return c, ErrToken
	}
	return c, nil
}

// canonical reports whether s uses only the unpadded base64url alphabet and
// '.'; the decoder would otherwise skip CR/LF, making tokens malleable.
func canonical(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// ParsePublicKey decodes a base64 Ed25519 public key (relay configuration).
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("relay: control public key must be 32 bytes, base64")
	}
	return ed25519.PublicKey(b), nil
}
