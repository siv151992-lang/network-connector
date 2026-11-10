// Package protocol defines the control-plane wire types shared by the
// server and every client (Linux, Windows, Android via gomobile).
//
// Compatibility rule: fields may be added, never renamed or repurposed.
// Clients ignore unknown fields; the server tolerates missing optional ones.
package protocol

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"golang.org/x/crypto/curve25519"
)

// Key is a Curve25519 key (WireGuard or disco). JSON form is standard
// base64, the same encoding `wg` uses.
type Key [32]byte

// ParseKey decodes a base64 key.
func ParseKey(s string) (Key, error) {
	var k Key
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return k, errors.New("protocol: key must be 32 bytes, base64")
	}
	copy(k[:], b)
	return k, nil
}

func (k Key) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

// Hex is the form used by WireGuard's UAPI configuration protocol.
func (k Key) Hex() string { return hex.EncodeToString(k[:]) }

// IsZero reports whether k is all zeros.
func (k Key) IsZero() bool { return k == Key{} }

func (k Key) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

func (k *Key) UnmarshalText(b []byte) error {
	p, err := ParseKey(string(b))
	if err != nil {
		return err
	}
	*k = p
	return nil
}

// PrivateKey is a Curve25519 private key. It never leaves the device; it has
// no JSON marshalling on purpose except via the client's state file.
type PrivateKey Key

// NewPrivateKey generates a clamped Curve25519 private key (as `wg genkey`).
func NewPrivateKey() (PrivateKey, error) {
	var k PrivateKey
	if _, err := rand.Read(k[:]); err != nil {
		return k, err
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	return k, nil
}

// Public derives the public key (as `wg pubkey`).
func (k PrivateKey) Public() Key {
	var pub Key
	curve25519.ScalarBaseMult((*[32]byte)(&pub), (*[32]byte)(&k))
	return pub
}

// Hex is the UAPI form.
func (k PrivateKey) Hex() string { return hex.EncodeToString(k[:]) }

func (k PrivateKey) MarshalText() ([]byte, error) {
	return []byte(base64.StdEncoding.EncodeToString(k[:])), nil
}

func (k *PrivateKey) UnmarshalText(b []byte) error {
	p, err := ParseKey(string(b))
	if err != nil {
		return err
	}
	*k = PrivateKey(p)
	return nil
}

// ---------------------------------------------------------------------------

// NetworkMap is everything a device needs to configure its tunnel: itself,
// the peers it may talk to, and the inbound packet filter it must enforce.
// It is compiled per device by the control server from the network's ACL.
type NetworkMap struct {
	// Version is a content hash; it changes whenever anything below changes.
	Version      string       `json:"version"`
	Network      NetworkInfo  `json:"network"`
	Self         Node         `json:"self"`
	Peers        []Node       `json:"peers"`
	PacketFilter []FilterRule `json:"packet_filter"`
	// STUNServers are host:port addresses for public-endpoint discovery.
	STUNServers []string `json:"stun_servers,omitempty"`
	// Relays carry traffic between peers with no direct path (Phase 6).
	Relays []Relay `json:"relays,omitempty"`
	// PollInterval tells Phase 4 clients how often to refresh (Phase 5
	// replaces polling with a WebSocket push stream).
	PollInterval Duration `json:"poll_interval"`
}

// NetworkInfo describes the network (tailnet).
type NetworkInfo struct {
	ID       string       `json:"id"`
	Name     string       `json:"name"`
	IPv4CIDR netip.Prefix `json:"ipv4_cidr"`
	IPv6CIDR netip.Prefix `json:"ipv6_cidr"`
	// Domain is the DNS suffix for device names: <device>.<Domain>.
	Domain string `json:"domain,omitempty"`
}

// Node is a device as seen by other devices.
type Node struct {
	ID         string           `json:"id"`
	Name       string           `json:"name"`
	User       string           `json:"user,omitempty"` // owner's email; empty for tagged devices
	Tags       []string         `json:"tags,omitempty"`
	OS         string           `json:"os,omitempty"`
	NodeKey    Key              `json:"node_key"`
	DiscoKey   Key              `json:"disco_key"`
	Addresses  []netip.Prefix   `json:"addresses"`   // the node's own /32 and /128
	AllowedIPs []netip.Prefix   `json:"allowed_ips"` // what this peer may source/route (addresses + approved routes)
	Endpoints  []netip.AddrPort `json:"endpoints"`   // candidate UDP endpoints, most preferred first
	HomeRelay  int              `json:"home_relay,omitempty"`
	KeyExpiry  *time.Time       `json:"key_expiry,omitempty"`
	KeyExpired bool             `json:"key_expired,omitempty"`
	LastSeen   *time.Time       `json:"last_seen,omitempty"`
	// Online is true while the node holds a control stream (real presence,
	// not inferred from last_seen).
	Online bool `json:"online,omitempty"`
}

// Protocol numbers used in filter rules (IANA). 0 means any protocol.
const (
	ProtoAny    = 0
	ProtoICMP   = 1
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoICMPv6 = 58
)

// FilterRule allows inbound packets whose source address is in SrcIPs,
// whose IP protocol is in Protos (empty = any) and, for TCP/UDP, whose
// destination port is in Ports (empty = any). Everything else is dropped,
// except replies to connections this device initiated.
type FilterRule struct {
	SrcIPs []netip.Prefix `json:"src_ips"`
	Protos []int          `json:"protos,omitempty"`
	Ports  []PortRange    `json:"ports,omitempty"`
}

// PortRange is an inclusive port range.
type PortRange struct {
	First uint16 `json:"first"`
	Last  uint16 `json:"last"`
}

// Contains reports whether p is in the range.
func (r PortRange) Contains(p uint16) bool { return p >= r.First && p <= r.Last }

// AllPorts is the range 0-65535.
var AllPorts = PortRange{First: 0, Last: 65535}

func (r PortRange) String() string {
	if r == AllPorts {
		return "*"
	}
	if r.First == r.Last {
		return fmt.Sprint(r.First)
	}
	return fmt.Sprintf("%d-%d", r.First, r.Last)
}

// EndpointsUpdate is sent by a device to report where it can be reached.
type EndpointsUpdate struct {
	Endpoints  []netip.AddrPort `json:"endpoints"`
	ListenPort uint16           `json:"listen_port"`
	HomeRelay  int              `json:"home_relay,omitempty"`
}

// Duration marshals as a Go duration string ("15s").
type Duration time.Duration

func (d Duration) MarshalText() ([]byte, error) { return []byte(time.Duration(d).String()), nil }

func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// ---------------------------------------------------------------------------
// Control stream (GET /api/v1/device/stream, WebSocket, JSON text frames)
// ---------------------------------------------------------------------------

// Stream message types.
const (
	// Server -> device
	StreamMap         = "map"           // full network map (sent on connect and on every change)
	StreamCallMeMaybe = "call_me_maybe" // a peer asks us to probe its endpoints now (NAT hole punching)
	StreamRevoked     = "revoked"       // credential revoked; the device must shut down
	// Device -> server
	StreamEndpoints = "endpoints" // EndpointsUpdate
	// StreamCallMeMaybe is also sent device -> server, addressed with To.
)

// StreamMessage is one frame on the control stream.
type StreamMessage struct {
	Type        string           `json:"type"`
	Map         *NetworkMap      `json:"map,omitempty"`
	Endpoints   *EndpointsUpdate `json:"endpoints,omitempty"`
	CallMeMaybe *CallMeMaybe     `json:"call_me_maybe,omitempty"`
}

// CallMeMaybe asks a peer to start sending disco pings to the listed
// endpoints immediately, so both NATs see outbound packets at the same time.
// Device -> server: To is set. Server -> device: From is set (by the server,
// from the authenticated sender; never trusted from the client).
type CallMeMaybe struct {
	From      Key              `json:"from,omitempty"`
	To        Key              `json:"to,omitempty"`
	Endpoints []netip.AddrPort `json:"endpoints"`
	// Quiesce asks the peer to stop sending anything to us for one quiet
	// period, so stale NAT state on both sides expires before a fresh,
	// synchronized hole-punching attempt (see pkg/client/magicsock).
	Quiesce bool `json:"quiesce,omitempty"`
}

// Relay is a packet relay a device can use when no direct path exists.
type Relay struct {
	ID  int    `json:"id"`
	URL string `json:"url"` // https://host/relay (WebSocket)
}

// RelayToken is returned by POST /api/v1/device/relay-token.
type RelayToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}
