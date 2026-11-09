package client

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/siv151992-lang/network-connector/pkg/protocol"
)

// packet is the parsed subset of an IP packet the filter needs.
type packet struct {
	src, dst     netip.Addr
	proto        int
	srcPort      uint16 // TCP/UDP port, or ICMP echo identifier
	dstPort      uint16
	icmpType     uint8
	nonFirstFrag bool
}

// parsePacket parses IPv4/IPv6 headers (skipping IPv6 extension headers) and
// the TCP/UDP/ICMP header. ok is false for anything malformed or truncated.
func parsePacket(b []byte) (p packet, ok bool) {
	if len(b) < 1 {
		return p, false
	}
	var payload []byte
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return p, false
		}
		ihl := int(b[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(b[2:4]))
		if ihl < 20 || total < ihl || len(b) < total {
			return p, false
		}
		p.src = netip.AddrFrom4([4]byte(b[12:16]))
		p.dst = netip.AddrFrom4([4]byte(b[16:20]))
		p.proto = int(b[9])
		fragOff := binary.BigEndian.Uint16(b[6:8]) & 0x1fff
		if fragOff != 0 {
			p.nonFirstFrag = true
			return p, true
		}
		payload = b[ihl:total]
	case 6:
		if len(b) < 40 {
			return p, false
		}
		p.src = netip.AddrFrom16([16]byte(b[8:24]))
		p.dst = netip.AddrFrom16([16]byte(b[24:40]))
		next := int(b[6])
		rest := b[40:]
		for hops := 0; ; hops++ {
			if hops > 8 {
				return p, false
			}
			switch next {
			case 0, 43, 60: // hop-by-hop, routing, destination options
				if len(rest) < 8 {
					return p, false
				}
				l := (int(rest[1]) + 1) * 8
				if len(rest) < l {
					return p, false
				}
				next, rest = int(rest[0]), rest[l:]
				continue
			case 44: // fragment
				if len(rest) < 8 {
					return p, false
				}
				if binary.BigEndian.Uint16(rest[2:4])>>3 != 0 {
					p.proto = int(rest[0])
					p.nonFirstFrag = true
					return p, true
				}
				next, rest = int(rest[0]), rest[8:]
				continue
			}
			break
		}
		p.proto = next
		payload = rest
	default:
		return p, false
	}
	switch p.proto {
	case protocol.ProtoTCP, protocol.ProtoUDP:
		if len(payload) < 4 {
			return p, false
		}
		p.srcPort = binary.BigEndian.Uint16(payload[0:2])
		p.dstPort = binary.BigEndian.Uint16(payload[2:4])
	case protocol.ProtoICMP, protocol.ProtoICMPv6:
		if len(payload) < 8 {
			return p, false
		}
		p.icmpType = payload[0]
		if isEcho(p.proto, p.icmpType) {
			id := binary.BigEndian.Uint16(payload[4:6])
			p.srcPort, p.dstPort = id, id
		}
	}
	return p, true
}

func isEcho(proto int, t uint8) bool {
	return (proto == protocol.ProtoICMP && (t == 8 || t == 0)) || (proto == protocol.ProtoICMPv6 && (t == 128 || t == 129))
}

// isICMPError reports ICMP error messages (unreachable, time exceeded, …),
// which are related to an existing flow rather than new connections.
func isICMPError(proto int, t uint8) bool {
	return (proto == protocol.ProtoICMP && (t == 3 || t == 11 || t == 12)) ||
		(proto == protocol.ProtoICMPv6 && t >= 1 && t <= 4)
}

// ---------------------------------------------------------------------------
// Connection tracking
// ---------------------------------------------------------------------------

type flowKey struct {
	proto              int
	local, remote      netip.Addr
	localPort, remPort uint16
}

const maxFlows = 1 << 16

// conntrack remembers flows this device initiated so replies are let in even
// though the peer's filter rules don't cover them.
type conntrack struct {
	mu      sync.Mutex
	flows   map[flowKey]time.Time
	remotes map[netip.Addr]time.Time // any recent flow with this peer (for ICMP errors)
	now     func() time.Time
}

func newConntrack() *conntrack {
	return &conntrack{flows: map[flowKey]time.Time{}, remotes: map[netip.Addr]time.Time{}, now: time.Now}
}

func flowTTL(proto int) time.Duration {
	switch proto {
	case protocol.ProtoTCP:
		return 30 * time.Minute
	case protocol.ProtoUDP:
		return 2 * time.Minute
	default:
		return 30 * time.Second
	}
}

func (c *conntrack) outbound(p packet) {
	if p.nonFirstFrag {
		return
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.flows) >= maxFlows {
		c.expireLocked(now)
		if len(c.flows) >= maxFlows {
			return // table full: new outbound flows just won't get reply tracking
		}
	}
	c.flows[flowKey{p.proto, p.src, p.dst, p.srcPort, p.dstPort}] = now.Add(flowTTL(p.proto))
	c.remotes[p.dst] = now.Add(flowTTL(p.proto))
}

// isReply reports whether inbound packet p belongs to a flow we started.
func (c *conntrack) isReply(p packet) bool {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if isICMPError(p.proto, p.icmpType) {
		exp, ok := c.remotes[p.src]
		return ok && now.Before(exp)
	}
	k := flowKey{p.proto, p.dst, p.src, p.dstPort, p.srcPort}
	exp, ok := c.flows[k]
	if !ok || !now.Before(exp) {
		return false
	}
	c.flows[k] = now.Add(flowTTL(p.proto)) // refresh on traffic
	return true
}

func (c *conntrack) expireLocked(now time.Time) {
	for k, exp := range c.flows {
		if !now.Before(exp) {
			delete(c.flows, k)
		}
	}
	for k, exp := range c.remotes {
		if !now.Before(exp) {
			delete(c.remotes, k)
		}
	}
}

func (c *conntrack) expire() {
	c.mu.Lock()
	c.expireLocked(c.now())
	c.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Filter
// ---------------------------------------------------------------------------

type filterState struct {
	rules []protocol.FilterRule
	self  map[netip.Addr]bool
}

// Filter enforces the network map's inbound rules for this device. A nil or
// empty rule set drops every new inbound flow (default deny).
type Filter struct {
	state atomic.Pointer[filterState]
	ct    *conntrack
	// Dropped counts inbound packets rejected (for status output).
	Dropped atomic.Uint64
}

// NewFilter returns a deny-all filter until SetRules is called.
func NewFilter() *Filter {
	f := &Filter{ct: newConntrack()}
	f.state.Store(&filterState{self: map[netip.Addr]bool{}})
	return f
}

// SetRules atomically replaces the rules and this device's own addresses.
func (f *Filter) SetRules(rules []protocol.FilterRule, self []netip.Prefix) {
	st := &filterState{rules: rules, self: map[netip.Addr]bool{}}
	for _, p := range self {
		st.self[p.Addr()] = true
	}
	f.state.Store(st)
}

// Outbound records a packet leaving this device (never blocks).
func (f *Filter) Outbound(b []byte) {
	if p, ok := parsePacket(b); ok {
		f.ct.outbound(p)
	}
}

// AllowInbound decides whether a decrypted packet from a peer may be
// delivered to the OS.
func (f *Filter) AllowInbound(b []byte) bool {
	p, ok := parsePacket(b)
	if !ok {
		return false
	}
	st := f.state.Load()
	if !st.self[p.dst] {
		return false // not addressed to us (no subnet routing until it's approved)
	}
	if p.nonFirstFrag {
		// The first fragment carries the ports and is filtered; without it
		// the OS can't reassemble, so later fragments are harmless.
		return true
	}
	if f.ct.isReply(p) {
		return true
	}
	if isICMPError(p.proto, p.icmpType) {
		return false // errors only for flows we track
	}
	if p.proto == protocol.ProtoICMP || p.proto == protocol.ProtoICMPv6 {
		if p.icmpType == 0 || p.icmpType == 129 {
			return false // unsolicited echo reply
		}
		return protocol.Allowed(st.rules, p.src, p.proto, 0)
	}
	return protocol.Allowed(st.rules, p.src, p.proto, p.dstPort)
}

// filteredTUN wraps a tun.Device: packets read from the OS (outbound) are
// connection-tracked; packets written to the OS (inbound from peers, already
// decrypted and source-checked by WireGuard's cryptokey routing) are filtered.
type filteredTUN struct {
	tun.Device
	f *Filter
}

func (t *filteredTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.Device.Read(bufs, sizes, offset)
	for i := 0; i < n; i++ {
		t.f.Outbound(bufs[i][offset : offset+sizes[i]])
	}
	return n, err
}

func (t *filteredTUN) Write(bufs [][]byte, offset int) (int, error) {
	kept := bufs[:0:0]
	for _, b := range bufs {
		if t.f.AllowInbound(b[offset:]) {
			kept = append(kept, b)
		} else {
			t.f.Dropped.Add(1)
		}
	}
	if len(kept) == 0 {
		return len(bufs), nil
	}
	if _, err := t.Device.Write(kept, offset); err != nil {
		return 0, err
	}
	return len(bufs), nil
}
