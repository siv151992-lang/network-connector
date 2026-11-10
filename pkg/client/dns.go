package client

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/siv151992-lang/network-connector/pkg/protocol"
)

// DNSServer answers A/AAAA queries for <device>.<network domain> from the
// current network map ("MagicDNS"). It listens on the device's own tunnel
// address, and the OS resolver is pointed at it for that domain only.
// Anything outside the domain is REFUSED: it is not a general resolver.
type DNSServer struct {
	mu      sync.RWMutex
	domain  string                  // "home.wm.internal." (lower case, trailing dot)
	records map[string][]netip.Addr // fqdn -> addresses
	conn    *net.UDPConn
}

const (
	dnsTypeA    = 1
	dnsTypeAAAA = 28
	dnsTTL      = 60
)

// Update rebuilds the records from a network map.
func (d *DNSServer) Update(nm *protocol.NetworkMap) {
	if nm == nil || nm.Network.Domain == "" {
		return
	}
	dom := strings.ToLower(strings.TrimSuffix(nm.Network.Domain, ".")) + "."
	recs := map[string][]netip.Addr{}
	add := func(n protocol.Node) {
		if n.Name == "" {
			return
		}
		fqdn := strings.ToLower(n.Name) + "." + dom
		for _, p := range n.Addresses {
			recs[fqdn] = append(recs[fqdn], p.Addr())
		}
	}
	add(nm.Self)
	for _, p := range nm.Peers {
		add(p)
	}
	d.mu.Lock()
	d.domain, d.records = dom, recs
	d.mu.Unlock()
}

// Domain returns the served domain without the trailing dot.
func (d *DNSServer) Domain() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return strings.TrimSuffix(d.domain, ".")
}

// Listen binds UDP on addr (typically <tunnel IPv4>:53) and serves until Close.
func (d *DNSServer) Listen(addr netip.AddrPort) error {
	c, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(addr))
	if err != nil {
		return err
	}
	d.mu.Lock()
	d.conn = c
	d.mu.Unlock()
	go func() {
		buf := make([]byte, 512)
		for {
			n, src, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if resp := d.Answer(buf[:n]); resp != nil {
				_, _ = c.WriteToUDPAddrPort(resp, src)
			}
		}
	}()
	return nil
}

// Close stops serving.
func (d *DNSServer) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conn != nil {
		d.conn.Close()
		d.conn = nil
	}
}

var errDNS = errors.New("dns: malformed query")

// parseQuestion returns the lower-cased qname (with trailing dot), qtype and
// the offset just past the question.
func parseQuestion(q []byte) (string, uint16, int, error) {
	off := 12
	var labels []string
	for total := 0; ; {
		if off >= len(q) {
			return "", 0, 0, errDNS
		}
		l := int(q[off])
		off++
		if l == 0 {
			break
		}
		if l&0xc0 != 0 || off+l > len(q) { // no compression in questions
			return "", 0, 0, errDNS
		}
		total += l + 1
		if total > 255 {
			return "", 0, 0, errDNS
		}
		labels = append(labels, strings.ToLower(string(q[off:off+l])))
		off += l
	}
	if off+4 > len(q) {
		return "", 0, 0, errDNS
	}
	return strings.Join(labels, ".") + ".", binary.BigEndian.Uint16(q[off:]), off + 4, nil
}

// Answer builds the response to one query packet (nil = drop).
func (d *DNSServer) Answer(q []byte) []byte {
	if len(q) < 12 || q[2]&0x80 != 0 { // too short, or a response
		return nil
	}
	resp := func(rcode byte, qend int, answers [][]byte, aa bool) []byte {
		out := make([]byte, 12, 512)
		copy(out[0:2], q[0:2])        // ID
		out[2] = 0x80 | (q[2] & 0x79) // QR=1, keep opcode and RD
		if aa {
			out[2] |= 0x04
		}
		out[3] = rcode
		if qend > 0 {
			binary.BigEndian.PutUint16(out[4:], 1)
			out = append(out, q[12:qend]...)
		}
		binary.BigEndian.PutUint16(out[6:], uint16(len(answers)))
		for _, a := range answers {
			out = append(out, a...)
		}
		return out
	}
	if (q[2]>>3)&0x0f != 0 {
		return resp(4, 0, nil, false) // NOTIMP: only standard queries
	}
	if binary.BigEndian.Uint16(q[4:6]) != 1 {
		return resp(1, 0, nil, false) // FORMERR
	}
	name, qtype, qend, err := parseQuestion(q)
	if err != nil {
		return resp(1, 0, nil, false)
	}
	d.mu.RLock()
	dom, addrs, known := d.domain, d.records[name], false
	_, known = d.records[name]
	d.mu.RUnlock()
	if dom == "" || (name != dom && !strings.HasSuffix(name, "."+dom)) {
		return resp(5, qend, nil, false) // REFUSED: not our zone
	}
	if !known {
		return resp(3, qend, nil, true) // NXDOMAIN
	}
	var answers [][]byte
	for _, a := range addrs {
		var rdata []byte
		switch {
		case qtype == dnsTypeA && a.Is4():
			b := a.As4()
			rdata = b[:]
		case qtype == dnsTypeAAAA && a.Is6():
			b := a.As16()
			rdata = b[:]
		default:
			continue
		}
		rr := []byte{0xc0, 12} // pointer to the question name
		rr = binary.BigEndian.AppendUint16(rr, qtype)
		rr = binary.BigEndian.AppendUint16(rr, 1) // IN
		rr = binary.BigEndian.AppendUint32(rr, dnsTTL)
		rr = binary.BigEndian.AppendUint16(rr, uint16(len(rdata)))
		answers = append(answers, append(rr, rdata...))
	}
	return resp(0, qend, answers, true)
}
