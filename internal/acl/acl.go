// Package acl parses, validates and compiles network access policies.
//
// A policy is a default-deny list of "accept" rules:
//
//	{
//	  "groups": {"group:admins": ["alice@example.com"]},
//	  "hosts":  {"office-lan": "192.168.10.0/24"},
//	  "acls": [
//	    {"action": "accept", "src": ["group:admins"], "dst": ["*:*"]},
//	    {"action": "accept", "src": ["autogroup:member"], "dst": ["tag:web:80,443"], "proto": "tcp"},
//	    {"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]}
//	  ]
//	}
//
// Selectors (src and the part of dst before the last ':'):
//
//   - every device / every address
//     alice@example.com  untagged devices owned by that user
//     group:<name>       untagged devices owned by any user in the group
//     tag:<name>         devices carrying the tag (tagged devices have no user identity)
//     autogroup:member   all untagged (user-owned) devices
//     autogroup:tagged   all tagged devices
//     autogroup:self     (dst only) devices owned by the same user as the source device
//     <host alias>       an entry from "hosts"
//     100.64.0.5, 10.0.0.0/8, [fd7a::1], [fd7a::/48]   addresses/prefixes
//
// Ports (after the last ':' in dst): "*", "22", "80,443", "8000-8100".
// IPv6 literals in dst must be bracketed: "[fd7a::1]:22".
//
// Compilation per device produces (1) its visible peers, i.e. devices it may
// reach or be reached by, and (2) its inbound packet filter. Enforcement is on
// the receiving device, so a compromised sender can't bypass it.
package acl

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/siv151992-lang/network-connector/pkg/protocol"
)

// Policy is the JSON document stored per network.
type Policy struct {
	Groups map[string][]string `json:"groups,omitempty"`
	Hosts  map[string]string   `json:"hosts,omitempty"`
	ACLs   []Rule              `json:"acls"`
}

// Rule is one accept rule.
type Rule struct {
	Action string   `json:"action"`
	Src    []string `json:"src"`
	Dst    []string `json:"dst"`
	Proto  string   `json:"proto,omitempty"` // tcp | udp | icmp | "" (any)
}

// DefaultPolicyJSON allows every device to reach every other device: the
// sensible default for a personal network. Admins should tighten it for
// shared networks.
const DefaultPolicyJSON = `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`

// Limits bound compile cost (the policy is attacker-influenced input if an
// admin account is compromised; it must not be able to stall the server).
const (
	maxRules     = 1000
	maxSelectors = 256
	maxGroups    = 500
	maxMembers   = 1000
	maxPolicyLen = 256 << 10
)

var (
	groupName = regexp.MustCompile(`^group:[a-z0-9][a-z0-9_-]{0,62}$`)
	tagName   = regexp.MustCompile(`^tag:[a-z0-9][a-z0-9-]{0,62}$`)
	hostName  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	emailLike = regexp.MustCompile(`^[^@\s:]+@[^@\s:]+\.[^@\s:]+$`)
)

// ValidationError lists every problem in a policy, with JSON-path-like locations.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string { return "invalid policy: " + strings.Join(e.Problems, "; ") }

// Parse decodes and validates a policy, rejecting unknown fields.
func Parse(b []byte) (*Policy, error) {
	if len(b) > maxPolicyLen {
		return nil, &ValidationError{Problems: []string{fmt.Sprintf("policy larger than %d bytes", maxPolicyLen)}}
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, &ValidationError{Problems: []string{"malformed JSON: " + err.Error()}}
	}
	if dec.More() {
		return nil, &ValidationError{Problems: []string{"trailing data after policy object"}}
	}
	if _, err := Compile(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

// MustDefault returns the default allow-all policy.
func MustDefault() *Policy {
	p, err := Parse([]byte(DefaultPolicyJSON))
	if err != nil {
		panic(err)
	}
	return p
}

// ---------------------------------------------------------------------------
// Compilation
// ---------------------------------------------------------------------------

type matcherKind int

const (
	mAny matcherKind = iota
	mMember
	mTagged
	mSelf
	mUser
	mGroup
	mTag
	mPrefix
)

type matcher struct {
	kind   matcherKind
	user   string
	users  map[string]bool
	tag    string
	prefix netip.Prefix
}

type dstMatcher struct {
	matcher
	ports []protocol.PortRange
}

type compiledRule struct {
	src    []matcher
	dst    []dstMatcher
	protos []int
}

// Compiled is a validated policy ready for evaluation.
type Compiled struct{ rules []compiledRule }

// Device is the identity of a device for policy evaluation.
type Device struct {
	ID    string
	User  string   // owner email; ignored when Tags is non-empty
	Tags  []string // tagged devices are identified by tags only
	Addrs []netip.Addr
}

func (d Device) tagged() bool { return len(d.Tags) > 0 }

func (d Device) hasTag(t string) bool {
	for _, x := range d.Tags {
		if x == t {
			return true
		}
	}
	return false
}

// Compile validates p and builds matchers.
func Compile(p *Policy) (*Compiled, error) {
	var probs []string
	bad := func(format string, args ...any) { probs = append(probs, fmt.Sprintf(format, args...)) }

	if len(p.Groups) > maxGroups {
		bad("at most %d groups", maxGroups)
	}
	groups := map[string]map[string]bool{}
	for name, members := range p.Groups {
		if !groupName.MatchString(name) {
			bad("groups: %q must look like group:name", name)
			continue
		}
		if len(members) > maxMembers {
			bad("groups.%s: at most %d members", name, maxMembers)
		}
		set := map[string]bool{}
		for _, m := range members {
			if !emailLike.MatchString(m) {
				bad("groups.%s: %q is not an email address (groups can't nest)", name, m)
				continue
			}
			set[strings.ToLower(m)] = true
		}
		groups[name] = set
	}
	hosts := map[string]netip.Prefix{}
	for name, v := range p.Hosts {
		if !hostName.MatchString(name) {
			bad("hosts: %q must be lowercase letters, digits and dashes", name)
			continue
		}
		pfx, err := parsePrefix(v)
		if err != nil {
			bad("hosts.%s: %v", name, err)
			continue
		}
		hosts[name] = pfx
	}

	if len(p.ACLs) > maxRules {
		bad("at most %d rules", maxRules)
	}
	c := &Compiled{}
	for i, r := range p.ACLs {
		at := fmt.Sprintf("acls[%d]", i)
		if r.Action != "accept" {
			bad("%s.action must be \"accept\" (policies are default-deny)", at)
		}
		if len(r.Src) == 0 || len(r.Dst) == 0 {
			bad("%s: src and dst must be non-empty", at)
		}
		if len(r.Src) > maxSelectors || len(r.Dst) > maxSelectors {
			bad("%s: at most %d selectors in src/dst", at, maxSelectors)
			continue
		}
		var cr compiledRule
		switch strings.ToLower(r.Proto) {
		case "":
		case "tcp":
			cr.protos = []int{protocol.ProtoTCP}
		case "udp":
			cr.protos = []int{protocol.ProtoUDP}
		case "icmp":
			cr.protos = []int{protocol.ProtoICMP, protocol.ProtoICMPv6}
		default:
			bad("%s.proto must be tcp, udp, icmp or empty", at)
		}
		for j, s := range r.Src {
			m, err := parseSelector(s, groups, hosts)
			if err != nil {
				bad("%s.src[%d]: %v", at, j, err)
				continue
			}
			if m.kind == mSelf {
				bad("%s.src[%d]: autogroup:self is only valid in dst", at, j)
				continue
			}
			cr.src = append(cr.src, m)
		}
		for j, d := range r.Dst {
			sel, portSpec, err := splitDst(d)
			if err != nil {
				bad("%s.dst[%d]: %v", at, j, err)
				continue
			}
			m, err := parseSelector(sel, groups, hosts)
			if err != nil {
				bad("%s.dst[%d]: %v", at, j, err)
				continue
			}
			ports, err := parsePorts(portSpec)
			if err != nil {
				bad("%s.dst[%d]: %v", at, j, err)
				continue
			}
			if strings.EqualFold(r.Proto, "icmp") && !(len(ports) == 1 && ports[0] == protocol.AllPorts) {
				bad("%s.dst[%d]: icmp rules must use port *", at, j)
			}
			cr.dst = append(cr.dst, dstMatcher{matcher: m, ports: ports})
		}
		c.rules = append(c.rules, cr)
	}
	if len(probs) > 0 {
		sort.Strings(probs)
		return nil, &ValidationError{Problems: probs}
	}
	return c, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid prefix %q", s)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid address %q", s)
	}
	return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
}

func parseSelector(s string, groups map[string]map[string]bool, hosts map[string]netip.Prefix) (matcher, error) {
	switch {
	case s == "*":
		return matcher{kind: mAny}, nil
	case s == "autogroup:member":
		return matcher{kind: mMember}, nil
	case s == "autogroup:tagged":
		return matcher{kind: mTagged}, nil
	case s == "autogroup:self":
		return matcher{kind: mSelf}, nil
	case strings.HasPrefix(s, "autogroup:"):
		return matcher{}, fmt.Errorf("unknown autogroup %q", s)
	case strings.HasPrefix(s, "group:"):
		set, ok := groups[s]
		if !ok {
			return matcher{}, fmt.Errorf("undefined group %q", s)
		}
		return matcher{kind: mGroup, users: set}, nil
	case strings.HasPrefix(s, "tag:"):
		if !tagName.MatchString(s) {
			return matcher{}, fmt.Errorf("invalid tag %q", s)
		}
		return matcher{kind: mTag, tag: s}, nil
	case emailLike.MatchString(s):
		return matcher{kind: mUser, user: strings.ToLower(s)}, nil
	}
	if p, ok := hosts[s]; ok {
		return matcher{kind: mPrefix, prefix: p}, nil
	}
	p, err := parsePrefix(s)
	if err != nil {
		return matcher{}, fmt.Errorf("unknown selector %q (not *, a user, group:, tag:, autogroup:, host alias or IP)", s)
	}
	return matcher{kind: mPrefix, prefix: p}, nil
}

// splitDst splits "selector:ports" at the last colon. Bracketed IPv6 is supported.
func splitDst(s string) (string, string, error) {
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 || len(s) < end+3 || s[end+1] != ':' {
			return "", "", fmt.Errorf("%q: IPv6 destinations look like [fd7a::1]:22", s)
		}
		return s[:end+1], s[end+2:], nil
	}
	i := strings.LastIndex(s, ":")
	if i <= 0 || i == len(s)-1 {
		return "", "", fmt.Errorf("%q: destination must be selector:ports, e.g. tag:web:443 or *:*", s)
	}
	if strings.Count(s[:i], ":") > 1 && !strings.HasPrefix(s, "tag:") && !strings.HasPrefix(s, "group:") && !strings.HasPrefix(s, "autogroup:") {
		return "", "", fmt.Errorf("%q: bracket IPv6 addresses, e.g. [fd7a::1]:22", s)
	}
	return s[:i], s[i+1:], nil
}

func parsePorts(spec string) ([]protocol.PortRange, error) {
	if spec == "*" {
		return []protocol.PortRange{protocol.AllPorts}, nil
	}
	var out []protocol.PortRange
	for _, part := range strings.Split(spec, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		first, err1 := strconv.ParseUint(lo, 10, 16)
		last := first
		var err2 error
		if isRange {
			last, err2 = strconv.ParseUint(hi, 10, 16)
		}
		if err1 != nil || err2 != nil || first > last {
			return nil, fmt.Errorf("invalid port spec %q (use *, 22, 80,443 or 8000-8100)", spec)
		}
		out = append(out, protocol.PortRange{First: uint16(first), Last: uint16(last)})
	}
	return out, nil
}

// matchesDevice reports whether m selects device d. mSelf is handled by callers.
func (m matcher) matchesDevice(d Device) bool {
	switch m.kind {
	case mAny:
		return true
	case mMember:
		return !d.tagged()
	case mTagged:
		return d.tagged()
	case mUser:
		return !d.tagged() && strings.EqualFold(d.User, m.user)
	case mGroup:
		return !d.tagged() && m.users[strings.ToLower(d.User)]
	case mTag:
		return d.hasTag(m.tag)
	case mPrefix:
		for _, a := range d.Addrs {
			if m.prefix.Contains(a) {
				return true
			}
		}
	}
	return false
}

// dstApplies reports whether dst selector m covers device dst for traffic from src.
func dstApplies(m matcher, src, dst Device) bool {
	if m.kind == mSelf {
		return !src.tagged() && !dst.tagged() && src.User != "" && strings.EqualFold(src.User, dst.User)
	}
	return m.matchesDevice(dst)
}

// CanReach reports whether any rule lets src open connections to dst (on any port).
func (c *Compiled) CanReach(src, dst Device) bool {
	for _, r := range c.rules {
		srcOK := false
		for _, m := range r.src {
			if m.matchesDevice(src) {
				srcOK = true
				break
			}
		}
		if !srcOK {
			continue
		}
		for _, d := range r.dst {
			if dstApplies(d.matcher, src, dst) {
				return true
			}
		}
	}
	return false
}

// Peers returns the subset of all devices that self may see: those it can
// reach or that can reach it. self is never included.
func (c *Compiled) Peers(self Device, all []Device) []Device {
	var out []Device
	for _, d := range all {
		if d.ID == self.ID {
			continue
		}
		if c.CanReach(self, d) || c.CanReach(d, self) {
			out = append(out, d)
		}
	}
	return out
}

var (
	allV4 = netip.MustParsePrefix("0.0.0.0/0")
	allV6 = netip.MustParsePrefix("::/0")
)

// Filter compiles the inbound packet filter for device self, given every
// device in the network.
func (c *Compiled) Filter(self Device, all []Device) []protocol.FilterRule {
	var out []protocol.FilterRule
	for _, r := range c.rules {
		for _, d := range r.dst {
			var srcs []netip.Prefix
			seen := map[netip.Prefix]bool{}
			add := func(p netip.Prefix) {
				if !seen[p] {
					seen[p] = true
					srcs = append(srcs, p)
				}
			}
			for _, sm := range r.src {
				// Address selectors and "*" contribute prefixes directly, but
				// only if the destination selector covers self regardless of
				// the source's identity (autogroup:self needs a known owner).
				if d.kind != mSelf && d.matchesDevice(self) {
					switch sm.kind {
					case mAny:
						add(allV4)
						add(allV6)
						continue
					case mPrefix:
						add(sm.prefix)
						continue
					}
				}
				for _, src := range all {
					if sm.matchesDevice(src) && dstApplies(d.matcher, src, self) {
						for _, a := range src.Addrs {
							add(netip.PrefixFrom(a, a.BitLen()))
						}
					}
				}
			}
			if len(srcs) == 0 {
				continue
			}
			sort.Slice(srcs, func(i, j int) bool { return srcs[i].String() < srcs[j].String() })
			out = append(out, protocol.FilterRule{SrcIPs: srcs, Protos: r.protos, Ports: d.ports})
		}
	}
	return out
}

// Check evaluates the compiled filter for dst against one packet from src.
// It is the same logic devices run, exposed for the "test access" API.
func (c *Compiled) Check(src, dst Device, all []Device, proto int, port uint16) bool {
	for _, a := range src.Addrs {
		if Allowed(c.Filter(dst, all), a, proto, port) {
			return true
		}
	}
	return false
}

// Allowed evaluates filter rules for a new inbound flow. It is the same
// function devices run (protocol.Allowed), so server-side tests match reality.
func Allowed(rules []protocol.FilterRule, src netip.Addr, proto int, port uint16) bool {
	return protocol.Allowed(rules, src, proto, port)
}
