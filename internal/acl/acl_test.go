package acl

import (
	"net/netip"
	"sort"
	"strings"
	"testing"

	"github.com/siv151992-lang/network-connector/pkg/protocol"
)

func dev(id, user string, ip string, tags ...string) Device {
	v4 := netip.MustParseAddr(ip)
	b := v4.As4()
	v6 := netip.AddrFrom16([16]byte{0xfd, 0x7a, 12: b[0], 13: b[1], 14: b[2], 15: b[3]})
	return Device{ID: id, User: user, Tags: tags, Addrs: []netip.Addr{v4, v6}}
}

var (
	aliceLaptop = dev("a1", "alice@example.com", "100.64.0.1")
	alicePhone  = dev("a2", "alice@example.com", "100.64.0.2")
	bobLaptop   = dev("b1", "bob@example.com", "100.64.0.3")
	webServer   = dev("w1", "alice@example.com", "100.64.0.4", "tag:web")
	dbServer    = dev("d1", "alice@example.com", "100.64.0.5", "tag:db")
	all         = []Device{aliceLaptop, alicePhone, bobLaptop, webServer, dbServer}
)

func mustCompile(t *testing.T, js string) *Compiled {
	t.Helper()
	p, err := Parse([]byte(js))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	c, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func ids(ds []Device) string {
	var s []string
	for _, d := range ds {
		s = append(s, d.ID)
	}
	sort.Strings(s)
	return strings.Join(s, ",")
}

func TestValidation(t *testing.T) {
	cases := map[string]string{
		`{"acls":[{"action":"deny","src":["*"],"dst":["*:*"]}]}`:                         `action must be "accept"`,
		`{"acls":[{"action":"accept","src":["group:nope"],"dst":["*:*"]}]}`:              `undefined group`,
		`{"acls":[{"action":"accept","src":["*"],"dst":["*"]}]}`:                         `selector:ports`,
		`{"acls":[{"action":"accept","src":["*"],"dst":["*:99999"]}]}`:                   `invalid port spec`,
		`{"acls":[{"action":"accept","src":["*"],"dst":["*:20-10"]}]}`:                   `invalid port spec`,
		`{"acls":[{"action":"accept","src":["autogroup:self"],"dst":["*:*"]}]}`:          `only valid in dst`,
		`{"acls":[{"action":"accept","src":["*"],"dst":["fd7a::1:22"]}]}`:                `bracket IPv6`,
		`{"acls":[{"action":"accept","src":["*"],"dst":["tag:web:22"],"proto":"icmp"}]}`: `icmp rules must use port *`,
		`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"],"proto":"sctp"}]}`:        `proto must be`,
		`{"groups":{"admins":["a@b.c"]},"acls":[]}`:                                      `must look like group:name`,
		`{"groups":{"group:x":["group:y"]},"acls":[]}`:                                   `groups can't nest`,
		`{"hosts":{"nas":"not-an-ip"},"acls":[]}`:                                        `invalid address`,
		`{"acls":[{"action":"accept","src":["Bad Selector"],"dst":["*:*"]}]}`:            `unknown selector`,
		`{"acls":[],"extra":1}`: `unknown field`,
		`{"acls":[]} {}`:        `trailing data`,
	}
	for js, want := range cases {
		_, err := Parse([]byte(js))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s\n  want error containing %q, got %v", js, want, err)
		}
	}
	// Several problems are reported at once.
	_, err := Parse([]byte(`{"acls":[{"action":"x","src":[],"dst":[]}]}`))
	if ve, ok := err.(*ValidationError); !ok || len(ve.Problems) < 2 {
		t.Fatalf("want multiple problems, got %v", err)
	}
	if _, err := Parse([]byte(`{"hosts":{"nas":"[fd7a::5]"},"acls":[{"action":"accept","src":["nas","10.0.0.0/8"],"dst":["[fd7a::1]:22","nas:80"]}]}`)); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
}

func TestDefaultPolicyAllowsEverything(t *testing.T) {
	c, _ := Compile(MustDefault())
	if got := ids(c.Peers(aliceLaptop, all)); got != "a2,b1,d1,w1" {
		t.Fatalf("peers = %s", got)
	}
	f := c.Filter(bobLaptop, all)
	if !Allowed(f, netip.MustParseAddr("100.64.0.1"), protocol.ProtoICMP, 0) || !Allowed(f, netip.MustParseAddr("100.64.0.1"), protocol.ProtoTCP, 22) {
		t.Fatal("default policy should allow all")
	}
}

func TestEmptyPolicyDeniesEverything(t *testing.T) {
	c := mustCompile(t, `{"acls":[]}`)
	if len(c.Peers(aliceLaptop, all)) != 0 || len(c.Filter(aliceLaptop, all)) != 0 {
		t.Fatal("empty policy must be default-deny")
	}
}

func TestIdentitySemantics(t *testing.T) {
	c := mustCompile(t, `{
	  "groups": {"group:admins": ["ALICE@example.com"]},
	  "acls": [
	    {"action":"accept","src":["group:admins"],"dst":["tag:db:5432"],"proto":"tcp"},
	    {"action":"accept","src":["autogroup:member"],"dst":["tag:web:80,443"]},
	    {"action":"accept","src":["tag:web"],"dst":["tag:db:5432"]},
	    {"action":"accept","src":["autogroup:member"],"dst":["autogroup:self:*"]}
	  ]}`)

	cases := []struct {
		src, dst Device
		proto    int
		port     uint16
		want     bool
	}{
		{aliceLaptop, dbServer, protocol.ProtoTCP, 5432, true},  // group member (case-insensitive email)
		{aliceLaptop, dbServer, protocol.ProtoUDP, 5432, false}, // proto restricted to tcp
		{aliceLaptop, dbServer, protocol.ProtoTCP, 22, false},   // port not listed
		{bobLaptop, dbServer, protocol.ProtoTCP, 5432, false},   // not in group
		{bobLaptop, webServer, protocol.ProtoTCP, 443, true},    // any member -> web
		{bobLaptop, webServer, protocol.ProtoICMP, 0, false},    // port-specific rule does not open ICMP
		{webServer, dbServer, protocol.ProtoTCP, 5432, true},    // tag -> tag
		{webServer, aliceLaptop, protocol.ProtoTCP, 22, false},  // tagged device has no user identity: not "self"
		{dbServer, webServer, protocol.ProtoTCP, 443, false},    // tagged device is not autogroup:member
		{alicePhone, aliceLaptop, protocol.ProtoTCP, 22, true},  // autogroup:self
		{bobLaptop, aliceLaptop, protocol.ProtoTCP, 22, false},  // other user's device
	}
	for _, tc := range cases {
		if got := c.Check(tc.src, tc.dst, all, tc.proto, tc.port); got != tc.want {
			t.Errorf("%s -> %s proto %d port %d: got %v want %v", tc.src.ID, tc.dst.ID, tc.proto, tc.port, got, tc.want)
		}
	}

	// Peer visibility is symmetric in reachability and hides unrelated devices.
	if got := ids(c.Peers(bobLaptop, all)); got != "w1" {
		t.Fatalf("bob's peers = %s (should only see the web server)", got)
	}
	if got := ids(c.Peers(dbServer, all)); got != "a1,a2,w1" {
		t.Fatalf("db's peers = %s", got)
	}
	if got := ids(c.Peers(aliceLaptop, all)); got != "a2,d1,w1" {
		t.Fatalf("alice laptop peers = %s", got)
	}
}

func TestPrefixSelectors(t *testing.T) {
	c := mustCompile(t, `{
	  "hosts": {"lan": "192.168.1.0/24"},
	  "acls": [
	    {"action":"accept","src":["lan"],"dst":["tag:web:22"]},
	    {"action":"accept","src":["100.64.0.3"],"dst":["100.64.0.1:8080"]}
	  ]}`)
	f := c.Filter(webServer, all)
	if !Allowed(f, netip.MustParseAddr("192.168.1.77"), protocol.ProtoTCP, 22) || Allowed(f, netip.MustParseAddr("192.168.2.1"), protocol.ProtoTCP, 22) {
		t.Fatalf("host alias prefix: %+v", f)
	}
	if !c.Check(bobLaptop, aliceLaptop, all, protocol.ProtoTCP, 8080) || c.Check(alicePhone, aliceLaptop, all, protocol.ProtoTCP, 8080) {
		t.Fatal("ip selector")
	}
	if got := ids(c.Peers(bobLaptop, all)); got != "a1" {
		t.Fatalf("peers by IP selector = %s", got)
	}
}

func TestFilterIncludesBothAddressFamilies(t *testing.T) {
	c := mustCompile(t, `{"acls":[{"action":"accept","src":["bob@example.com"],"dst":["alice@example.com:22"]}]}`)
	f := c.Filter(aliceLaptop, all)
	if len(f) != 1 || len(f[0].SrcIPs) != 2 {
		t.Fatalf("filter: %+v", f)
	}
	if !Allowed(f, bobLaptop.Addrs[1], protocol.ProtoTCP, 22) {
		t.Fatal("IPv6 source not allowed")
	}
}
