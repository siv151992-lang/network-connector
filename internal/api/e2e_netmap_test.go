package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// enroll registers a device with a fresh key and returns its bearer client and id.
func (w *world) enroll(t *testing.T, key, host string) (*client, string) {
	t.Helper()
	d := w.e.client()
	r := d.must(201, "POST", "/api/v1/device/register", map[string]string{
		"auth_key": key, "node_key": wgKey(t), "disco_key": wgKey(t), "hostname": host, "os": "linux"})
	d.bearer = r.str(t, "credential")
	return d, r.str(t, "device.id")
}

func TestE2ENetmapAndACL(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	key := w.alice.must(201, "POST", w.path("/auth-keys"), map[string]any{"reusable": true, "preauthorized": true}).str(t, "key")
	a, aID := w.enroll(t, key, "alpha")
	b, _ := w.enroll(t, key, "bravo")

	// Default policy: everyone sees everyone and may send anything.
	r := a.must(200, "GET", "/api/v1/device/netmap", nil)
	nm := r.json(t)
	if get(nm, "self.name") != "alpha" || len(get(nm, "peers").([]any)) != 1 || get(nm, "peers.0.name") != "bravo" {
		t.Fatalf("netmap: %s", r.body)
	}
	if get(nm, "self.user") != "alice@example.com" || get(nm, "poll_interval") != "10s" || len(get(nm, "packet_filter").([]any)) != 1 {
		t.Fatalf("netmap fields: %s", r.body)
	}
	if strings.Contains(string(r.body), "credential") || strings.Contains(string(r.body), "private") {
		t.Fatal("netmap leaks secrets")
	}

	// ETag: unchanged map -> 304, even though last_seen moved.
	etag := r.hdr.Get("ETag")
	if a.do("GET", "/api/v1/device/netmap", nil).hdr.Get("ETag") != etag {
		t.Fatal("etag changed without content change")
	}
	if code := a.withHeader("If-None-Match", etag).do("GET", "/api/v1/device/netmap", nil).code; code != 304 {
		t.Fatalf("If-None-Match: got %d", code)
	}

	// Endpoints: validated, deduplicated, then visible to peers (and the ETag changes).
	a.errCode(422, "validation_failed", "POST", "/api/v1/device/endpoints", map[string]any{"endpoints": []string{"127.0.0.1:51820"}})
	a.errCode(422, "validation_failed", "POST", "/api/v1/device/endpoints", map[string]any{"endpoints": []string{"192.0.2.1:0"}})
	a.must(204, "POST", "/api/v1/device/endpoints", map[string]any{"endpoints": []string{"192.0.2.1:51820", "192.0.2.1:51820", "[2001:db8::1]:51820"}, "listen_port": 51820})
	r = b.must(200, "GET", "/api/v1/device/netmap", nil)
	eps := get(r.json(t), "peers.0.endpoints").([]any)
	if len(eps) != 2 || eps[0] != "192.0.2.1:51820" {
		t.Fatalf("endpoints in peer map: %v", eps)
	}
	if a.withHeader("If-None-Match", etag).do("GET", "/api/v1/device/netmap", nil).code != 200 {
		t.Fatal("map version did not change after endpoint update")
	}

	// ACL: read default, write with version check, validation errors.
	acl := w.bob.must(200, "GET", w.path("/acl"), nil).json(t)
	if get(acl, "is_default") != true || get(acl, "version") != 0.0 {
		t.Fatalf("default acl: %v", acl)
	}
	w.bob.errCode(403, "forbidden", "PUT", w.path("/acl"), map[string]any{"version": 0, "policy": map[string]any{"acls": []any{}}})
	w.alice.errCode(422, "validation_failed", "PUT", w.path("/acl"), map[string]any{"policy": map[string]any{"acls": []any{}}})
	w.alice.errCode(422, "invalid_policy", "PUT", w.path("/acl"), map[string]any{"version": 0,
		"policy": map[string]any{"acls": []any{map[string]any{"action": "accept", "src": []string{"group:ghosts"}, "dst": []string{"*:*"}}}}})

	// Only alpha -> bravo:22 over TCP.
	policy := map[string]any{"acls": []any{map[string]any{"action": "accept", "proto": "tcp",
		"src": []string{"100.64.0.1"}, "dst": []string{"100.64.0.2:22"}}}}
	r = w.alice.must(200, "PUT", w.path("/acl"), map[string]any{"version": 0, "policy": policy})
	if get(r.json(t), "version") != 1.0 {
		t.Fatalf("saved version: %s", r.body)
	}
	w.alice.errCode(409, "stale_version", "PUT", w.path("/acl"), map[string]any{"version": 0, "policy": policy})

	// Maps reflect the policy: both still see each other (reachability in one
	// direction), but only bravo gets a filter rule.
	nmA := a.must(200, "GET", "/api/v1/device/netmap", nil).json(t)
	nmB := b.must(200, "GET", "/api/v1/device/netmap", nil).json(t)
	if len(get(nmA, "peers").([]any)) != 1 || len(get(nmB, "peers").([]any)) != 1 {
		t.Fatal("peers should be visible in both directions")
	}
	if len(get(nmA, "packet_filter").([]any)) != 0 {
		t.Fatalf("alpha should accept nothing new: %v", get(nmA, "packet_filter"))
	}
	if get(nmB, "packet_filter.0.ports.0.first") != 22.0 || get(nmB, "packet_filter.0.src_ips.0") != "100.64.0.1/32" {
		t.Fatalf("bravo filter: %v", get(nmB, "packet_filter"))
	}

	// Test endpoint (admins/auditors), by name, address or id.
	test := func(c *client, src, dst, proto string, port int) bool {
		t.Helper()
		v := c.must(200, "POST", w.path("/acl/test"), map[string]any{"src": src, "dst": dst, "proto": proto, "port": port}).json(t)
		return get(v, "allowed") == true
	}
	if !test(w.carol, "alpha", "bravo", "tcp", 22) || test(w.carol, "alpha", "bravo", "tcp", 23) ||
		test(w.carol, "bravo", "100.64.0.1", "tcp", 22) || test(w.alice, aID, "bravo", "icmp", 0) {
		t.Fatal("acl test results wrong")
	}
	w.bob.errCode(403, "forbidden", "POST", w.path("/acl/test"), map[string]any{"src": "alpha", "dst": "bravo"})
	w.carol.errCode(422, "validation_failed", "POST", w.path("/acl/test"), map[string]any{"src": "nope", "dst": "bravo"})
	// Draft policy evaluation doesn't save anything.
	draft := map[string]any{"acls": []any{map[string]any{"action": "accept", "src": []string{"*"}, "dst": []string{"*:*"}}}}
	if !test2(t, w, map[string]any{"src": "bravo", "dst": "alpha", "proto": "icmp", "policy": draft}) {
		t.Fatal("draft policy not applied")
	}
	if get(w.alice.must(200, "GET", w.path("/acl"), nil).json(t), "version") != 1.0 {
		t.Fatal("draft was saved")
	}

	// Empty policy: deny all -> no peers.
	w.alice.must(200, "PUT", w.path("/acl"), map[string]any{"version": 1, "policy": map[string]any{"acls": []any{}}})
	if n := len(get(a.must(200, "GET", "/api/v1/device/netmap", nil).json(t), "peers").([]any)); n != 0 {
		t.Fatalf("deny-all still shows %d peers", n)
	}
}

func test2(t *testing.T, w *world, body map[string]any) bool {
	t.Helper()
	return get(w.alice.must(200, "POST", w.path("/acl/test"), body).json(t), "allowed") == true
}

func TestE2ENetmapPendingAndExpired(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	key := w.alice.must(201, "POST", w.path("/auth-keys"), map[string]any{"reusable": true}).str(t, "key") // needs approval
	p, pID := w.enroll(t, key, "pending-box")
	p.errCode(403, "device_not_approved", "GET", "/api/v1/device/netmap", nil)

	pre := w.alice.must(201, "POST", w.path("/auth-keys"), map[string]any{"reusable": true, "preauthorized": true}).str(t, "key")
	ok, _ := w.enroll(t, pre, "ok-box")
	if n := len(get(ok.must(200, "GET", "/api/v1/device/netmap", nil).json(t), "peers").([]any)); n != 0 {
		t.Fatalf("pending device leaked into peers (%d)", n)
	}
	w.alice.must(200, "POST", w.path("/devices/"+pID+"/approve"), nil)
	if n := len(get(ok.must(200, "GET", "/api/v1/device/netmap", nil).json(t), "peers").([]any)); n != 1 {
		t.Fatal("approved device missing from peers")
	}

	// Expired key: the device gets no peers and disappears from others' maps.
	past := time.Now().Add(-time.Hour)
	if _, err := w.e.store.Pool().Exec(context.Background(), `UPDATE devices SET key_expires_at = $1 WHERE id = $2`, past, uuid.MustParse(pID)); err != nil {
		t.Fatal(err)
	}
	nm := p.must(200, "GET", "/api/v1/device/netmap", nil).json(t)
	if get(nm, "self.key_expired") != true || len(get(nm, "peers").([]any)) != 0 {
		t.Fatalf("expired self: %v", nm)
	}
	if n := len(get(ok.must(200, "GET", "/api/v1/device/netmap", nil).json(t), "peers").([]any)); n != 0 {
		t.Fatal("expired device still a peer")
	}
	// Rotating the key renews expiry and brings it back.
	p.must(200, "POST", "/api/v1/device/rotate-key", map[string]string{"node_key": wgKey(t), "disco_key": wgKey(t)})
	if n := len(get(ok.must(200, "GET", "/api/v1/device/netmap", nil).json(t), "peers").([]any)); n != 1 {
		t.Fatal("rotated device not back in peers")
	}
}
