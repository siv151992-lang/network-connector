package api

import (
	"net/netip"
	"strings"
	"testing"
)

// world is a network with an owner (alice), a member (bob), an auditor
// (carol) and an outsider (dave).
type world struct {
	e                       *env
	alice, bob, carol, dave *client
	nid, bobID              string
}

func newWorld(t *testing.T) *world {
	e := newEnv(t, nil)
	e.createUser("alice@example.com", pw, false)
	bob := e.createUser("bob@example.com", pw, false)
	e.createUser("carol@example.com", pw, false)
	e.createUser("dave@example.com", pw, false)
	w := &world{e: e,
		alice: e.loggedIn("alice@example.com", pw), bob: e.loggedIn("bob@example.com", pw),
		carol: e.loggedIn("carol@example.com", pw), dave: e.loggedIn("dave@example.com", pw),
		bobID: bob.ID.String()}

	r := w.alice.must(201, "POST", "/api/v1/networks", map[string]any{"name": "Home Lab"})
	w.nid = r.str(t, "network.id")
	w.alice.must(201, "POST", "/api/v1/networks/"+w.nid+"/members", map[string]string{"email": "bob@example.com", "role": "member"})
	w.alice.must(201, "POST", "/api/v1/networks/"+w.nid+"/members", map[string]string{"email": "carol@example.com", "role": "auditor"})
	return w
}

func (w *world) path(p string) string { return "/api/v1/networks/" + w.nid + p }

func TestE2ENetworks(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	r := w.alice.must(200, "GET", w.path(""), nil)
	n := r.json(t)
	if get(n, "network.slug") != "home-lab" || get(n, "role") != "owner" || get(n, "network.ipv4_cidr") != "100.64.0.0/10" {
		t.Fatalf("network: %s", r.body)
	}
	v6 := netip.MustParsePrefix(get(n, "network.ipv6_cidr").(string))
	if v6.Bits() != 48 || v6.Addr().As16()[0] != 0xfd {
		t.Fatalf("ipv6 prefix %s", v6)
	}

	// Same name again gets a de-duplicated slug; an explicit duplicate slug is a conflict.
	r = w.alice.must(201, "POST", "/api/v1/networks", map[string]any{"name": "Home Lab"})
	if s := r.str(t, "network.slug"); !strings.HasPrefix(s, "home-lab-") || len(s) != len("home-lab-")+4 {
		t.Fatalf("dedup slug %q", s)
	}
	w.alice.errCode(409, "conflict", "POST", "/api/v1/networks", map[string]any{"name": "x", "slug": "home-lab"})
	w.alice.errCode(422, "validation_failed", "POST", "/api/v1/networks", map[string]any{"name": "", "key_expiry_days": -1})

	// Outsiders can't see the network at all (404, not 403).
	w.dave.errCode(404, "not_found", "GET", w.path(""), nil)
	w.dave.errCode(404, "not_found", "GET", "/api/v1/networks/not-a-uuid", nil)
	if nets := get(w.dave.must(200, "GET", "/api/v1/networks", nil).json(t), "networks").([]any); len(nets) != 0 {
		t.Fatal("dave sees networks")
	}

	// Membership management.
	w.alice.errCode(404, "not_found", "POST", w.path("/members"), map[string]string{"email": "ghost@example.com"})
	w.alice.errCode(409, "conflict", "POST", w.path("/members"), map[string]string{"email": "bob@example.com"})
	w.bob.errCode(403, "forbidden", "POST", w.path("/members"), map[string]string{"email": "dave@example.com"})
	w.bob.errCode(403, "forbidden", "PATCH", w.path(""), map[string]any{"name": "Mine"})
	w.alice.must(200, "PATCH", w.path(""), map[string]any{"device_approval_required": false, "key_expiry_days": 30})
	if len(get(w.bob.must(200, "GET", w.path("/members"), nil).json(t), "members").([]any)) != 3 {
		t.Fatal("member list")
	}

	// Only owners grant ownership; the last owner can't leave.
	w.alice.must(201, "POST", w.path("/members"), map[string]string{"email": "dave@example.com", "role": "admin"})
	w.dave.errCode(403, "forbidden", "PATCH", w.path("/members/"+w.bobID), map[string]string{"role": "owner"})
	aliceID := w.alice.must(200, "GET", "/api/v1/auth/me", nil).str(t, "user.id")
	w.alice.errCode(422, "invalid", "DELETE", w.path("/members/"+aliceID), nil)
	w.dave.errCode(403, "forbidden", "DELETE", w.path("/members/"+aliceID), nil)

	// Audit trail is visible to admins and auditors only.
	entries := get(w.carol.must(200, "GET", w.path("/audit-logs?limit=100"), nil).json(t), "entries").([]any)
	actions := map[string]bool{}
	for _, en := range entries {
		actions[get(en, "action").(string)] = true
	}
	for _, a := range []string{"network.create", "member.add", "network.update"} {
		if !actions[a] {
			t.Errorf("audit log missing %s: %v", a, actions)
		}
	}
	w.bob.errCode(403, "forbidden", "GET", w.path("/audit-logs"), nil)

	w.dave.errCode(403, "forbidden", "DELETE", w.path(""), nil) // admin, not owner
	w.alice.must(204, "DELETE", w.path(""), nil)
	w.bob.errCode(404, "not_found", "GET", w.path(""), nil)
}

func TestE2EDeviceLifecycle(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	tt := t

	// Auth keys: admin only, validated, raw key shown once.
	w.bob.errCode(403, "forbidden", "POST", w.path("/auth-keys"), map[string]any{})
	w.alice.errCode(422, "validation_failed", "POST", w.path("/auth-keys"), map[string]any{"tags": []string{"servers"}})
	r := w.alice.must(201, "POST", w.path("/auth-keys"), map[string]any{"description": "laptop", "expires_in_hours": 1})
	key := r.str(t, "key")
	if !strings.HasPrefix(key, "wmk_") || !strings.HasPrefix(key, r.str(t, "auth_key.prefix")) {
		t.Fatalf("auth key: %s", r.body)
	}
	if strings.Contains(string(w.alice.must(200, "GET", w.path("/auth-keys"), nil).body), key) {
		t.Fatal("raw key returned by list")
	}

	// Unauthenticated / malformed registrations.
	dev := w.e.client()
	dev.errCode(401, "unauthorized", "POST", "/api/v1/device/register", map[string]string{"node_key": wgKey(t), "disco_key": wgKey(t)})
	dev.errCode(422, "validation_failed", "POST", "/api/v1/device/register", map[string]string{"auth_key": key, "node_key": "AAAA", "disco_key": wgKey(t)})

	// Register with the key: pending because the network requires approval.
	nodeKey := wgKey(t)
	r = dev.must(201, "POST", "/api/v1/device/register", map[string]string{
		"auth_key": key, "node_key": nodeKey, "disco_key": wgKey(t), "hostname": "Alice-Laptop.local", "os": "linux"})
	did := r.str(t, "device.id")
	dev.bearer = r.str(t, "credential")
	if r.str(t, "device.status") != "pending" || r.str(t, "device.ipv4") != "100.64.0.1" || r.str(t, "device.name") != "alice-laptop" ||
		r.str(t, "device.node_key") != nodeKey || !strings.HasPrefix(dev.bearer, "wmd_") || strings.Contains(string(r.body), "credential_hash") {
		t.Fatalf("register: %s", r.body)
	}
	w.e.client().errCode(401, "invalid_auth_key", "POST", "/api/v1/device/register", map[string]string{"auth_key": key, "node_key": wgKey(t), "disco_key": wgKey(t)})

	if dev.must(200, "GET", "/api/v1/device/self", nil).str(t, "device.status") != "pending" {
		t.Fatal("self status")
	}
	dev.errCode(403, "forbidden", "POST", "/api/v1/device/rotate-key", map[string]string{"node_key": wgKey(t), "disco_key": wgKey(t)})

	// Visibility and approval permissions.
	if n := len(get(w.bob.must(200, "GET", w.path("/devices"), nil).json(t), "devices").([]any)); n != 0 {
		t.Fatalf("member sees %d foreign devices", n)
	}
	w.bob.errCode(404, "not_found", "GET", w.path("/devices/"+did), nil)
	w.bob.errCode(403, "forbidden", "POST", w.path("/devices/"+did+"/approve"), nil)
	if n := len(get(w.carol.must(200, "GET", w.path("/devices?status=pending"), nil).json(t), "devices").([]any)); n != 1 {
		t.Fatalf("auditor sees %d pending", n)
	}
	w.carol.errCode(403, "forbidden", "POST", w.path("/devices/"+did+"/approve"), nil)

	r = w.alice.must(200, "POST", w.path("/devices/"+did+"/approve"), nil)
	if r.str(t, "device.status") != "approved" || r.str(t, "device.approved_by") == "" {
		t.Fatalf("approve: %s", r.body)
	}
	w.alice.errCode(422, "invalid", "POST", w.path("/devices/"+did+"/reject"), nil) // approved -> rejected not allowed

	// Key rotation by the device itself.
	newKey := wgKey(t)
	if dev.must(200, "POST", "/api/v1/device/rotate-key", map[string]string{"node_key": newKey, "disco_key": wgKey(t)}).str(t, "device.node_key") != newKey {
		t.Fatal("rotate-key")
	}

	// Interactive registration by a signed-in member (needs CSRF).
	bobKey := wgKey(t)
	saved := w.bob.csrf
	w.bob.csrf = ""
	w.bob.errCode(403, "csrf_failed", "POST", "/api/v1/device/register", map[string]string{"network_id": w.nid, "node_key": bobKey, "disco_key": wgKey(t)})
	w.bob.csrf = saved
	r = w.bob.must(201, "POST", "/api/v1/device/register", map[string]string{"network_id": w.nid, "node_key": bobKey, "disco_key": wgKey(t), "hostname": "bob-phone"})
	bobDev := w.e.client()
	bobDev.bearer = r.str(t, "credential")
	bobDID := r.str(t, "device.id")
	if r.str(t, "device.ipv4") != "100.64.0.2" || r.str(t, "device.status") != "pending" {
		t.Fatalf("bob device: %s", r.body)
	}
	w.bob.errCode(409, "conflict", "POST", "/api/v1/device/register", map[string]string{"network_id": w.nid, "node_key": bobKey, "disco_key": wgKey(t)})
	w.carol.errCode(403, "forbidden", "POST", "/api/v1/device/register", map[string]string{"network_id": w.nid, "node_key": wgKey(t), "disco_key": wgKey(t)})
	w.dave.errCode(404, "not_found", "POST", "/api/v1/device/register", map[string]string{"network_id": w.nid, "node_key": wgKey(t), "disco_key": wgKey(t)})

	// Owners rename their devices; only admins tag.
	w.bob.must(200, "PATCH", w.path("/devices/"+bobDID), map[string]string{"name": "pixel"})
	w.bob.errCode(422, "validation_failed", "PATCH", w.path("/devices/"+bobDID), map[string]string{"name": "Bad Name"})
	w.bob.errCode(409, "conflict", "PATCH", w.path("/devices/"+bobDID), map[string]string{"name": "alice-laptop"})
	w.bob.errCode(403, "forbidden", "PATCH", w.path("/devices/"+bobDID), map[string]any{"tags": []string{"tag:phone"}})
	if tags := get(w.alice.must(200, "PATCH", w.path("/devices/"+bobDID), map[string]any{"tags": []string{"tag:phone"}}).json(t), "device.tags").([]any); tags[0] != "tag:phone" {
		t.Fatal("tags")
	}

	// A device owner can revoke their own device; revocation kills its credential.
	w.bob.must(200, "POST", w.path("/devices/"+bobDID+"/revoke"), nil)
	bobDev.errCode(401, "unauthorized", "GET", "/api/v1/device/self", nil)
	w.alice.must(200, "POST", w.path("/devices/"+did+"/revoke"), nil)
	dev.errCode(401, "unauthorized", "GET", "/api/v1/device/self", nil)
	w.alice.errCode(422, "invalid", "POST", w.path("/devices/"+did+"/approve"), nil) // revoked is terminal

	// Preauthorized, reusable, ephemeral, tagged key: approved immediately;
	// logout deletes the device and frees its address.
	r = w.alice.must(201, "POST", w.path("/auth-keys"), map[string]any{
		"reusable": true, "ephemeral": true, "preauthorized": true, "tags": []string{"tag:ci"}})
	ciKey := r.str(t, "key")
	var ciIDs []string
	for i := 0; i < 2; i++ {
		ci := w.e.client()
		r = ci.must(201, "POST", "/api/v1/device/register", map[string]string{"auth_key": ciKey, "node_key": wgKey(t), "disco_key": wgKey(t), "hostname": "runner"})
		if r.str(t, "device.status") != "approved" || get(r.json(t), "device.ephemeral") != true || get(r.json(t), "device.tags.0") != "tag:ci" {
			t.Fatalf("ci device: %s", r.body)
		}
		ci.bearer = r.str(t, "credential")
		ciIDs = append(ciIDs, r.str(t, "device.id"))
		if i == 1 {
			if r.str(t, "device.name") != "runner-2" {
				t.Fatalf("name dedup: %s", r.str(t, "device.name"))
			}
			ci.must(204, "POST", "/api/v1/device/logout", nil)
			w.alice.errCode(404, "not_found", "GET", w.path("/devices/"+ciIDs[1]), nil)
		}
	}

	// Removing a member deletes their devices.
	w.alice.must(204, "DELETE", w.path("/members/"+w.bobID), nil)
	w.alice.errCode(404, "not_found", "GET", w.path("/devices/"+bobDID), nil)
	w.bob.errCode(404, "not_found", "GET", w.path("/devices"), nil)

	// Every state change is audited.
	entries := get(w.alice.must(200, "GET", w.path("/audit-logs?limit=200"), nil).json(tt), "entries").([]any)
	actions := map[string]int{}
	for _, en := range entries {
		actions[get(en, "action").(string)]++
	}
	for _, a := range []string{"auth_key.create", "device.register", "device.approve", "device.rotate_key", "device.rename", "device.tags", "device.revoke", "device.logout", "member.remove"} {
		if actions[a] == 0 {
			t.Errorf("audit log missing %s: %v", a, actions)
		}
	}
}
