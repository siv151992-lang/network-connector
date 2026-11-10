package api

import (
	"strings"
	"testing"
)

func TestE2EDeviceCodeLogin(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	dev := w.e.client()
	nodeKey := wgKey(t)
	r := dev.must(201, "POST", "/api/v1/device/login/start", map[string]string{
		"node_key": nodeKey, "disco_key": wgKey(t), "hostname": "headless-box", "os": "linux"})
	code, poll := r.str(t, "code"), r.str(t, "poll_token")
	if len(code) != 9 || code[4] != '-' || !strings.HasSuffix(r.str(t, "verify_url"), "/activate?code="+code) {
		t.Fatalf("start: %s", r.body)
	}
	if dev.must(200, "POST", "/api/v1/device/login/poll", map[string]string{"poll_token": poll}).str(t, "status") != "pending" {
		t.Fatal("expected pending")
	}

	// The user looks the code up (case/format-insensitive) and approves into a network.
	lower := strings.ToLower(strings.ReplaceAll(code, "-", ""))
	if w.bob.must(200, "GET", "/api/v1/device/login/"+lower, nil).str(t, "login.hostname") != "headless-box" {
		t.Fatal("lookup by code")
	}
	w.carol.errCode(403, "forbidden", "POST", "/api/v1/device/login/approve", map[string]string{"code": code, "network_id": w.nid}) // auditor
	w.dave.errCode(404, "not_found", "POST", "/api/v1/device/login/approve", map[string]string{"code": code, "network_id": w.nid})  // outsider
	r = w.bob.must(200, "POST", "/api/v1/device/login/approve", map[string]string{"code": code, "network_id": w.nid})
	if r.str(t, "device.name") != "headless-box" || r.str(t, "device.node_key") != nodeKey {
		t.Fatalf("approve: %s", r.body)
	}
	w.bob.errCode(404, "not_found", "POST", "/api/v1/device/login/approve", map[string]string{"code": code, "network_id": w.nid}) // single use

	// The device receives its credential exactly once, and it works.
	r = dev.must(200, "POST", "/api/v1/device/login/poll", map[string]string{"poll_token": poll})
	cred := r.str(t, "credential")
	if r.str(t, "status") != "approved" || !strings.HasPrefix(cred, "wmd_") {
		t.Fatalf("poll: %s", r.body)
	}
	dev.errCode(410, "login_expired", "POST", "/api/v1/device/login/poll", map[string]string{"poll_token": poll})
	dev.bearer = cred
	if dev.must(200, "GET", "/api/v1/device/self", nil).str(t, "device.status") != "pending" { // network requires approval
		t.Fatal("device status")
	}
	// A registered node key can't start another login.
	w.e.client().errCode(409, "conflict", "POST", "/api/v1/device/login/start", map[string]string{"node_key": nodeKey, "disco_key": wgKey(t)})
	w.e.client().errCode(400, "bad_request", "POST", "/api/v1/device/login/poll", map[string]string{"poll_token": "wml_bogus"})
}
