package api

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/siv151992-lang/network-connector/pkg/protocol"
	"github.com/siv151992-lang/network-connector/pkg/relayproto"
)

type wsDevice struct {
	t  *testing.T
	ws *websocket.Conn
}

func (w *world) dial(t *testing.T, cred string) (*wsDevice, *http.Response, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hdr := http.Header{"Authorization": {"Bearer " + cred}}
	ws, resp, err := websocket.Dial(ctx, w.e.srv.URL+"/api/v1/device/stream", &websocket.DialOptions{HTTPHeader: hdr})
	if err != nil {
		return nil, resp, err
	}
	ws.SetReadLimit(1 << 20)
	t.Cleanup(func() { ws.CloseNow() })
	return &wsDevice{t: t, ws: ws}, resp, nil
}

func (d *wsDevice) send(m protocol.StreamMessage) {
	d.t.Helper()
	b, _ := json.Marshal(m)
	if err := d.ws.Write(context.Background(), websocket.MessageText, b); err != nil {
		d.t.Fatal(err)
	}
}

// next returns the next message matching pred, failing after timeout.
func (d *wsDevice) next(pred func(protocol.StreamMessage) bool) protocol.StreamMessage {
	d.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		_, data, err := d.ws.Read(ctx)
		if err != nil {
			d.t.Fatalf("stream read: %v", err)
		}
		var m protocol.StreamMessage
		if err := json.Unmarshal(data, &m); err != nil {
			d.t.Fatal(err)
		}
		if pred(m) {
			return m
		}
	}
}

func isMap(f func(*protocol.NetworkMap) bool) func(protocol.StreamMessage) bool {
	return func(m protocol.StreamMessage) bool { return m.Type == protocol.StreamMap && f(m.Map) }
}

func TestE2EStream(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	key := w.alice.must(201, "POST", w.path("/auth-keys"), map[string]any{"reusable": true, "preauthorized": true}).str(t, "key")
	a, aID := w.enroll(t, key, "alpha")

	// Bad credential and unapproved devices are refused before upgrade.
	if _, resp, err := w.dial(t, "wmd_"+strings.Repeat("A", 43)); err == nil || resp == nil || resp.StatusCode != 401 {
		t.Fatalf("bad credential: %v %v", err, resp)
	}
	pendKey := w.alice.must(201, "POST", w.path("/auth-keys"), map[string]any{}).str(t, "key")
	p, _ := w.enroll(t, pendKey, "pending")
	if _, resp, err := w.dial(t, p.bearer); err == nil || resp == nil || resp.StatusCode != 403 {
		t.Fatalf("pending device: %v %v", err, resp)
	}

	sa, _, err := w.dial(t, a.bearer)
	if err != nil {
		t.Fatal(err)
	}
	m := sa.next(isMap(func(nm *protocol.NetworkMap) bool { return true }))
	if m.Map.Self.Name != "alpha" || len(m.Map.Peers) != 0 {
		t.Fatalf("first map: %+v", m.Map)
	}

	// Presence: alpha is online in the dashboard API.
	if get(w.alice.must(200, "GET", w.path("/devices/"+aID), nil).json(t), "device.online") != true {
		t.Fatal("alpha not online while streaming")
	}

	// A new device joining is pushed immediately (no polling).
	b, bID := w.enroll(t, key, "bravo")
	sa.next(isMap(func(nm *protocol.NetworkMap) bool {
		return len(nm.Peers) == 1 && nm.Peers[0].Name == "bravo" && !nm.Peers[0].Online
	}))
	sb, _, err := w.dial(t, b.bearer)
	if err != nil {
		t.Fatal(err)
	}
	sb.next(isMap(func(nm *protocol.NetworkMap) bool { return len(nm.Peers) == 1 }))
	// ...and bravo coming online is pushed to alpha.
	sa.next(isMap(func(nm *protocol.NetworkMap) bool { return len(nm.Peers) == 1 && nm.Peers[0].Online }))

	// Endpoints reported over the stream reach the peer's map.
	ep := netip.MustParseAddrPort("198.51.100.20:41000")
	sb.send(protocol.StreamMessage{Type: protocol.StreamEndpoints, Endpoints: &protocol.EndpointsUpdate{Endpoints: []netip.AddrPort{ep}}})
	sa.next(isMap(func(nm *protocol.NetworkMap) bool {
		return len(nm.Peers[0].Endpoints) == 1 && nm.Peers[0].Endpoints[0] == ep
	}))

	// Call-me-maybe is forwarded, with From set by the server (not the client).
	bKey := mustKey(t, w, b)
	aKey := mustKey(t, w, a)
	var forged protocol.Key
	forged[0] = 7
	sa.send(protocol.StreamMessage{Type: protocol.StreamCallMeMaybe, CallMeMaybe: &protocol.CallMeMaybe{From: forged, To: bKey, Endpoints: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.1:1")}}})
	got := sb.next(func(m protocol.StreamMessage) bool { return m.Type == protocol.StreamCallMeMaybe })
	if got.CallMeMaybe.From != aKey || got.CallMeMaybe.Endpoints[0].String() != "203.0.113.1:1" {
		t.Fatalf("forwarded cmm: %+v", got.CallMeMaybe)
	}

	// Under a policy where they can't see each other, call-me-maybe is not forwarded.
	w.alice.must(200, "PUT", w.path("/acl"), map[string]any{"version": 0, "policy": map[string]any{"acls": []any{}}})
	sa.next(isMap(func(nm *protocol.NetworkMap) bool { return len(nm.Peers) == 0 })) // ACL change pushed
	sb.next(isMap(func(nm *protocol.NetworkMap) bool { return len(nm.Peers) == 0 }))
	sa.send(protocol.StreamMessage{Type: protocol.StreamCallMeMaybe, CallMeMaybe: &protocol.CallMeMaybe{To: bKey, Endpoints: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.1:2")}}})
	// (A Read with a cancelled context would close the WebSocket, so instead
	// restore the policy and check nothing call-me-maybe-shaped arrives first.)
	time.Sleep(300 * time.Millisecond)
	w.alice.must(200, "PUT", w.path("/acl"), map[string]any{"version": 1, "policy": map[string]any{
		"acls": []any{map[string]any{"action": "accept", "src": []string{"*"}, "dst": []string{"*:*"}}}}})
	leaked := false
	sb.next(func(m protocol.StreamMessage) bool {
		if m.Type == protocol.StreamCallMeMaybe {
			leaked = true
		}
		return m.Type == protocol.StreamMap && len(m.Map.Peers) == 1
	})
	if leaked {
		t.Fatal("call-me-maybe leaked across the policy")
	}

	// Revocation: bravo is told and disconnected; alpha sees it go.
	w.alice.must(200, "POST", w.path("/devices/"+bID+"/revoke"), nil)
	rctx, rcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer rcancel()
	revoked := false
	for {
		_, data, err := sb.ws.Read(rctx)
		if err != nil {
			break
		}
		if strings.Contains(string(data), `"revoked"`) {
			revoked = true
		}
	}
	if !revoked {
		t.Fatal("revoked message not received before close")
	}
	if get(w.alice.must(200, "GET", w.path("/devices/"+bID), nil).json(t), "device.online") != false {
		t.Fatal("revoked device still online")
	}
}

func mustKey(t *testing.T, w *world, d *client) protocol.Key {
	t.Helper()
	k, err := protocol.ParseKey(d.must(200, "GET", "/api/v1/device/self", nil).str(t, "device.node_key"))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestE2ERelayToken(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	key := w.alice.must(201, "POST", w.path("/auth-keys"), map[string]any{"preauthorized": true}).str(t, "key")
	d, _ := w.enroll(t, key, "relay-user")
	tok := d.must(200, "POST", "/api/v1/device/relay-token", map[string]any{}).str(t, "token")

	sk, err := relayproto.SigningKey(testSecret)
	if err != nil {
		t.Fatal(err)
	}
	c, err := relayproto.Verify(sk.Public().(ed25519.PublicKey), tok, time.Now())
	if err != nil || c.NodeKey != mustKey(t, w, d) || c.NetworkID != w.nid {
		t.Fatalf("token claims: %+v %v", c, err)
	}
	if time.Unix(c.Expires, 0).After(time.Now().Add(11 * time.Minute)) {
		t.Fatal("token lifetime too long")
	}

	pend := w.alice.must(201, "POST", w.path("/auth-keys"), map[string]any{}).str(t, "key")
	p, _ := w.enroll(t, pend, "pending")
	p.errCode(403, "forbidden", "POST", "/api/v1/device/relay-token", map[string]any{})
	w.e.client().errCode(401, "unauthorized", "POST", "/api/v1/device/relay-token", map[string]any{})
}
