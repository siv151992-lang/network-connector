package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/siv151992-lang/network-connector/pkg/protocol"
	"github.com/siv151992-lang/network-connector/pkg/relayproto"
)

func key(b byte) protocol.Key { var k protocol.Key; k[0] = b; return k }

type env struct {
	t   *testing.T
	s   *Server
	url string
	sk  ed25519.PrivateKey
}

func newEnv(t *testing.T) *env {
	sk, err := relayproto.SigningKey(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{ControlKey: sk.Public().(ed25519.PublicKey)}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	return &env{t: t, s: s, url: "ws" + strings.TrimPrefix(srv.URL, "http"), sk: sk}
}

func (e *env) token(k protocol.Key, network string, ttl time.Duration) string {
	tok, err := relayproto.Sign(e.sk, relayproto.Claims{NodeKey: k, NetworkID: network, Expires: time.Now().Add(ttl).Unix()})
	if err != nil {
		e.t.Fatal(err)
	}
	return tok
}

func (e *env) dial(tok string) *websocket.Conn {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, e.url, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { c.CloseNow() })
	if err := c.Write(ctx, websocket.MessageText, []byte(tok)); err != nil {
		e.t.Fatal(err)
	}
	return c
}

func send(t *testing.T, c *websocket.Conn, to protocol.Key, p []byte) {
	t.Helper()
	if err := c.Write(context.Background(), websocket.MessageBinary, relayproto.Encode(relayproto.FrameSend, to, p)); err != nil {
		t.Fatal(err)
	}
}

func (e *env) waitClients(n int) {
	for i := 0; i < 100 && e.s.Clients() != n; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if e.s.Clients() != n {
		e.t.Fatalf("clients = %d, want %d", e.s.Clients(), n)
	}
}

func TestForwardsWithinNetwork(t *testing.T) {
	e := newEnv(t)
	a := e.dial(e.token(key(1), "net1", time.Minute))
	b := e.dial(e.token(key(2), "net1", time.Minute))
	e.waitClients(2)

	send(t, a, key(2), []byte("ciphertext"))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, msg, err := b.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	typ, from, payload, err := relayproto.Decode(msg)
	if err != nil || typ != relayproto.FrameRecv || from != key(1) || string(payload) != "ciphertext" {
		t.Fatalf("got %d %v %q %v", typ, from, payload, err)
	}
}

func TestRejectsBadTokens(t *testing.T) {
	e := newEnv(t)
	other, _ := relayproto.SigningKey(bytes.Repeat([]byte{8}, 32))
	forged, _ := relayproto.Sign(other, relayproto.Claims{NodeKey: key(1), NetworkID: "n", Expires: time.Now().Add(time.Minute).Unix()})
	for name, tok := range map[string]string{
		"garbage": "nope", "expired": e.token(key(1), "n", -time.Second), "wrong signer": forged,
	} {
		c := e.dial(tok)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, _, err := c.Read(ctx)
		cancel()
		if websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
			t.Errorf("%s: want policy-violation close, got %v", name, err)
		}
	}
	if e.s.Clients() != 0 {
		t.Fatal("unauthenticated client registered")
	}
}

func TestIsolatesNetworks(t *testing.T) {
	e := newEnv(t)
	a := e.dial(e.token(key(1), "net1", time.Minute))
	c := e.dial(e.token(key(3), "net2", time.Minute))
	e.waitClients(2)
	send(t, a, key(3), []byte("x"))
	send(t, a, key(9), []byte("x")) // unknown peer
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, _, err := c.Read(ctx); err == nil {
		t.Fatal("packet crossed networks")
	}
	if e.s.Dropped.Load() != 2 || e.s.Forwarded.Load() != 0 {
		t.Fatalf("dropped=%d forwarded=%d", e.s.Dropped.Load(), e.s.Forwarded.Load())
	}
}

func TestTokenRoundTripAndFrames(t *testing.T) {
	sk, _ := relayproto.SigningKey(bytes.Repeat([]byte{1}, 32))
	sk2, _ := relayproto.SigningKey(bytes.Repeat([]byte{1}, 32))
	if !sk.Equal(sk2) {
		t.Fatal("key derivation not deterministic")
	}
	tok, _ := relayproto.Sign(sk, relayproto.Claims{NodeKey: key(5), NetworkID: "n", Expires: time.Now().Add(time.Minute).Unix()})
	c, err := relayproto.Verify(sk.Public().(ed25519.PublicKey), tok, time.Now())
	if err != nil || c.NodeKey != key(5) {
		t.Fatalf("verify: %v", err)
	}
	if _, err := relayproto.Verify(sk.Public().(ed25519.PublicKey), tok[:len(tok)-2]+"AA", time.Now()); err == nil {
		t.Fatal("tampered token accepted")
	}
	if _, _, _, err := relayproto.Decode(make([]byte, 10)); err == nil {
		t.Fatal("short frame accepted")
	}
	if _, _, _, err := relayproto.Decode(make([]byte, 33+relayproto.MaxPayload+1)); err == nil {
		t.Fatal("oversized frame accepted")
	}
}
