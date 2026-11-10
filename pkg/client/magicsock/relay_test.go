package magicsock

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/siv151992-lang/network-connector/pkg/protocol"
	"github.com/siv151992-lang/network-connector/pkg/relayproto"
	"github.com/siv151992-lang/network-connector/relay"
)

func TestRelayFallbackThenDirectUpgrade(t *testing.T) {
	sk, _ := relayproto.SigningKey(bytes.Repeat([]byte{3}, 32))
	srv := &relay.Server{ControlKey: sk.Public().(ed25519.PublicKey)}
	hs := httptest.NewServer(srv)
	defer hs.Close()
	relays := []protocol.Relay{{ID: 1, URL: hs.URL}}

	a, b := newNode(t, "100.64.0.1"), newNode(t, "100.64.0.2")
	for _, n := range []*node{a, b} {
		nk := n.node.Public()
		n.ms.SetRelayToken(func(context.Context) (string, error) {
			return relayproto.Sign(sk, relayproto.Claims{NodeKey: nk, NetworkID: "net", Expires: time.Now().Add(time.Minute).Unix()})
		})
	}
	// No candidate addresses at all: only the relay can connect them.
	connect(t, a, b, nil, nil)
	a.ms.SetPeers([]protocol.Node{b.asPeer()}, nil, relays)
	b.ms.SetPeers([]protocol.Node{a.asPeer()}, nil, relays)
	waitFor(t, "both relay links up", func() bool { return a.ms.relayUp.Load() && b.ms.relayUp.Load() })

	ping(t, a, b)
	ping(t, b, a)
	if a.ms.Relayed.Load() == 0 || srv.Forwarded.Load() == 0 {
		t.Fatal("traffic did not go through the relay")
	}
	if p, _ := a.ms.PeerPath(b.node.Public()); p.IsValid() {
		t.Fatal("unexpected direct path")
	}

	// Now they learn each other's addresses: traffic moves to a direct path.
	a.ms.SetPeers([]protocol.Node{b.asPeer(b.addr())}, nil, relays)
	b.ms.SetPeers([]protocol.Node{a.asPeer(a.addr())}, nil, relays)
	waitFor(t, "direct path after upgrade", func() bool { p, _ := a.ms.PeerPath(b.node.Public()); return p == b.addr() })
	// Assert on fresh traffic only: WireGuard's 1 s persistent keepalives
	// over 2.5 s must all go direct. (Stale copies of earlier relayed test
	// packets may still be queued, so a ping alone could pass trivially.)
	go func() {
		for range b.tun.Inbound {
		}
	}()
	time.Sleep(500 * time.Millisecond) // sends issued before the switch drain
	relayed0, direct0 := a.ms.Relayed.Load(), a.ms.Direct.Load()
	time.Sleep(2500 * time.Millisecond)
	if a.ms.Relayed.Load() != relayed0 {
		t.Fatalf("relayed %d packets after a direct path was confirmed", a.ms.Relayed.Load()-relayed0)
	}
	if a.ms.Direct.Load() == direct0 {
		t.Fatal("no traffic on the direct path after the upgrade")
	}
}
