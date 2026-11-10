// Package relay is the WireMesh packet relay: it forwards encrypted packets
// between devices that can't reach each other directly (symmetric NATs, UDP
// blocked, or while a direct path is being set up). See pkg/relayproto.
package relay

import (
	"context"
	"crypto/ed25519"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/time/rate"

	"github.com/siv151992-lang/network-connector/pkg/protocol"
	"github.com/siv151992-lang/network-connector/pkg/relayproto"
)

// Server is an http.Handler serving the relay WebSocket.
type Server struct {
	ControlKey ed25519.PublicKey // verifies relay tokens
	Log        *slog.Logger
	// PacketsPerSec and Burst limit each client (bandwidth abuse protection).
	PacketsPerSec float64
	Burst         int
	Now           func() time.Time

	mu      sync.Mutex
	clients map[protocol.Key]*client

	Forwarded atomic.Uint64
	Dropped   atomic.Uint64
}

type client struct {
	key     protocol.Key
	network string
	out     chan []byte
	done    chan struct{}
	once    sync.Once
}

func (c *client) close() { c.once.Do(func() { close(c.done) }) }

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Clients returns the number of connected clients.
func (s *Server) Clients() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.clients) }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer ws.CloseNow()
	ws.SetReadLimit(4096)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Authenticate: first frame is the token, within 10 s.
	actx, acancel := context.WithTimeout(ctx, 10*time.Second)
	typ, tok, err := ws.Read(actx)
	acancel()
	if err != nil || typ != websocket.MessageText {
		return
	}
	claims, err := relayproto.Verify(s.ControlKey, string(tok), s.now())
	if err != nil {
		ws.Close(websocket.StatusPolicyViolation, "invalid relay token")
		return
	}

	c := &client{key: claims.NodeKey, network: claims.NetworkID, out: make(chan []byte, 256), done: make(chan struct{})}
	s.mu.Lock()
	if s.clients == nil {
		s.clients = map[protocol.Key]*client{}
	}
	if old := s.clients[c.key]; old != nil {
		old.close() // newest connection for a key wins
	}
	s.clients[c.key] = c
	s.mu.Unlock()
	defer func() {
		c.close()
		s.mu.Lock()
		if s.clients[c.key] == c {
			delete(s.clients, c.key)
		}
		s.mu.Unlock()
	}()
	if s.Log != nil {
		s.Log.Debug("relay client connected", "node", c.key.String()[:8])
	}

	// Writer.
	go func() {
		defer cancel()
		for {
			select {
			case <-ctx.Done():
				return
			case <-c.done:
				ws.Close(websocket.StatusGoingAway, "replaced")
				return
			case b := <-c.out:
				wctx, wc := context.WithTimeout(ctx, 10*time.Second)
				err := ws.Write(wctx, websocket.MessageBinary, b)
				wc()
				if err != nil {
					return
				}
			}
		}
	}()
	// Keepalive: detect dead clients.
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				pctx, pc := context.WithTimeout(ctx, 10*time.Second)
				err := ws.Ping(pctx)
				pc()
				if err != nil {
					cancel()
					return
				}
			}
		}
	}()

	pps, burst := s.PacketsPerSec, s.Burst
	if pps <= 0 {
		pps, burst = 20000, 4000
	}
	lim := rate.NewLimiter(rate.Limit(pps), burst)
	for {
		typ, b, err := ws.Read(ctx)
		if err != nil {
			return
		}
		if typ != websocket.MessageBinary {
			continue
		}
		ft, dst, payload, err := relayproto.Decode(b)
		if err != nil || ft != relayproto.FrameSend || !lim.Allow() {
			s.Dropped.Add(1)
			continue
		}
		s.mu.Lock()
		to := s.clients[dst]
		s.mu.Unlock()
		// Only within the same network: tokens bind keys to networks.
		if to == nil || to.network != c.network || to == c {
			s.Dropped.Add(1)
			continue
		}
		select {
		case to.out <- relayproto.Encode(relayproto.FrameRecv, c.key, payload):
			s.Forwarded.Add(1)
		default:
			s.Dropped.Add(1) // receiver too slow: drop, like a congested link
		}
	}
}
