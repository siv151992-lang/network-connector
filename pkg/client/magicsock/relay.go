package magicsock

import (
	"context"
	"net"
	"time"

	"github.com/coder/websocket"
	"golang.zx2c4.com/wireguard/conn"

	"github.com/siv151992-lang/network-connector/pkg/protocol"
	"github.com/siv151992-lang/network-connector/pkg/relayproto"
)

// Relay fallback: the device stays connected to its home relay (the first
// relay in the network map). Whenever a peer has no confirmed direct path,
// WireGuard packets go through the relay, so peers connect immediately even
// behind symmetric NATs or while a direct path is being (re)discovered. Path
// discovery keeps running, and traffic moves to the direct path as soon as
// one is confirmed. The relay only ever sees WireGuard ciphertext.

type relayPkt struct {
	from protocol.Key
	b    []byte
}

func (c *Conn) setRelays(relays []protocol.Relay) {
	url := ""
	if len(relays) > 0 {
		url = relays[0].URL
	}
	if url != c.relayURL {
		c.relayURL = url
		select {
		case c.relayChange <- struct{}{}:
		default:
		}
	}
}

// relayLoop maintains the home-relay connection.
func (c *Conn) relayLoop() {
	backoff := time.Second
	for {
		c.mu.Lock()
		url, tokenFn := c.relayURL, c.o.RelayToken
		c.mu.Unlock()
		if url == "" || tokenFn == nil {
			select {
			case <-c.stop:
				return
			case <-c.relayChange:
				continue
			}
		}
		err := c.runRelay(url, tokenFn)
		c.relayUp.Store(false)
		select {
		case <-c.stop:
			return
		default:
		}
		if err != nil {
			c.log.Warn("relay connection lost; reconnecting", "relay", url, "error", err, "in", backoff)
		}
		select {
		case <-c.stop:
			return
		case <-c.relayChange:
			backoff = time.Second
		case <-time.After(backoff):
			backoff = min(backoff*2, 30*time.Second)
		}
	}
}

// SetRelayToken sets how relay tokens are obtained.
func (c *Conn) SetRelayToken(f func(context.Context) (string, error)) {
	c.mu.Lock()
	c.o.RelayToken = f
	c.mu.Unlock()
	select {
	case c.relayChange <- struct{}{}:
	default:
	}
}

func (c *Conn) runRelay(url string, tokenFn func(context.Context) (string, error)) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-c.stop:
		case <-c.relayChange: // relay list changed: reconnect
		case <-ctx.Done():
		}
		cancel()
	}()

	tctx, tc := context.WithTimeout(ctx, 15*time.Second)
	tok, err := tokenFn(tctx)
	tc()
	if err != nil {
		return err
	}
	dctx, dc := context.WithTimeout(ctx, 15*time.Second)
	ws, _, err := websocket.Dial(dctx, url, nil)
	dc()
	if err != nil {
		return err
	}
	defer ws.CloseNow()
	ws.SetReadLimit(4096)
	if err := ws.Write(ctx, websocket.MessageText, []byte(tok)); err != nil {
		return err
	}
	c.relayUp.Store(true)
	c.log.Info("relay connected", "relay", url)

	errc := make(chan error, 3)
	go func() { // writer
		for {
			select {
			case <-ctx.Done():
				errc <- ctx.Err()
				return
			case f := <-c.relayOut:
				wctx, wc := context.WithTimeout(ctx, 10*time.Second)
				err := ws.Write(wctx, websocket.MessageBinary, f)
				wc()
				if err != nil {
					errc <- err
					return
				}
			}
		}
	}()
	go func() { // keepalive
		t := time.NewTicker(25 * time.Second)
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
					errc <- err
					return
				}
			}
		}
	}()
	go func() { // reader
		for {
			_, b, err := ws.Read(ctx)
			if err != nil {
				errc <- err
				return
			}
			typ, from, payload, err := relayproto.Decode(b)
			if err != nil || typ != relayproto.FrameRecv {
				continue
			}
			select {
			case c.relayIn <- relayPkt{from: from, b: append([]byte(nil), payload...)}:
			default: // WireGuard not keeping up: drop
			}
		}
	}()
	return <-errc
}

// sendRelay queues a packet for a peer via the relay. It reports false if
// no relay is connected.
func (c *Conn) sendRelay(to protocol.Key, b []byte) bool {
	if !c.relayUp.Load() || len(b) > relayproto.MaxPayload {
		return false
	}
	select {
	case c.relayOut <- relayproto.Encode(relayproto.FrameSend, to, b):
		c.Relayed.Add(1)
	default: // relay link congested: drop, WireGuard handles loss
	}
	return true
}

// relayReceiver feeds relayed WireGuard packets from known peers to
// wireguard-go. It returns when the bind is closed.
func (c *Conn) relayReceiver(closing <-chan struct{}) conn.ReceiveFunc {
	return func(pkts [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			select {
			case <-closing:
				return 0, net.ErrClosed
			case p := <-c.relayIn:
				c.mu.Lock()
				peer := c.peers[p.from]
				c.mu.Unlock()
				if peer == nil || len(p.b) > len(pkts[0]) {
					c.DroppedUnknown.Add(1)
					continue
				}
				sizes[0] = copy(pkts[0], p.b)
				eps[0] = peer.ep
				return 1, nil
			}
		}
	}
}
