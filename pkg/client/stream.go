package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/siv151992-lang/network-connector/pkg/protocol"
)

// Stream is the device's control stream (WebSocket).
type Stream struct {
	ws *websocket.Conn
	mu sync.Mutex // serializes writes
}

// Stream opens the control stream. 401 maps to ErrUnauthorized and
// device_not_approved to ErrNotApproved.
func (c *Control) Stream(ctx context.Context) (*Stream, error) {
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+c.credential)
	hdr.Set("User-Agent", c.userAgent)
	ws, resp, err := websocket.Dial(ctx, c.base.String()+"/api/v1/device/stream", &websocket.DialOptions{
		HTTPHeader: hdr, HTTPClient: &http.Client{Timeout: 30 * time.Second},
		CompressionMode: websocket.CompressionContextTakeover,
	})
	if err != nil {
		if resp != nil {
			switch resp.StatusCode {
			case http.StatusUnauthorized:
				return nil, fmt.Errorf("%w: stream refused", ErrUnauthorized)
			case http.StatusForbidden:
				return nil, ErrNotApproved
			}
		}
		return nil, fmt.Errorf("control stream: %w", err)
	}
	ws.SetReadLimit(16 << 20) // network maps of large networks
	return &Stream{ws: ws}, nil
}

// Recv returns the next message.
func (s *Stream) Recv(ctx context.Context) (protocol.StreamMessage, error) {
	var m protocol.StreamMessage
	_, data, err := s.ws.Read(ctx)
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return m, fmt.Errorf("control stream: bad message: %w", err)
	}
	return m, nil
}

// Send writes a message.
func (s *Stream) Send(ctx context.Context, m protocol.StreamMessage) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.ws.Write(wctx, websocket.MessageText, b)
}

// KeepAlive pings the server every interval and returns when a ping fails
// (dead connection), so a silently dropped stream is noticed quickly.
func (s *Stream) KeepAlive(ctx context.Context, interval time.Duration) error {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := s.ws.Ping(pctx)
			cancel()
			if err != nil {
				return errors.New("control stream: server stopped answering pings")
			}
		}
	}
}

// Close closes the stream.
func (s *Stream) Close() { s.ws.Close(websocket.StatusNormalClosure, "bye") }
