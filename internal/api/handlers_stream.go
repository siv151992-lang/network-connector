package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"golang.org/x/time/rate"

	"github.com/siv151992-lang/network-connector/internal/api/httpx"
	"github.com/siv151992-lang/network-connector/internal/coord"
	"github.com/siv151992-lang/network-connector/internal/store"
	"github.com/siv151992-lang/network-connector/pkg/protocol"
)

const (
	streamPingInterval = 30 * time.Second
	streamWriteTimeout = 10 * time.Second
	streamReadLimit    = 64 << 10
)

// notify pushes fresh maps to every connected device in a network.
func (s *Server) notify(networkID uuid.UUID) {
	if s.hub != nil {
		s.hub.Notify(networkID)
	}
}

// kick disconnects a device's stream (revoked => it is told to shut down).
func (s *Server) kick(deviceID uuid.UUID, revoked bool) {
	if s.hub != nil {
		s.hub.Kick(deviceID, revoked)
	}
}

// cleanEndpoints validates and de-duplicates endpoints reported by a device.
func cleanEndpoints(in []netip.AddrPort) ([]netip.AddrPort, error) {
	if len(in) > maxEndpoints {
		return nil, httpx.Validation(map[string]string{"endpoints": "at most 16 endpoints"})
	}
	out := make([]netip.AddrPort, 0, len(in))
	seen := map[netip.AddrPort]bool{}
	for _, ep := range in {
		a := ep.Addr().Unmap()
		if !ep.IsValid() || ep.Port() == 0 || a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() || a.IsLinkLocalUnicast() {
			return nil, httpx.Validation(map[string]string{"endpoints": "invalid endpoint " + ep.String()})
		}
		ep = netip.AddrPortFrom(a, ep.Port())
		if !seen[ep] {
			seen[ep] = true
			out = append(out, ep)
		}
	}
	return out, nil
}

func (s *Server) storeEndpoints(ctx context.Context, d *store.Device, u protocol.EndpointsUpdate) error {
	clean, err := cleanEndpoints(u.Endpoints)
	if err != nil {
		return err
	}
	var relay *int
	if u.HomeRelay > 0 {
		relay = &u.HomeRelay
	}
	if err := s.store.UpdateDeviceEndpoints(ctx, d.ID, clean, relay); err != nil {
		return err
	}
	s.notify(d.NetworkID)
	return nil
}

// handleStream is the device control stream (WebSocket). The server sends
// the network map on connect and on every change, relays call-me-maybe
// messages, and pings every 30 s. Holding the stream is what makes a device
// "online".
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request, d *store.Device) error {
	if d.Status != store.DeviceStatusApproved {
		return &httpx.Error{Status: http.StatusForbidden, Code: "device_not_approved",
			Message: "device status is " + d.Status + "; an admin must approve it"}
	}
	// The server's ReadTimeout applies to the request; a stream lives longer.
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})

	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionContextTakeover})
	if err != nil {
		return nil // Accept already wrote the HTTP error
	}
	ws.SetReadLimit(streamReadLimit)
	defer ws.CloseNow()

	ctx, cancel := context.WithCancel(context.Background()) // r.Context() ends with the handler's hijack
	defer cancel()

	conn := s.hub.Attach(d)
	defer func() {
		s.hub.Detach(conn)
		bg, c := context.WithTimeout(context.Background(), 5*time.Second)
		_ = s.store.TouchDevice(bg, d.ID)
		c()
		s.notify(d.NetworkID) // peers see us go offline
	}()
	_ = s.store.TouchDevice(ctx, d.ID)
	s.notify(d.NetworkID) // peers see us come online
	go s.hub.RunMaps(ctx, conn)
	s.log.Info("device stream connected", "device", d.ID, "name", d.Name)

	// Reader: endpoint reports and call-me-maybe requests.
	go func() {
		defer cancel()
		cmmLimit := rate.NewLimiter(10, 20)
		for {
			_, data, err := ws.Read(ctx)
			if err != nil {
				return
			}
			var m protocol.StreamMessage
			if err := json.Unmarshal(data, &m); err != nil {
				s.log.Debug("stream: bad message", "device", d.ID, "error", err)
				return
			}
			switch m.Type {
			case protocol.StreamEndpoints:
				if m.Endpoints == nil {
					return
				}
				if err := s.storeEndpoints(ctx, d, *m.Endpoints); err != nil {
					s.log.Debug("stream: endpoints rejected", "device", d.ID, "error", err)
				}
			case protocol.StreamCallMeMaybe:
				if m.CallMeMaybe == nil || !cmmLimit.Allow() {
					continue
				}
				eps, err := cleanEndpoints(m.CallMeMaybe.Endpoints)
				if err != nil {
					continue
				}
				err = s.hub.ForwardCallMeMaybe(ctx, conn, protocol.CallMeMaybe{To: m.CallMeMaybe.To, Endpoints: eps, Quiesce: m.CallMeMaybe.Quiesce})
				if err != nil && !errors.Is(err, coord.ErrPeerUnavailable) {
					s.log.Warn("stream: forward call-me-maybe", "error", err)
				}
			default:
				// Unknown types are ignored for forward compatibility.
			}
		}
	}()

	ping := time.NewTicker(streamPingInterval)
	defer ping.Stop()
	write := func(m protocol.StreamMessage) error {
		b, err := json.Marshal(m)
		if err != nil {
			return err
		}
		wctx, c := context.WithTimeout(ctx, streamWriteTimeout)
		defer c()
		return ws.Write(wctx, websocket.MessageText, b)
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-conn.Done():
			if conn.Revoked() {
				_ = write(protocol.StreamMessage{Type: protocol.StreamRevoked})
				ws.Close(websocket.StatusPolicyViolation, "revoked")
			} else {
				ws.Close(websocket.StatusGoingAway, "reconnect")
			}
			return nil
		case m := <-conn.Out:
			if err := write(m); err != nil {
				return nil
			}
		case <-ping.C:
			pctx, c := context.WithTimeout(ctx, streamWriteTimeout)
			err := ws.Ping(pctx)
			c()
			if err != nil {
				return nil // dead connection: offline
			}
			_ = s.store.TouchDevice(ctx, d.ID)
		}
	}
}
