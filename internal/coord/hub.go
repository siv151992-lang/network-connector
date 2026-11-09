package coord

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/siv151992-lang/network-connector/internal/store"
	"github.com/siv151992-lang/network-connector/pkg/protocol"
)

// Hub tracks devices connected to the control stream, pushes them fresh
// network maps whenever something in their network changes, and forwards
// call-me-maybe messages between peers.
//
// Single-process design. With several control-server replicas, Notify and
// Forward would be published over Redis (WIREMESH_REDIS_URL, Phase 11);
// the Conn/Hub API is the seam for that.
type Hub struct {
	B   *Builder
	Log *slog.Logger

	mu    sync.Mutex
	conns map[uuid.UUID]*Conn               // by device
	nets  map[uuid.UUID]map[uuid.UUID]*Conn // network -> device -> conn
}

// NewHub creates a hub and wires its presence into the builder.
func NewHub(b *Builder, log *slog.Logger) *Hub {
	h := &Hub{B: b, Log: log, conns: map[uuid.UUID]*Conn{}, nets: map[uuid.UUID]map[uuid.UUID]*Conn{}}
	b.Online = h.Online
	return h
}

// Conn is one device's stream.
type Conn struct {
	DeviceID  uuid.UUID
	NetworkID uuid.UUID

	// Out carries messages to the stream writer. If it fills up the client is
	// too slow: the connection is closed and the device reconnects, receiving
	// a full map (maps are complete state, so nothing is lost).
	Out chan protocol.StreamMessage

	mu       sync.Mutex
	nodeKey  protocol.Key
	kick     chan struct{}
	done     chan struct{}
	once     sync.Once
	revoked  bool
	lastSent string
}

// Done is closed when the hub wants the connection gone.
func (c *Conn) Done() <-chan struct{} { return c.done }

// Revoked reports whether the device was revoked/deleted (the writer then
// sends a final "revoked" message before closing).
func (c *Conn) Revoked() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.revoked }

func (c *Conn) close(revoked bool) {
	c.mu.Lock()
	c.revoked = c.revoked || revoked
	c.mu.Unlock()
	c.once.Do(func() { close(c.done) })
}

func (c *Conn) enqueue(m protocol.StreamMessage) bool {
	select {
	case c.Out <- m:
		return true
	default:
		c.close(false)
		return false
	}
}

func (c *Conn) poke() {
	select {
	case c.kick <- struct{}{}:
	default:
	}
}

// Attach registers a device's stream, replacing (closing) any older stream
// from the same device.
func (h *Hub) Attach(d *store.Device) *Conn {
	c := &Conn{DeviceID: d.ID, NetworkID: d.NetworkID, Out: make(chan protocol.StreamMessage, 32),
		kick: make(chan struct{}, 1), done: make(chan struct{})}
	copy(c.nodeKey[:], d.NodeKey)
	h.mu.Lock()
	if old := h.conns[d.ID]; old != nil {
		old.close(false)
	}
	h.conns[d.ID] = c
	if h.nets[d.NetworkID] == nil {
		h.nets[d.NetworkID] = map[uuid.UUID]*Conn{}
	}
	h.nets[d.NetworkID][d.ID] = c
	h.mu.Unlock()
	c.poke() // first map
	return c
}

// Detach unregisters c (if it is still the current stream for its device).
func (h *Hub) Detach(c *Conn) {
	c.close(false)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.conns[c.DeviceID] == c {
		delete(h.conns, c.DeviceID)
		delete(h.nets[c.NetworkID], c.DeviceID)
		if len(h.nets[c.NetworkID]) == 0 {
			delete(h.nets, c.NetworkID)
		}
	}
}

// Online reports whether a device currently holds a stream.
func (h *Hub) Online(deviceID uuid.UUID) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.conns[deviceID]
	return ok
}

// Notify tells every connected device in a network to rebuild its map.
func (h *Hub) Notify(networkID uuid.UUID) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, c := range h.nets[networkID] {
		c.poke()
	}
}

// Kick disconnects a device (revoked=true sends a final "revoked" message).
func (h *Hub) Kick(deviceID uuid.UUID, revoked bool) {
	h.mu.Lock()
	c := h.conns[deviceID]
	h.mu.Unlock()
	if c != nil {
		c.close(revoked)
	}
}

// CloseAll disconnects every stream (server shutdown).
func (h *Hub) CloseAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, c := range h.conns {
		c.close(false)
	}
}

// RunMaps rebuilds and enqueues the device's map each time it is poked,
// until the connection ends. Pokes arriving close together are coalesced.
func (h *Hub) RunMaps(ctx context.Context, c *Conn) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		case <-c.kick:
		}
		// Coalesce bursts (e.g. many devices reconnecting after a restart).
		select {
		case <-time.After(50 * time.Millisecond):
		case <-ctx.Done():
			return
		}
		select {
		case <-c.kick:
		default:
		}

		d, err := h.B.Store.GetDevice(ctx, c.NetworkID, c.DeviceID)
		if errors.Is(err, store.ErrNotFound) || (err == nil && d.Status == store.DeviceStatusRevoked) {
			c.close(true)
			return
		}
		if err != nil {
			if ctx.Err() == nil {
				h.Log.Warn("stream: load device", "device", c.DeviceID, "error", err)
			}
			continue
		}
		c.mu.Lock()
		copy(c.nodeKey[:], d.NodeKey)
		c.mu.Unlock()
		nm, err := h.B.Build(ctx, d)
		if errors.Is(err, ErrNotApproved) {
			c.close(false)
			return
		}
		if err != nil {
			if ctx.Err() == nil {
				h.Log.Warn("stream: build map", "device", c.DeviceID, "error", err)
			}
			continue
		}
		if nm.Version == c.lastSent {
			continue
		}
		if !c.enqueue(protocol.StreamMessage{Type: protocol.StreamMap, Map: nm}) {
			return
		}
		c.lastSent = nm.Version
	}
}

// ErrPeerUnavailable means the call-me-maybe target isn't connected or isn't
// a permitted peer.
var ErrPeerUnavailable = errors.New("peer not connected or not reachable under the policy")

// ForwardCallMeMaybe relays a call-me-maybe from one device to a peer in the
// same network, but only if the policy lets them see each other (otherwise it
// would leak endpoints to devices that shouldn't learn them).
func (h *Hub) ForwardCallMeMaybe(ctx context.Context, from *Conn, cmm protocol.CallMeMaybe) error {
	h.mu.Lock()
	var to *Conn
	for _, c := range h.nets[from.NetworkID] {
		c.mu.Lock()
		match := c.nodeKey == cmm.To && c != from
		c.mu.Unlock()
		if match {
			to = c
			break
		}
	}
	h.mu.Unlock()
	if to == nil {
		return ErrPeerUnavailable
	}
	policy, err := h.B.Policy(ctx, from.NetworkID)
	if err != nil {
		return err
	}
	_, byID, emails, err := h.B.Members(ctx, from.NetworkID)
	if err != nil {
		return err
	}
	src, okSrc := byID[from.DeviceID.String()]
	dst, okDst := byID[to.DeviceID.String()]
	if !okSrc || !okDst {
		return ErrPeerUnavailable
	}
	a, b := ToACL(src, emails[src.UserID]), ToACL(dst, emails[dst.UserID])
	if !policy.CanReach(a, b) && !policy.CanReach(b, a) {
		return ErrPeerUnavailable
	}
	from.mu.Lock()
	fromKey := from.nodeKey
	from.mu.Unlock()
	to.enqueue(protocol.StreamMessage{Type: protocol.StreamCallMeMaybe,
		CallMeMaybe: &protocol.CallMeMaybe{From: fromKey, Endpoints: cmm.Endpoints, Quiesce: cmm.Quiesce}})
	return nil
}
