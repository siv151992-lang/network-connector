// Package coord builds per-device network maps: the peers a device may talk
// to, their keys, addresses and endpoints, and the device's inbound packet
// filter, all compiled from the network's ACL policy.
package coord

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"

	"github.com/siv151992-lang/network-connector/internal/acl"
	"github.com/siv151992-lang/network-connector/internal/store"
	"github.com/siv151992-lang/network-connector/pkg/protocol"
)

// PollInterval is how often Phase 4 clients refresh their map.
const PollInterval = 10 * time.Second

// ErrNotApproved is returned for devices that may not join the mesh yet.
var ErrNotApproved = errors.New("device is not approved")

// Builder compiles network maps.
type Builder struct {
	Store *store.Store
	Now   func() time.Time
}

// Policy returns the compiled policy for a network (the stored one, or the
// default allow-all policy if none was saved).
func (b *Builder) Policy(ctx context.Context, networkID uuid.UUID) (*acl.Compiled, error) {
	p, err := b.Store.GetACLPolicy(ctx, networkID)
	var pol *acl.Policy
	switch {
	case errors.Is(err, store.ErrNotFound):
		pol = acl.MustDefault()
	case err != nil:
		return nil, err
	default:
		if pol, err = acl.Parse(p.Policy); err != nil {
			return nil, fmt.Errorf("stored policy for network %s is invalid: %w", networkID, err)
		}
	}
	return acl.Compile(pol)
}

// Members returns the network's approved, unexpired devices in ACL form,
// plus the store records keyed by ID.
func (b *Builder) Members(ctx context.Context, networkID uuid.UUID) ([]acl.Device, map[string]*store.Device, map[uuid.UUID]string, error) {
	devs, err := b.Store.ListDevices(ctx, networkID, store.DeviceFilter{Status: store.DeviceStatusApproved})
	if err != nil {
		return nil, nil, nil, err
	}
	members, err := b.Store.ListMembers(ctx, networkID)
	if err != nil {
		return nil, nil, nil, err
	}
	emails := make(map[uuid.UUID]string, len(members))
	for _, m := range members {
		emails[m.UserID] = m.Email
	}
	now := b.Now()
	var out []acl.Device
	byID := map[string]*store.Device{}
	for _, d := range devs {
		if d.KeyExpiresAt != nil && !now.Before(*d.KeyExpiresAt) {
			continue // expired keys drop out of everyone's map until rotated
		}
		out = append(out, ToACL(d, emails[d.UserID]))
		byID[d.ID.String()] = d
	}
	return out, byID, emails, nil
}

// ToACL converts a store device to its policy identity.
func ToACL(d *store.Device, email string) acl.Device {
	return acl.Device{ID: d.ID.String(), User: email, Tags: d.Tags, Addrs: []netip.Addr{d.IPv4, d.IPv6}}
}

// Build compiles the network map for device self.
func (b *Builder) Build(ctx context.Context, self *store.Device) (*protocol.NetworkMap, error) {
	if self.Status != store.DeviceStatusApproved {
		return nil, ErrNotApproved
	}
	n, err := b.Store.GetNetwork(ctx, self.NetworkID)
	if err != nil {
		return nil, err
	}
	policy, err := b.Policy(ctx, n.ID)
	if err != nil {
		return nil, err
	}
	all, byID, emails, err := b.Members(ctx, n.ID)
	if err != nil {
		return nil, err
	}

	nm := &protocol.NetworkMap{
		Network:      protocol.NetworkInfo{ID: n.ID.String(), Name: n.Name, IPv4CIDR: n.IPv4CIDR, IPv6CIDR: n.IPv6CIDR},
		Self:         toNode(self, emails[self.UserID]),
		Peers:        []protocol.Node{},
		PacketFilter: []protocol.FilterRule{},
		PollInterval: protocol.Duration(PollInterval),
	}
	if self.KeyExpiresAt != nil && !b.Now().Before(*self.KeyExpiresAt) {
		// An expired device gets no peers until it rotates its key.
		nm.Self.KeyExpired = true
	} else {
		me := ToACL(self, emails[self.UserID])
		for _, p := range policy.Peers(me, all) {
			nm.Peers = append(nm.Peers, toNode(byID[p.ID], emails[byID[p.ID].UserID]))
		}
		nm.PacketFilter = policy.Filter(me, all)
		if nm.PacketFilter == nil {
			nm.PacketFilter = []protocol.FilterRule{}
		}
	}
	nm.Version, err = version(nm)
	if err != nil {
		return nil, err
	}
	return nm, nil
}

func toNode(d *store.Device, email string) protocol.Node {
	var nk, dk protocol.Key
	copy(nk[:], d.NodeKey)
	copy(dk[:], d.DiscoKey)
	addrs := []netip.Prefix{netip.PrefixFrom(d.IPv4, 32), netip.PrefixFrom(d.IPv6, 128)}
	allowed := append([]netip.Prefix{}, addrs...)
	allowed = append(allowed, d.ApprovedRoutes...)
	node := protocol.Node{
		ID: d.ID.String(), Name: d.Name, Tags: d.Tags, OS: d.OS, NodeKey: nk, DiscoKey: dk,
		Addresses: addrs, AllowedIPs: allowed, Endpoints: d.Endpoints,
		KeyExpiry: d.KeyExpiresAt, LastSeen: d.LastSeenAt,
	}
	if len(d.Tags) == 0 {
		node.User = email
	}
	if d.HomeRelayRegion != nil {
		node.HomeRelay = *d.HomeRelayRegion
	}
	return node
}

// version hashes the map's content, ignoring last-seen timestamps (which
// change on every poll) so unchanged maps keep the same ETag.
func version(nm *protocol.NetworkMap) (string, error) {
	c := *nm
	c.Version = ""
	c.Self.LastSeen = nil
	c.Peers = make([]protocol.Node, len(nm.Peers))
	for i, p := range nm.Peers {
		p.LastSeen = nil
		c.Peers[i] = p
	}
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:12]), nil
}
