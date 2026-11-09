package store

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
)

// Device statuses.
const (
	DeviceStatusPending  = "pending"
	DeviceStatusApproved = "approved"
	DeviceStatusRejected = "rejected"
	DeviceStatusRevoked  = "revoked"
)

// deviceTransitions lists the allowed status changes. Revocation is terminal:
// a revoked device must re-register with a new node key.
var deviceTransitions = map[string][]string{
	DeviceStatusPending:  {DeviceStatusApproved, DeviceStatusRejected, DeviceStatusRevoked},
	DeviceStatusRejected: {DeviceStatusApproved, DeviceStatusRevoked},
	DeviceStatusApproved: {DeviceStatusRevoked},
	DeviceStatusRevoked:  {},
}

// ValidDeviceTransition reports whether a device may move from one status to another.
func ValidDeviceTransition(from, to string) bool {
	for _, s := range deviceTransitions[from] {
		if s == to {
			return true
		}
	}
	return false
}

// Device is a node in a network.
type Device struct {
	ID               uuid.UUID        `json:"id"`
	NetworkID        uuid.UUID        `json:"network_id"`
	UserID           uuid.UUID        `json:"user_id"`
	AuthKeyID        *uuid.UUID       `json:"auth_key_id,omitempty"`
	Name             string           `json:"name"`
	Hostname         string           `json:"hostname"`
	OS               string           `json:"os"`
	OSVersion        string           `json:"os_version"`
	ClientVersion    string           `json:"client_version"`
	NodeKey          []byte           `json:"node_key"`  // WireGuard public key (base64 in JSON)
	DiscoKey         []byte           `json:"disco_key"` // disco public key
	CredentialHash   []byte           `json:"-"`
	IPv4             netip.Addr       `json:"ipv4"`
	IPv6             netip.Addr       `json:"ipv6"`
	Status           string           `json:"status"`
	Ephemeral        bool             `json:"ephemeral"`
	Tags             []string         `json:"tags"`
	Endpoints        []netip.AddrPort `json:"endpoints"`
	HomeRelayRegion  *int             `json:"home_relay_region,omitempty"`
	AdvertisedRoutes []netip.Prefix   `json:"advertised_routes"`
	ApprovedRoutes   []netip.Prefix   `json:"approved_routes"`
	IsExitNode       bool             `json:"is_exit_node"`
	KeyExpiresAt     *time.Time       `json:"key_expires_at,omitempty"`
	LastSeenAt       *time.Time       `json:"last_seen_at,omitempty"`
	ApprovedAt       *time.Time       `json:"approved_at,omitempty"`
	ApprovedBy       *uuid.UUID       `json:"approved_by,omitempty"`
	RevokedAt        *time.Time       `json:"revoked_at,omitempty"`
	CreatedAt        time.Time        `json:"created_at"`
	UpdatedAt        time.Time        `json:"updated_at"`

	// Online is live presence, filled in by the API layer (not stored).
	Online bool `json:"online"`
}

// NewDevice holds the fields needed to register a device. Addresses are
// chosen by the IPAM layer (Phase 4) before calling CreateDevice.
type NewDevice struct {
	NetworkID      uuid.UUID
	UserID         uuid.UUID
	AuthKeyID      *uuid.UUID
	Name           string
	Hostname       string
	OS             string
	OSVersion      string
	ClientVersion  string
	NodeKey        []byte
	DiscoKey       []byte
	CredentialHash []byte
	IPv4           netip.Addr
	IPv6           netip.Addr
	Status         string
	Ephemeral      bool
	Tags           []string
	KeyExpiresAt   *time.Time
}

const deviceColumns = `id, network_id, user_id, auth_key_id, name, hostname, os, os_version, client_version,
	node_key, disco_key, credential_hash, ipv4, ipv6, status, ephemeral, tags, endpoints, home_relay_region,
	advertised_routes, approved_routes, is_exit_node, key_expires_at, last_seen_at, approved_at, approved_by,
	revoked_at, created_at, updated_at`

func scanDevice(row interface{ Scan(...any) error }) (*Device, error) {
	var d Device
	var v4, v6 netip.Prefix
	if err := row.Scan(&d.ID, &d.NetworkID, &d.UserID, &d.AuthKeyID, &d.Name, &d.Hostname, &d.OS, &d.OSVersion,
		&d.ClientVersion, &d.NodeKey, &d.DiscoKey, &d.CredentialHash, &v4, &v6, &d.Status, &d.Ephemeral, &d.Tags,
		&d.Endpoints, &d.HomeRelayRegion, &d.AdvertisedRoutes, &d.ApprovedRoutes, &d.IsExitNode, &d.KeyExpiresAt,
		&d.LastSeenAt, &d.ApprovedAt, &d.ApprovedBy, &d.RevokedAt, &d.CreatedAt, &d.UpdatedAt); err != nil {
		return nil, err
	}
	d.IPv4, d.IPv6 = v4.Addr(), v6.Addr()
	if d.Tags == nil {
		d.Tags = []string{}
	}
	if d.Endpoints == nil {
		d.Endpoints = []netip.AddrPort{}
	}
	return &d, nil
}

func hostPrefix(a netip.Addr) netip.Prefix { return netip.PrefixFrom(a, a.BitLen()) }

// CreateDevice inserts a device. A *ConflictError is returned if the node key,
// name or an address is already in use; the IPAM layer retries on address conflicts.
func (s *Store) CreateDevice(ctx context.Context, nd NewDevice) (*Device, error) {
	if len(nd.NodeKey) != 32 || len(nd.DiscoKey) != 32 {
		return nil, &InvalidError{Reason: "node and disco keys must be 32 bytes"}
	}
	if !nd.IPv4.Is4() || !nd.IPv6.Is6() || nd.IPv6.Is4In6() {
		return nil, &InvalidError{Reason: "device needs one IPv4 and one IPv6 address"}
	}
	status := nd.Status
	if status == "" {
		status = DeviceStatusPending
	}
	tags := nd.Tags
	if tags == nil {
		tags = []string{}
	}
	var approvedAt any
	if status == DeviceStatusApproved {
		approvedAt = time.Now()
	}
	d, err := scanDevice(s.q.QueryRow(ctx, `
		INSERT INTO devices (network_id, user_id, auth_key_id, name, hostname, os, os_version, client_version,
		                     node_key, disco_key, credential_hash, ipv4, ipv6, status, ephemeral, tags,
		                     key_expires_at, approved_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
		RETURNING `+deviceColumns,
		nd.NetworkID, nd.UserID, nd.AuthKeyID, nd.Name, truncate(nd.Hostname, 255), truncate(nd.OS, 64),
		truncate(nd.OSVersion, 64), truncate(nd.ClientVersion, 64), nd.NodeKey, nd.DiscoKey, nd.CredentialHash,
		hostPrefix(nd.IPv4), hostPrefix(nd.IPv6), status, nd.Ephemeral, tags, nd.KeyExpiresAt, approvedAt))
	return d, wrap("create device", err)
}

// GetDevice fetches a device scoped to its network (prevents cross-network access by ID).
func (s *Store) GetDevice(ctx context.Context, networkID, id uuid.UUID) (*Device, error) {
	d, err := scanDevice(s.q.QueryRow(ctx,
		`SELECT `+deviceColumns+` FROM devices WHERE network_id = $1 AND id = $2`, networkID, id))
	return d, wrap("get device", err)
}

// GetDeviceByNodeKey fetches a device by WireGuard public key.
func (s *Store) GetDeviceByNodeKey(ctx context.Context, nodeKey []byte) (*Device, error) {
	d, err := scanDevice(s.q.QueryRow(ctx, `SELECT `+deviceColumns+` FROM devices WHERE node_key = $1`, nodeKey))
	return d, wrap("get device by node key", err)
}

// GetDeviceByCredentialHash authenticates a device bearer credential.
func (s *Store) GetDeviceByCredentialHash(ctx context.Context, hash []byte) (*Device, error) {
	d, err := scanDevice(s.q.QueryRow(ctx,
		`SELECT `+deviceColumns+` FROM devices WHERE credential_hash = $1`, hash))
	return d, wrap("get device by credential", err)
}

// DeviceFilter narrows ListDevices.
type DeviceFilter struct {
	UserID *uuid.UUID // only this user's devices
	Status string     // only this status
}

// ListDevices lists a network's devices ordered by name.
func (s *Store) ListDevices(ctx context.Context, networkID uuid.UUID, f DeviceFilter) ([]*Device, error) {
	rows, err := s.q.Query(ctx, `SELECT `+deviceColumns+` FROM devices
		WHERE network_id = $1
		  AND ($2::uuid IS NULL OR user_id = $2)
		  AND ($3 = '' OR status = $3)
		ORDER BY name`, networkID, f.UserID, f.Status)
	if err != nil {
		return nil, wrap("list devices", err)
	}
	defer rows.Close()
	out := []*Device{}
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, wrap("scan device", err)
		}
		out = append(out, d)
	}
	return out, wrap("list devices", rows.Err())
}

// UsedAddresses returns every IPv4 and IPv6 address allocated in a network.
// The IPAM allocator (Phase 4) uses this to find a free address.
func (s *Store) UsedAddresses(ctx context.Context, networkID uuid.UUID) ([]netip.Addr, error) {
	rows, err := s.q.Query(ctx, `SELECT ipv4 FROM devices WHERE network_id = $1
		UNION ALL SELECT ipv6 FROM devices WHERE network_id = $1`, networkID)
	if err != nil {
		return nil, wrap("used addresses", err)
	}
	defer rows.Close()
	var out []netip.Addr
	for rows.Next() {
		var p netip.Prefix
		if err := rows.Scan(&p); err != nil {
			return nil, wrap("scan address", err)
		}
		out = append(out, p.Addr())
	}
	return out, wrap("used addresses", rows.Err())
}

// SetDeviceStatus moves a device to a new status, enforcing allowed transitions
// under a row lock. actor is recorded as approver when approving. Revocation
// also clears the device credential so it can no longer reach the control plane.
func (s *Store) SetDeviceStatus(ctx context.Context, networkID, id uuid.UUID, to string, actor *uuid.UUID) (*Device, error) {
	var out *Device
	err := s.WithTx(ctx, func(tx *Store) error {
		var cur string
		err := tx.q.QueryRow(ctx,
			`SELECT status FROM devices WHERE network_id = $1 AND id = $2 FOR UPDATE`, networkID, id).Scan(&cur)
		if err != nil {
			return wrap("lock device", err)
		}
		if !ValidDeviceTransition(cur, to) {
			return &InvalidError{Reason: fmt.Sprintf("cannot change device status from %s to %s", cur, to)}
		}
		d, err := scanDevice(tx.q.QueryRow(ctx, `
			UPDATE devices SET
			  status          = $3,
			  approved_at     = CASE WHEN $3 = 'approved' THEN now() ELSE approved_at END,
			  approved_by     = CASE WHEN $3 = 'approved' THEN $4::uuid ELSE approved_by END,
			  revoked_at      = CASE WHEN $3 = 'revoked'  THEN now() ELSE revoked_at END,
			  credential_hash = CASE WHEN $3 = 'revoked'  THEN NULL  ELSE credential_hash END,
			  updated_at      = now()
			WHERE network_id = $1 AND id = $2
			RETURNING `+deviceColumns, networkID, id, to, actor))
		if err != nil {
			return wrap("set device status", err)
		}
		out = d
		return nil
	})
	return out, err
}

// RenameDevice changes the DNS name of a device.
func (s *Store) RenameDevice(ctx context.Context, networkID, id uuid.UUID, name string) (*Device, error) {
	d, err := scanDevice(s.q.QueryRow(ctx, `
		UPDATE devices SET name = $3, updated_at = now() WHERE network_id = $1 AND id = $2
		RETURNING `+deviceColumns, networkID, id, name))
	return d, wrap("rename device", err)
}

// SetDeviceTags replaces a device's ACL tags.
func (s *Store) SetDeviceTags(ctx context.Context, networkID, id uuid.UUID, tags []string) (*Device, error) {
	if tags == nil {
		tags = []string{}
	}
	d, err := scanDevice(s.q.QueryRow(ctx, `
		UPDATE devices SET tags = $3, updated_at = now() WHERE network_id = $1 AND id = $2
		RETURNING `+deviceColumns, networkID, id, tags))
	return d, wrap("set device tags", err)
}

// UpdateDeviceEndpoints stores the device's latest reachable candidates and home relay.
func (s *Store) UpdateDeviceEndpoints(ctx context.Context, id uuid.UUID, eps []netip.AddrPort, homeRelay *int) error {
	if eps == nil {
		eps = []netip.AddrPort{}
	}
	return s.execOne(ctx, "update endpoints", `
		UPDATE devices SET endpoints = $2, home_relay_region = $3, last_seen_at = now(), updated_at = now()
		WHERE id = $1`, id, eps, homeRelay)
}

// RotateNodeKey replaces a device's WireGuard and disco public keys.
func (s *Store) RotateNodeKey(ctx context.Context, id uuid.UUID, nodeKey, discoKey []byte, keyExpiresAt *time.Time) error {
	if len(nodeKey) != 32 || len(discoKey) != 32 {
		return &InvalidError{Reason: "node and disco keys must be 32 bytes"}
	}
	return s.execOne(ctx, "rotate node key", `
		UPDATE devices SET node_key = $2, disco_key = $3, key_expires_at = $4, updated_at = now()
		WHERE id = $1 AND status <> 'revoked'`, id, nodeKey, discoKey, keyExpiresAt)
}

// TouchDevice records that the device was seen now.
func (s *Store) TouchDevice(ctx context.Context, id uuid.UUID) error {
	return s.execOne(ctx, "touch device", `UPDATE devices SET last_seen_at = now() WHERE id = $1`, id)
}

// DeleteDevice removes a device, releasing its addresses.
func (s *Store) DeleteDevice(ctx context.Context, networkID, id uuid.UUID) error {
	return s.execOne(ctx, "delete device", `DELETE FROM devices WHERE network_id = $1 AND id = $2`, networkID, id)
}

// LockNetwork reads a network with a row lock, serializing address and name
// allocation for that network. Must be called inside WithTx.
func (s *Store) LockNetwork(ctx context.Context, id uuid.UUID) (*Network, error) {
	n, err := scanNetwork(s.q.QueryRow(ctx, `SELECT `+networkColumns+` FROM networks WHERE id = $1 FOR UPDATE`, id))
	return n, wrap("lock network", err)
}

// DeviceNames returns all device names in a network.
func (s *Store) DeviceNames(ctx context.Context, networkID uuid.UUID) (map[string]bool, error) {
	rows, err := s.q.Query(ctx, `SELECT name FROM devices WHERE network_id = $1`, networkID)
	if err != nil {
		return nil, wrap("device names", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, wrap("scan device name", err)
		}
		out[n] = true
	}
	return out, wrap("device names", rows.Err())
}

// DeleteUserDevices removes all of a user's devices in a network (used when
// the user leaves or is removed). Returns the number deleted.
func (s *Store) DeleteUserDevices(ctx context.Context, networkID, userID uuid.UUID) (int64, error) {
	tag, err := s.q.Exec(ctx, `DELETE FROM devices WHERE network_id = $1 AND user_id = $2`, networkID, userID)
	if err != nil {
		return 0, wrap("delete user devices", err)
	}
	return tag.RowsAffected(), nil
}

// ClearDeviceCredential logs a device out of the control plane.
func (s *Store) ClearDeviceCredential(ctx context.Context, id uuid.UUID) error {
	return s.execOne(ctx, "clear device credential",
		`UPDATE devices SET credential_hash = NULL, updated_at = now() WHERE id = $1`, id)
}
