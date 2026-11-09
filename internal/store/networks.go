package store

import (
	"context"
	"net/netip"
	"time"

	"github.com/google/uuid"
)

// Network roles, from most to least privileged.
const (
	RoleOwner   = "owner"
	RoleAdmin   = "admin"
	RoleMember  = "member"
	RoleAuditor = "auditor"
)

// IsNetworkAdmin reports whether role may manage devices, members and policy.
func IsNetworkAdmin(role string) bool { return role == RoleOwner || role == RoleAdmin }

// ValidNetworkRole reports whether role is a known network role.
func ValidNetworkRole(role string) bool {
	switch role {
	case RoleOwner, RoleAdmin, RoleMember, RoleAuditor:
		return true
	}
	return false
}

// Network is a private mesh ("tailnet"): an address space plus policy.
type Network struct {
	ID                     uuid.UUID    `json:"id"`
	Name                   string       `json:"name"`
	Slug                   string       `json:"slug"`
	IPv4CIDR               netip.Prefix `json:"ipv4_cidr"`
	IPv6CIDR               netip.Prefix `json:"ipv6_cidr"`
	DeviceApprovalRequired bool         `json:"device_approval_required"`
	KeyExpiryDays          int          `json:"key_expiry_days"`
	CreatedAt              time.Time    `json:"created_at"`
	UpdatedAt              time.Time    `json:"updated_at"`
}

// NewNetwork holds the fields needed to create a network.
type NewNetwork struct {
	Name                   string
	Slug                   string
	IPv4CIDR               netip.Prefix
	IPv6CIDR               netip.Prefix
	DeviceApprovalRequired bool
	KeyExpiryDays          int
	OwnerID                uuid.UUID
}

// Member is a user's membership in a network.
type Member struct {
	NetworkID   uuid.UUID `json:"network_id"`
	UserID      uuid.UUID `json:"user_id"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	Role        string    `json:"role"`
	CreatedAt   time.Time `json:"created_at"`
}

const networkColumns = `id, name, slug, ipv4_cidr, ipv6_cidr, device_approval_required, key_expiry_days, created_at, updated_at`

func scanNetwork(row interface{ Scan(...any) error }) (*Network, error) {
	var n Network
	if err := row.Scan(&n.ID, &n.Name, &n.Slug, &n.IPv4CIDR, &n.IPv6CIDR,
		&n.DeviceApprovalRequired, &n.KeyExpiryDays, &n.CreatedAt, &n.UpdatedAt); err != nil {
		return nil, err
	}
	return &n, nil
}

// CreateNetwork creates a network and makes OwnerID its owner, atomically.
func (s *Store) CreateNetwork(ctx context.Context, nn NewNetwork) (*Network, error) {
	var out *Network
	err := s.WithTx(ctx, func(tx *Store) error {
		n, err := scanNetwork(tx.q.QueryRow(ctx, `
			INSERT INTO networks (name, slug, ipv4_cidr, ipv6_cidr, device_approval_required, key_expiry_days)
			VALUES ($1, $2, $3, $4, $5, $6)
			RETURNING `+networkColumns,
			nn.Name, nn.Slug, nn.IPv4CIDR.Masked(), nn.IPv6CIDR.Masked(), nn.DeviceApprovalRequired, nn.KeyExpiryDays))
		if err != nil {
			return wrap("create network", err)
		}
		if err := tx.AddMember(ctx, n.ID, nn.OwnerID, RoleOwner); err != nil {
			return err
		}
		out = n
		return nil
	})
	return out, err
}

// GetNetwork fetches a network by ID.
func (s *Store) GetNetwork(ctx context.Context, id uuid.UUID) (*Network, error) {
	n, err := scanNetwork(s.q.QueryRow(ctx, `SELECT `+networkColumns+` FROM networks WHERE id = $1`, id))
	return n, wrap("get network", err)
}

// GetNetworkBySlug fetches a network by slug.
func (s *Store) GetNetworkBySlug(ctx context.Context, slug string) (*Network, error) {
	n, err := scanNetwork(s.q.QueryRow(ctx, `SELECT `+networkColumns+` FROM networks WHERE slug = $1`, slug))
	return n, wrap("get network by slug", err)
}

// NetworkWithRole is a network plus the requesting user's role in it.
type NetworkWithRole struct {
	Network
	Role string `json:"role"`
}

// ListNetworksForUser returns the networks userID belongs to.
func (s *Store) ListNetworksForUser(ctx context.Context, userID uuid.UUID) ([]*NetworkWithRole, error) {
	rows, err := s.q.Query(ctx, `
		SELECT n.id, n.name, n.slug, n.ipv4_cidr, n.ipv6_cidr, n.device_approval_required, n.key_expiry_days,
		       n.created_at, n.updated_at, m.role
		FROM networks n JOIN network_members m ON m.network_id = n.id
		WHERE m.user_id = $1 ORDER BY n.name, n.id`, userID)
	if err != nil {
		return nil, wrap("list networks", err)
	}
	defer rows.Close()
	var out []*NetworkWithRole
	for rows.Next() {
		var n NetworkWithRole
		if err := rows.Scan(&n.ID, &n.Name, &n.Slug, &n.IPv4CIDR, &n.IPv6CIDR, &n.DeviceApprovalRequired,
			&n.KeyExpiryDays, &n.CreatedAt, &n.UpdatedAt, &n.Role); err != nil {
			return nil, wrap("scan network", err)
		}
		out = append(out, &n)
	}
	return out, wrap("list networks", rows.Err())
}

// UpdateNetworkSettings changes mutable network settings.
func (s *Store) UpdateNetworkSettings(ctx context.Context, id uuid.UUID, name string, approvalRequired bool, keyExpiryDays int) (*Network, error) {
	n, err := scanNetwork(s.q.QueryRow(ctx, `
		UPDATE networks SET name = $2, device_approval_required = $3, key_expiry_days = $4, updated_at = now()
		WHERE id = $1 RETURNING `+networkColumns, id, name, approvalRequired, keyExpiryDays))
	return n, wrap("update network", err)
}

// DeleteNetwork deletes a network and (by cascade) its devices, keys and policy.
func (s *Store) DeleteNetwork(ctx context.Context, id uuid.UUID) error {
	return s.execOne(ctx, "delete network", `DELETE FROM networks WHERE id = $1`, id)
}

// AddMember adds userID to a network with role.
func (s *Store) AddMember(ctx context.Context, networkID, userID uuid.UUID, role string) error {
	if !ValidNetworkRole(role) {
		return &InvalidError{Reason: "unknown role " + role}
	}
	_, err := s.q.Exec(ctx,
		`INSERT INTO network_members (network_id, user_id, role) VALUES ($1, $2, $3)`, networkID, userID, role)
	return wrap("add member", err)
}

// GetMemberRole returns userID's role in networkID, or ErrNotFound if not a member.
func (s *Store) GetMemberRole(ctx context.Context, networkID, userID uuid.UUID) (string, error) {
	var role string
	err := s.q.QueryRow(ctx,
		`SELECT role FROM network_members WHERE network_id = $1 AND user_id = $2`, networkID, userID).Scan(&role)
	return role, wrap("get member role", err)
}

// SetMemberRole changes a member's role. It refuses to demote the last owner,
// which would leave the network unmanageable.
func (s *Store) SetMemberRole(ctx context.Context, networkID, userID uuid.UUID, role string) error {
	if !ValidNetworkRole(role) {
		return &InvalidError{Reason: "unknown role " + role}
	}
	return s.WithTx(ctx, func(tx *Store) error {
		cur, err := tx.lockMemberRole(ctx, networkID, userID)
		if err != nil {
			return err
		}
		if cur == RoleOwner && role != RoleOwner {
			if err := tx.ensureAnotherOwner(ctx, networkID, userID); err != nil {
				return err
			}
		}
		return tx.execOne(ctx, "set member role",
			`UPDATE network_members SET role = $3 WHERE network_id = $1 AND user_id = $2`, networkID, userID, role)
	})
}

// RemoveMember removes a user from a network, refusing to remove the last owner.
func (s *Store) RemoveMember(ctx context.Context, networkID, userID uuid.UUID) error {
	return s.WithTx(ctx, func(tx *Store) error {
		cur, err := tx.lockMemberRole(ctx, networkID, userID)
		if err != nil {
			return err
		}
		if cur == RoleOwner {
			if err := tx.ensureAnotherOwner(ctx, networkID, userID); err != nil {
				return err
			}
		}
		return tx.execOne(ctx, "remove member",
			`DELETE FROM network_members WHERE network_id = $1 AND user_id = $2`, networkID, userID)
	})
}

// lockMemberRole reads a role with a row lock. Owner rows of the network are
// locked too (FOR UPDATE over all owners) so concurrent demotions serialize.
func (s *Store) lockMemberRole(ctx context.Context, networkID, userID uuid.UUID) (string, error) {
	if _, err := s.q.Exec(ctx,
		`SELECT 1 FROM network_members WHERE network_id = $1 AND (role = 'owner' OR user_id = $2) FOR UPDATE`,
		networkID, userID); err != nil {
		return "", wrap("lock members", err)
	}
	return s.GetMemberRole(ctx, networkID, userID)
}

func (s *Store) ensureAnotherOwner(ctx context.Context, networkID, userID uuid.UUID) error {
	var others int
	if err := s.q.QueryRow(ctx,
		`SELECT count(*) FROM network_members WHERE network_id = $1 AND role = 'owner' AND user_id <> $2`,
		networkID, userID).Scan(&others); err != nil {
		return wrap("count owners", err)
	}
	if others == 0 {
		return &InvalidError{Reason: "a network must keep at least one owner"}
	}
	return nil
}

// ListMembers lists a network's members with their emails.
func (s *Store) ListMembers(ctx context.Context, networkID uuid.UUID) ([]*Member, error) {
	rows, err := s.q.Query(ctx, `
		SELECT m.network_id, m.user_id, u.email, u.display_name, m.role, m.created_at
		FROM network_members m JOIN users u ON u.id = m.user_id
		WHERE m.network_id = $1 ORDER BY u.email`, networkID)
	if err != nil {
		return nil, wrap("list members", err)
	}
	defer rows.Close()
	var out []*Member
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.NetworkID, &m.UserID, &m.Email, &m.DisplayName, &m.Role, &m.CreatedAt); err != nil {
			return nil, wrap("scan member", err)
		}
		out = append(out, &m)
	}
	return out, wrap("list members", rows.Err())
}
