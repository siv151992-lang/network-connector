package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// ErrAuthKeyUnusable is returned when an auth key is unknown, revoked, expired,
// or single-use and already used. Callers must not tell these cases apart in
// responses.
var ErrAuthKeyUnusable = errors.New("auth key is invalid, expired or already used")

// AuthKey is a pre-authentication key for unattended device enrollment.
type AuthKey struct {
	ID            uuid.UUID  `json:"id"`
	NetworkID     uuid.UUID  `json:"network_id"`
	CreatedBy     *uuid.UUID `json:"created_by,omitempty"`
	KeyHash       []byte     `json:"-"`
	Prefix        string     `json:"prefix"`
	Description   string     `json:"description"`
	Reusable      bool       `json:"reusable"`
	Ephemeral     bool       `json:"ephemeral"`
	Preauthorized bool       `json:"preauthorized"`
	Tags          []string   `json:"tags"`
	Uses          int        `json:"uses"`
	ExpiresAt     time.Time  `json:"expires_at"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

// Usable reports whether the key can enroll a device at time now.
func (k *AuthKey) Usable(now time.Time) bool {
	return k.RevokedAt == nil && now.Before(k.ExpiresAt) && (k.Reusable || k.Uses == 0)
}

// NewAuthKey holds the fields needed to create a key.
type NewAuthKey struct {
	NetworkID     uuid.UUID
	CreatedBy     uuid.UUID
	KeyHash       []byte
	Prefix        string
	Description   string
	Reusable      bool
	Ephemeral     bool
	Preauthorized bool
	Tags          []string
	ExpiresAt     time.Time
}

const authKeyColumns = `id, network_id, created_by, key_hash, prefix, description, reusable, ephemeral,
	preauthorized, tags, uses, expires_at, revoked_at, created_at`

func scanAuthKey(row interface{ Scan(...any) error }) (*AuthKey, error) {
	var k AuthKey
	if err := row.Scan(&k.ID, &k.NetworkID, &k.CreatedBy, &k.KeyHash, &k.Prefix, &k.Description, &k.Reusable,
		&k.Ephemeral, &k.Preauthorized, &k.Tags, &k.Uses, &k.ExpiresAt, &k.RevokedAt, &k.CreatedAt); err != nil {
		return nil, err
	}
	if k.Tags == nil {
		k.Tags = []string{}
	}
	return &k, nil
}

// CreateAuthKey stores a new key (hash only).
func (s *Store) CreateAuthKey(ctx context.Context, nk NewAuthKey) (*AuthKey, error) {
	tags := nk.Tags
	if tags == nil {
		tags = []string{}
	}
	k, err := scanAuthKey(s.q.QueryRow(ctx, `
		INSERT INTO auth_keys (network_id, created_by, key_hash, prefix, description, reusable, ephemeral,
		                       preauthorized, tags, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING `+authKeyColumns,
		nk.NetworkID, nk.CreatedBy, nk.KeyHash, nk.Prefix, truncate(nk.Description, 200), nk.Reusable,
		nk.Ephemeral, nk.Preauthorized, tags, nk.ExpiresAt))
	return k, wrap("create auth key", err)
}

// ListAuthKeys lists a network's keys, newest first.
func (s *Store) ListAuthKeys(ctx context.Context, networkID uuid.UUID) ([]*AuthKey, error) {
	rows, err := s.q.Query(ctx,
		`SELECT `+authKeyColumns+` FROM auth_keys WHERE network_id = $1 ORDER BY created_at DESC`, networkID)
	if err != nil {
		return nil, wrap("list auth keys", err)
	}
	defer rows.Close()
	out := []*AuthKey{}
	for rows.Next() {
		k, err := scanAuthKey(rows)
		if err != nil {
			return nil, wrap("scan auth key", err)
		}
		out = append(out, k)
	}
	return out, wrap("list auth keys", rows.Err())
}

// RevokeAuthKey revokes a key in a network.
func (s *Store) RevokeAuthKey(ctx context.Context, networkID, id uuid.UUID) error {
	return s.execOne(ctx, "revoke auth key", `
		UPDATE auth_keys SET revoked_at = now() WHERE network_id = $1 AND id = $2 AND revoked_at IS NULL`, networkID, id)
}

// ConsumeAuthKey validates a key under a row lock and counts one use. Call it
// inside the same transaction that creates the device, so a failed
// registration does not burn a single-use key.
func (s *Store) ConsumeAuthKey(ctx context.Context, hash []byte, now time.Time) (*AuthKey, error) {
	k, err := scanAuthKey(s.q.QueryRow(ctx,
		`SELECT `+authKeyColumns+` FROM auth_keys WHERE key_hash = $1 FOR UPDATE`, hash))
	if err != nil {
		if errors.Is(mapErr(err), ErrNotFound) {
			return nil, ErrAuthKeyUnusable
		}
		return nil, wrap("consume auth key", err)
	}
	if !k.Usable(now) {
		return nil, ErrAuthKeyUnusable
	}
	if _, err := s.q.Exec(ctx, `UPDATE auth_keys SET uses = uses + 1 WHERE id = $1`, k.ID); err != nil {
		return nil, wrap("consume auth key", err)
	}
	k.Uses++
	return k, nil
}
