package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// ErrStaleVersion is returned when an ACL update was based on an older
// version than the one stored (another admin saved in between).
var ErrStaleVersion = errors.New("policy was modified by someone else; reload and retry")

// ACLPolicy is a network's stored access policy.
type ACLPolicy struct {
	NetworkID uuid.UUID       `json:"network_id"`
	Version   int             `json:"version"`
	Policy    json.RawMessage `json:"policy"`
	UpdatedBy *uuid.UUID      `json:"updated_by,omitempty"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// GetACLPolicy returns the stored policy, or ErrNotFound if the network still
// uses the built-in default.
func (s *Store) GetACLPolicy(ctx context.Context, networkID uuid.UUID) (*ACLPolicy, error) {
	var p ACLPolicy
	err := s.q.QueryRow(ctx,
		`SELECT network_id, version, policy, updated_by, updated_at FROM acl_policies WHERE network_id = $1`, networkID).
		Scan(&p.NetworkID, &p.Version, &p.Policy, &p.UpdatedBy, &p.UpdatedAt)
	if err != nil {
		return nil, wrap("get acl policy", err)
	}
	return &p, nil
}

// PutACLPolicy stores a new policy version. expectedVersion must equal the
// current version (0 when no policy has been saved yet): optimistic
// concurrency, so concurrent editors can't silently overwrite each other.
// Every version is kept in acl_policy_history.
func (s *Store) PutACLPolicy(ctx context.Context, networkID uuid.UUID, expectedVersion int, policy []byte, by uuid.UUID) (*ACLPolicy, error) {
	var out *ACLPolicy
	err := s.WithTx(ctx, func(tx *Store) error {
		// Lock the network row so the first save (no policy row yet) also serializes.
		if _, err := tx.LockNetwork(ctx, networkID); err != nil {
			return err
		}
		cur := 0
		err := tx.q.QueryRow(ctx, `SELECT version FROM acl_policies WHERE network_id = $1`, networkID).Scan(&cur)
		if err != nil && !errors.Is(mapErr(err), ErrNotFound) {
			return wrap("read acl version", err)
		}
		if cur != expectedVersion {
			return ErrStaleVersion
		}
		var p ACLPolicy
		err = tx.q.QueryRow(ctx, `
			INSERT INTO acl_policies (network_id, version, policy, updated_by, updated_at)
			VALUES ($1, $2, $3, $4, now())
			ON CONFLICT (network_id) DO UPDATE
			  SET version = EXCLUDED.version, policy = EXCLUDED.policy,
			      updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at
			RETURNING network_id, version, policy, updated_by, updated_at`,
			networkID, cur+1, json.RawMessage(policy), by).
			Scan(&p.NetworkID, &p.Version, &p.Policy, &p.UpdatedBy, &p.UpdatedAt)
		if err != nil {
			return wrap("put acl policy", err)
		}
		if _, err := tx.q.Exec(ctx, `
			INSERT INTO acl_policy_history (network_id, version, policy, updated_by) VALUES ($1, $2, $3, $4)`,
			networkID, p.Version, json.RawMessage(policy), by); err != nil {
			return wrap("acl history", err)
		}
		out = &p
		return nil
	})
	return out, err
}
