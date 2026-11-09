package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// One-time token purposes.
const (
	TokenVerifyEmail   = "verify_email"
	TokenResetPassword = "reset_password"
)

// CreateUserToken stores a one-time token hash. Older unused tokens of the
// same purpose for the user are deleted, so only the latest link works.
func (s *Store) CreateUserToken(ctx context.Context, userID uuid.UUID, purpose string, hash []byte, ttl time.Duration) error {
	return s.WithTx(ctx, func(tx *Store) error {
		if _, err := tx.q.Exec(ctx,
			`DELETE FROM user_tokens WHERE user_id = $1 AND purpose = $2 AND used_at IS NULL`, userID, purpose); err != nil {
			return wrap("delete old tokens", err)
		}
		_, err := tx.q.Exec(ctx, `
			INSERT INTO user_tokens (token_hash, user_id, purpose, expires_at)
			VALUES ($1, $2, $3, now() + make_interval(secs => $4))`, hash, userID, purpose, ttl.Seconds())
		return wrap("create user token", err)
	})
}

// ConsumeUserToken marks a valid (unused, unexpired, matching purpose) token
// as used and returns its user. The single UPDATE makes consumption atomic:
// two concurrent requests cannot both succeed.
func (s *Store) ConsumeUserToken(ctx context.Context, hash []byte, purpose string) (uuid.UUID, error) {
	var userID uuid.UUID
	err := s.q.QueryRow(ctx, `
		UPDATE user_tokens SET used_at = now()
		WHERE token_hash = $1 AND purpose = $2 AND used_at IS NULL AND expires_at > now()
		RETURNING user_id`, hash, purpose).Scan(&userID)
	return userID, wrap("consume user token", err)
}

// DeleteStaleUserTokens purges tokens that expired or were used before cutoff.
func (s *Store) DeleteStaleUserTokens(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := s.q.Exec(ctx,
		`DELETE FROM user_tokens WHERE expires_at < $1 OR (used_at IS NOT NULL AND used_at < $1)`, cutoff)
	if err != nil {
		return 0, wrap("delete stale tokens", err)
	}
	return tag.RowsAffected(), nil
}
