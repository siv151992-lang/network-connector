package store

import (
	"context"
	"net/netip"
	"time"

	"github.com/google/uuid"
)

// Session is a dashboard login session. The raw token is only ever held by
// the browser; the database stores its SHA-256 hash.
type Session struct {
	ID         uuid.UUID   `json:"id"`
	TokenHash  []byte      `json:"-"`
	UserID     uuid.UUID   `json:"user_id"`
	MFAPassed  bool        `json:"mfa_passed"`
	IP         *netip.Addr `json:"ip,omitempty"`
	UserAgent  string      `json:"user_agent"`
	CreatedAt  time.Time   `json:"created_at"`
	LastSeenAt time.Time   `json:"last_seen_at"`
	ExpiresAt  time.Time   `json:"expires_at"`
	RevokedAt  *time.Time  `json:"revoked_at,omitempty"`
}

// Active reports whether the session is usable at time now.
func (s *Session) Active(now time.Time) bool {
	return s.RevokedAt == nil && now.Before(s.ExpiresAt)
}

// NewSession holds the fields needed to create a session.
type NewSession struct {
	TokenHash []byte
	UserID    uuid.UUID
	MFAPassed bool
	IP        *netip.Addr
	UserAgent string
	ExpiresAt time.Time
}

const sessionColumns = `id, token_hash, user_id, mfa_passed, ip, user_agent, created_at, last_seen_at, expires_at, revoked_at`

func scanSession(row interface{ Scan(...any) error }) (*Session, error) {
	var s Session
	var ip *netip.Prefix
	if err := row.Scan(&s.ID, &s.TokenHash, &s.UserID, &s.MFAPassed, &ip, &s.UserAgent,
		&s.CreatedAt, &s.LastSeenAt, &s.ExpiresAt, &s.RevokedAt); err != nil {
		return nil, err
	}
	if ip != nil {
		a := ip.Addr()
		s.IP = &a
	}
	return &s, nil
}

// CreateSession inserts a new session.
func (s *Store) CreateSession(ctx context.Context, ns NewSession) (*Session, error) {
	sess, err := scanSession(s.q.QueryRow(ctx, `
		INSERT INTO sessions (token_hash, user_id, mfa_passed, ip, user_agent, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING `+sessionColumns,
		ns.TokenHash, ns.UserID, ns.MFAPassed, addrPtrArg(ns.IP), truncate(ns.UserAgent, 512), ns.ExpiresAt))
	return sess, wrap("create session", err)
}

// GetSessionByTokenHash looks up a session by token hash. Callers must still
// check Active(); revoked/expired rows are returned so they can be audited.
func (s *Store) GetSessionByTokenHash(ctx context.Context, hash []byte) (*Session, error) {
	sess, err := scanSession(s.q.QueryRow(ctx, `SELECT `+sessionColumns+` FROM sessions WHERE token_hash = $1`, hash))
	return sess, wrap("get session", err)
}

// TouchSession updates last_seen_at and optionally extends expiry (sliding sessions).
func (s *Store) TouchSession(ctx context.Context, id uuid.UUID, newExpiry time.Time) error {
	return s.execOne(ctx, "touch session", `
		UPDATE sessions SET last_seen_at = now(), expires_at = GREATEST(expires_at, $2)
		WHERE id = $1 AND revoked_at IS NULL`, id, newExpiry)
}

// MarkSessionMFAPassed upgrades a partial session after a successful TOTP check.
func (s *Store) MarkSessionMFAPassed(ctx context.Context, id uuid.UUID) error {
	return s.execOne(ctx, "mark session mfa",
		`UPDATE sessions SET mfa_passed = true WHERE id = $1 AND revoked_at IS NULL`, id)
}

// RevokeSession revokes one session belonging to userID.
func (s *Store) RevokeSession(ctx context.Context, userID, id uuid.UUID) error {
	return s.execOne(ctx, "revoke session",
		`UPDATE sessions SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`, id, userID)
}

// RevokeUserSessions revokes all of a user's sessions except keep (may be uuid.Nil).
// Returns the number revoked.
func (s *Store) RevokeUserSessions(ctx context.Context, userID, keep uuid.UUID) (int64, error) {
	tag, err := s.q.Exec(ctx,
		`UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL`, userID, keep)
	if err != nil {
		return 0, wrap("revoke user sessions", err)
	}
	return tag.RowsAffected(), nil
}

// ListActiveSessions lists a user's unrevoked, unexpired sessions, newest first.
func (s *Store) ListActiveSessions(ctx context.Context, userID uuid.UUID) ([]*Session, error) {
	rows, err := s.q.Query(ctx, `SELECT `+sessionColumns+` FROM sessions
		WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()
		ORDER BY last_seen_at DESC`, userID)
	if err != nil {
		return nil, wrap("list sessions", err)
	}
	defer rows.Close()
	var out []*Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, wrap("scan session", err)
		}
		out = append(out, sess)
	}
	return out, wrap("list sessions", rows.Err())
}

// DeleteStaleSessions removes sessions that expired or were revoked before cutoff.
func (s *Store) DeleteStaleSessions(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := s.q.Exec(ctx,
		`DELETE FROM sessions WHERE expires_at < $1 OR (revoked_at IS NOT NULL AND revoked_at < $1)`, cutoff)
	if err != nil {
		return 0, wrap("delete stale sessions", err)
	}
	return tag.RowsAffected(), nil
}

// addrPtrArg converts an optional address to a value pgx encodes as inet (or NULL).
func addrPtrArg(a *netip.Addr) any {
	if a == nil || !a.IsValid() {
		return nil
	}
	return netip.PrefixFrom(*a, a.BitLen())
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Avoid cutting a multi-byte rune in half.
	for n > 0 && n < len(s) && (s[n]&0xC0) == 0x80 {
		n--
	}
	return s[:n]
}
