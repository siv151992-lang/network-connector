package store

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
)

// System roles.
const (
	SystemRoleAdmin = "admin"
	SystemRoleUser  = "user"
)

// User is an account that can log into the dashboard and own devices.
type User struct {
	ID              uuid.UUID  `json:"id"`
	Email           string     `json:"email"`
	PasswordHash    string     `json:"-"`
	DisplayName     string     `json:"display_name"`
	SystemRole      string     `json:"system_role"`
	EmailVerifiedAt *time.Time `json:"email_verified_at,omitempty"`
	TOTPSecretEnc   []byte     `json:"-"`
	TOTPEnabled     bool       `json:"totp_enabled"`
	TOTPLastStep    int64      `json:"-"`
	FailedLogins    int        `json:"-"`
	LockedUntil     *time.Time `json:"-"`
	LastLoginAt     *time.Time `json:"last_login_at,omitempty"`
	DisabledAt      *time.Time `json:"disabled_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// NewUser holds the fields needed to create a user.
type NewUser struct {
	Email        string
	PasswordHash string
	DisplayName  string
	SystemRole   string // defaults to "user"
	Verified     bool   // mark the email as already verified (admin-created users)
}

// NormalizeEmail lower-cases and trims an address; the schema enforces lower case.
func NormalizeEmail(e string) string { return strings.ToLower(strings.TrimSpace(e)) }

const userColumns = `id, email, password_hash, display_name, system_role, email_verified_at,
	totp_secret_enc, totp_enabled, totp_last_step, failed_logins, locked_until, last_login_at, disabled_at,
	created_at, updated_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.DisplayName, &u.SystemRole, &u.EmailVerifiedAt,
		&u.TOTPSecretEnc, &u.TOTPEnabled, &u.TOTPLastStep, &u.FailedLogins, &u.LockedUntil, &u.LastLoginAt, &u.DisabledAt,
		&u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// CreateUser inserts a user. Returns a *ConflictError if the email is taken.
func (s *Store) CreateUser(ctx context.Context, nu NewUser) (*User, error) {
	role := nu.SystemRole
	if role == "" {
		role = SystemRoleUser
	}
	row := s.q.QueryRow(ctx, `
		INSERT INTO users (email, password_hash, display_name, system_role, email_verified_at)
		VALUES ($1, $2, $3, $4, CASE WHEN $5 THEN now() END)
		RETURNING `+userColumns,
		NormalizeEmail(nu.Email), nu.PasswordHash, strings.TrimSpace(nu.DisplayName), role, nu.Verified)
	u, err := scanUser(row)
	return u, wrap("create user", err)
}

// GetUser fetches a user by ID.
func (s *Store) GetUser(ctx context.Context, id uuid.UUID) (*User, error) {
	u, err := scanUser(s.q.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, id))
	return u, wrap("get user", err)
}

// GetUserByEmail fetches a user by (normalized) email.
func (s *Store) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	u, err := scanUser(s.q.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE email = $1`, NormalizeEmail(email)))
	return u, wrap("get user by email", err)
}

// ListUsers returns users ordered by creation time, plus the total count.
func (s *Store) ListUsers(ctx context.Context, limit, offset int) ([]*User, int, error) {
	limit = clampLimit(limit, 50, 500)
	if offset < 0 {
		offset = 0
	}
	var total int
	if err := s.q.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&total); err != nil {
		return nil, 0, wrap("count users", err)
	}
	rows, err := s.q.Query(ctx, `SELECT `+userColumns+` FROM users ORDER BY created_at, id LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, wrap("list users", err)
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, 0, wrap("scan user", err)
		}
		out = append(out, u)
	}
	return out, total, wrap("list users", rows.Err())
}

// CountUsers returns the number of users (used to make the first user a system admin).
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.q.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, wrap("count users", err)
}

// MarkEmailVerified sets email_verified_at if not already set.
func (s *Store) MarkEmailVerified(ctx context.Context, id uuid.UUID) error {
	return s.execOne(ctx, "mark email verified",
		`UPDATE users SET email_verified_at = COALESCE(email_verified_at, now()), updated_at = now() WHERE id = $1`, id)
}

// SetPasswordHash replaces a user's password hash.
func (s *Store) SetPasswordHash(ctx context.Context, id uuid.UUID, hash string) error {
	return s.execOne(ctx, "set password",
		`UPDATE users SET password_hash = $2, failed_logins = 0, locked_until = NULL, updated_at = now() WHERE id = $1`, id, hash)
}

// RecordLoginSuccess resets the failure counter and stamps last_login_at.
func (s *Store) RecordLoginSuccess(ctx context.Context, id uuid.UUID) error {
	return s.execOne(ctx, "record login",
		`UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = now() WHERE id = $1`, id)
}

// RecordLoginFailure increments the failure counter and, once it reaches
// threshold, locks the account for lockFor. Returns the new failure count.
func (s *Store) RecordLoginFailure(ctx context.Context, id uuid.UUID, threshold int, lockFor time.Duration) (int, error) {
	var n int
	err := s.q.QueryRow(ctx, `
		UPDATE users SET
		  failed_logins = failed_logins + 1,
		  locked_until  = CASE WHEN failed_logins + 1 >= $2 THEN now() + make_interval(secs => $3) ELSE locked_until END
		WHERE id = $1
		RETURNING failed_logins`, id, threshold, lockFor.Seconds()).Scan(&n)
	return n, wrap("record login failure", err)
}

// SetTOTP stores the encrypted TOTP secret and enabled flag. Passing a nil
// secret clears TOTP entirely (and resets the replay counter).
func (s *Store) SetTOTP(ctx context.Context, id uuid.UUID, secretEnc []byte, enabled bool) error {
	return s.execOne(ctx, "set totp", `
		UPDATE users SET totp_secret_enc = $2, totp_enabled = $3,
		       totp_last_step = CASE WHEN $2::bytea IS NULL THEN 0 ELSE totp_last_step END,
		       updated_at = now()
		WHERE id = $1`, id, secretEnc, enabled)
}

// ClaimTOTPStep atomically records step as used. It returns false if a code
// for this or a later step was already accepted (replay or race).
func (s *Store) ClaimTOTPStep(ctx context.Context, id uuid.UUID, step int64) (bool, error) {
	tag, err := s.q.Exec(ctx,
		`UPDATE users SET totp_last_step = $2 WHERE id = $1 AND totp_last_step < $2`, id, step)
	if err != nil {
		return false, wrap("claim totp step", err)
	}
	return tag.RowsAffected() == 1, nil
}

// UpdateDisplayName changes a user's display name.
func (s *Store) UpdateDisplayName(ctx context.Context, id uuid.UUID, name string) error {
	return s.execOne(ctx, "update display name",
		`UPDATE users SET display_name = $2, updated_at = now() WHERE id = $1`, id, strings.TrimSpace(name))
}

// SetUserDisabled disables or re-enables an account.
func (s *Store) SetUserDisabled(ctx context.Context, id uuid.UUID, disabled bool) error {
	return s.execOne(ctx, "set user disabled", `
		UPDATE users SET disabled_at = CASE WHEN $2 THEN COALESCE(disabled_at, now()) ELSE NULL END,
		                 updated_at = now()
		WHERE id = $1`, id, disabled)
}

// SetSystemRole changes a user's system-wide role.
func (s *Store) SetSystemRole(ctx context.Context, id uuid.UUID, role string) error {
	return s.execOne(ctx, "set system role",
		`UPDATE users SET system_role = $2, updated_at = now() WHERE id = $1`, id, role)
}

// DeleteUser removes a user; cascades to sessions, memberships and devices.
func (s *Store) DeleteUser(ctx context.Context, id uuid.UUID) error {
	return s.execOne(ctx, "delete user", `DELETE FROM users WHERE id = $1`, id)
}

// execOne runs a statement that must affect exactly one row.
func (s *Store) execOne(ctx context.Context, op, sql string, args ...any) error {
	tag, err := s.q.Exec(ctx, sql, args...)
	if err != nil {
		return wrap(op, err)
	}
	if tag.RowsAffected() == 0 {
		return wrap(op, ErrNotFound)
	}
	return nil
}
