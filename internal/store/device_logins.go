package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// DeviceLogin is a pending device-code login.
type DeviceLogin struct {
	ID            uuid.UUID  `json:"id"`
	Code          string     `json:"code"`
	NodeKey       []byte     `json:"-"`
	DiscoKey      []byte     `json:"-"`
	Hostname      string     `json:"hostname"`
	OS            string     `json:"os"`
	OSVersion     string     `json:"os_version"`
	ClientVersion string     `json:"client_version"`
	ApprovedBy    *uuid.UUID `json:"-"`
	DeviceID      *uuid.UUID `json:"device_id,omitempty"`
	CredentialEnc []byte     `json:"-"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
}

const deviceLoginCols = `id, code, node_key, disco_key, hostname, os, os_version, client_version,
	approved_by, device_id, credential_enc, created_at, expires_at`

func scanDeviceLogin(row interface{ Scan(...any) error }) (*DeviceLogin, error) {
	var l DeviceLogin
	if err := row.Scan(&l.ID, &l.Code, &l.NodeKey, &l.DiscoKey, &l.Hostname, &l.OS, &l.OSVersion, &l.ClientVersion,
		&l.ApprovedBy, &l.DeviceID, &l.CredentialEnc, &l.CreatedAt, &l.ExpiresAt); err != nil {
		return nil, err
	}
	return &l, nil
}

// CreateDeviceLogin stores a new pending login. A code collision returns a
// *ConflictError so the caller can retry with another code.
func (s *Store) CreateDeviceLogin(ctx context.Context, l DeviceLogin, pollHash []byte) (*DeviceLogin, error) {
	out, err := scanDeviceLogin(s.q.QueryRow(ctx, `
		INSERT INTO device_logins (code, poll_hash, node_key, disco_key, hostname, os, os_version, client_version, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING `+deviceLoginCols,
		l.Code, pollHash, l.NodeKey, l.DiscoKey, truncate(l.Hostname, 255), truncate(l.OS, 64),
		truncate(l.OSVersion, 64), truncate(l.ClientVersion, 64), l.ExpiresAt))
	return out, wrap("create device login", err)
}

// GetDeviceLoginByCode returns an unexpired, not-yet-approved login.
func (s *Store) GetDeviceLoginByCode(ctx context.Context, code string) (*DeviceLogin, error) {
	l, err := scanDeviceLogin(s.q.QueryRow(ctx, `SELECT `+deviceLoginCols+` FROM device_logins
		WHERE code = $1 AND expires_at > now() AND approved_by IS NULL`, code))
	return l, wrap("get device login", err)
}

// GetDeviceLoginByPoll returns an unexpired login by poll-token hash.
func (s *Store) GetDeviceLoginByPoll(ctx context.Context, pollHash []byte) (*DeviceLogin, error) {
	l, err := scanDeviceLogin(s.q.QueryRow(ctx, `SELECT `+deviceLoginCols+` FROM device_logins
		WHERE poll_hash = $1 AND expires_at > now()`, pollHash))
	return l, wrap("get device login", err)
}

// LockDeviceLoginByCode locks a pending login for approval (inside WithTx).
func (s *Store) LockDeviceLoginByCode(ctx context.Context, code string) (*DeviceLogin, error) {
	l, err := scanDeviceLogin(s.q.QueryRow(ctx, `SELECT `+deviceLoginCols+` FROM device_logins
		WHERE code = $1 AND expires_at > now() AND approved_by IS NULL FOR UPDATE`, code))
	return l, wrap("lock device login", err)
}

// ApproveDeviceLogin records the approval and the sealed credential.
func (s *Store) ApproveDeviceLogin(ctx context.Context, id, userID, deviceID uuid.UUID, credEnc []byte) error {
	return s.execOne(ctx, "approve device login", `
		UPDATE device_logins SET approved_by = $2, device_id = $3, credential_enc = $4 WHERE id = $1`,
		id, userID, deviceID, credEnc)
}

// DeleteDeviceLogin removes a login (after the credential was handed out).
func (s *Store) DeleteDeviceLogin(ctx context.Context, id uuid.UUID) error {
	return s.execOne(ctx, "delete device login", `DELETE FROM device_logins WHERE id = $1`, id)
}

// DeleteExpiredDeviceLogins purges expired logins.
func (s *Store) DeleteExpiredDeviceLogins(ctx context.Context) (int64, error) {
	tag, err := s.q.Exec(ctx, `DELETE FROM device_logins WHERE expires_at < now()`)
	if err != nil {
		return 0, wrap("delete expired device logins", err)
	}
	return tag.RowsAffected(), nil
}
