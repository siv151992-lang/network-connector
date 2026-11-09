-- 0002_auth.sql — Phase 3 authentication additions.

-- Last accepted TOTP time step. A code is accepted only for a step greater
-- than this, so each code works once (RFC 6238 §5.2 replay protection).
ALTER TABLE users ADD COLUMN totp_last_step bigint NOT NULL DEFAULT 0;

-- Expired one-time tokens are purged by the server's janitor.
CREATE INDEX user_tokens_expires_idx ON user_tokens (expires_at);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);
