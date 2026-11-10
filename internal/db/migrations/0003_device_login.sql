-- 0003_device_login.sql — device-code login for headless clients.
-- A device starts a login and shows a short code; a signed-in user approves
-- it in the dashboard, choosing the network. The device polls with a secret
-- token and receives its credential once.
CREATE TABLE device_logins (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    code            text        NOT NULL,           -- e.g. BCDF-GHJK, shown to the user
    poll_hash       bytea       NOT NULL,           -- SHA-256 of the device's poll token
    node_key        bytea       NOT NULL,
    disco_key       bytea       NOT NULL,
    hostname        text        NOT NULL DEFAULT '',
    os              text        NOT NULL DEFAULT '',
    os_version      text        NOT NULL DEFAULT '',
    client_version  text        NOT NULL DEFAULT '',
    approved_by     uuid        REFERENCES users(id) ON DELETE CASCADE,
    device_id       uuid        REFERENCES devices(id) ON DELETE CASCADE,
    credential_enc  bytea,                          -- AES-GCM sealed; handed out once, then cleared
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    CONSTRAINT device_logins_code_format CHECK (code ~ '^[A-Z]{4}-[A-Z]{4}$'),
    CONSTRAINT device_logins_poll_len CHECK (octet_length(poll_hash) = 32),
    CONSTRAINT device_logins_keys CHECK (octet_length(node_key) = 32 AND octet_length(disco_key) = 32)
);
CREATE UNIQUE INDEX device_logins_code_key ON device_logins (code);
CREATE UNIQUE INDEX device_logins_poll_key ON device_logins (poll_hash);
CREATE INDEX device_logins_expires_idx ON device_logins (expires_at);
