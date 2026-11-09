-- 0001_init.sql — initial WireMesh schema.
-- Migrations are applied in order, each in its own transaction, by internal/db.Migrate.
-- Never edit a migration that has shipped; add a new numbered file instead
-- (the runner verifies checksums and refuses to start on mismatch).

-- ---------------------------------------------------------------------------
-- Users and authentication
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email              text        NOT NULL,
    password_hash      text        NOT NULL,              -- argon2id PHC string
    display_name       text        NOT NULL DEFAULT '',
    system_role        text        NOT NULL DEFAULT 'user',
    email_verified_at  timestamptz,
    totp_secret_enc    bytea,                             -- AES-256-GCM (internal/secretbox)
    totp_enabled       boolean     NOT NULL DEFAULT false,
    failed_logins      integer     NOT NULL DEFAULT 0,
    locked_until       timestamptz,
    last_login_at      timestamptz,
    disabled_at        timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT users_email_lower    CHECK (email = lower(email)),
    CONSTRAINT users_email_len      CHECK (char_length(email) BETWEEN 3 AND 254),
    CONSTRAINT users_system_role    CHECK (system_role IN ('admin', 'user')),
    CONSTRAINT users_totp_consistent CHECK (NOT totp_enabled OR totp_secret_enc IS NOT NULL)
);
CREATE UNIQUE INDEX users_email_key ON users (email);

-- One-time tokens sent by email (verification, password reset). Only hashes are stored.
CREATE TABLE user_tokens (
    token_hash  bytea       PRIMARY KEY,
    user_id     uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose     text        NOT NULL,
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT user_tokens_purpose CHECK (purpose IN ('verify_email', 'reset_password')),
    CONSTRAINT user_tokens_hash_len CHECK (octet_length(token_hash) = 32)
);
CREATE INDEX user_tokens_user_idx ON user_tokens (user_id, purpose);

CREATE TABLE sessions (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash    bytea       NOT NULL,
    user_id       uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mfa_passed    boolean     NOT NULL DEFAULT false,
    ip            inet,
    user_agent    text        NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    revoked_at    timestamptz,
    CONSTRAINT sessions_hash_len CHECK (octet_length(token_hash) = 32)
);
CREATE UNIQUE INDEX sessions_token_hash_key ON sessions (token_hash);
CREATE INDEX sessions_user_idx ON sessions (user_id) WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- Networks ("tailnets"), membership, teams
-- ---------------------------------------------------------------------------
CREATE TABLE networks (
    id                        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name                      text        NOT NULL,
    slug                      text        NOT NULL,
    ipv4_cidr                 cidr        NOT NULL,
    ipv6_cidr                 cidr        NOT NULL,
    device_approval_required  boolean     NOT NULL DEFAULT true,
    key_expiry_days           integer     NOT NULL DEFAULT 180,
    created_at                timestamptz NOT NULL DEFAULT now(),
    updated_at                timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT networks_slug_format CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    CONSTRAINT networks_name_len    CHECK (char_length(name) BETWEEN 1 AND 100),
    CONSTRAINT networks_ipv4_family CHECK (family(ipv4_cidr) = 4),
    CONSTRAINT networks_ipv6_family CHECK (family(ipv6_cidr) = 6),
    CONSTRAINT networks_key_expiry  CHECK (key_expiry_days BETWEEN 0 AND 3650)  -- 0 = never
);
CREATE UNIQUE INDEX networks_slug_key ON networks (slug);

CREATE TABLE network_members (
    network_id  uuid        NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    user_id     uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role        text        NOT NULL DEFAULT 'member',
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (network_id, user_id),
    CONSTRAINT network_members_role CHECK (role IN ('owner', 'admin', 'member', 'auditor'))
);
CREATE INDEX network_members_user_idx ON network_members (user_id);

CREATE TABLE teams (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    network_id  uuid        NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    name        text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT teams_name_format CHECK (name ~ '^[a-z0-9][a-z0-9_-]{0,62}$')
);
CREATE UNIQUE INDEX teams_network_name_key ON teams (network_id, name);

CREATE TABLE team_members (
    team_id  uuid NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id  uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (team_id, user_id)
);

-- ---------------------------------------------------------------------------
-- Pre-authentication keys for unattended device enrollment
-- ---------------------------------------------------------------------------
CREATE TABLE auth_keys (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    network_id     uuid        NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    created_by     uuid        REFERENCES users(id) ON DELETE SET NULL,
    key_hash       bytea       NOT NULL,
    prefix         text        NOT NULL,          -- first chars shown in UI, e.g. "wmk_ab12"
    description    text        NOT NULL DEFAULT '',
    reusable       boolean     NOT NULL DEFAULT false,
    ephemeral      boolean     NOT NULL DEFAULT false,
    preauthorized  boolean     NOT NULL DEFAULT false,
    tags           text[]      NOT NULL DEFAULT '{}',
    uses           integer     NOT NULL DEFAULT 0,
    expires_at     timestamptz NOT NULL,
    revoked_at     timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT auth_keys_hash_len CHECK (octet_length(key_hash) = 32)
);
CREATE UNIQUE INDEX auth_keys_hash_key ON auth_keys (key_hash);
CREATE INDEX auth_keys_network_idx ON auth_keys (network_id);

-- ---------------------------------------------------------------------------
-- Devices (nodes)
-- ---------------------------------------------------------------------------
CREATE TABLE devices (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    network_id         uuid        NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    user_id            uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    auth_key_id        uuid        REFERENCES auth_keys(id) ON DELETE SET NULL,
    name               text        NOT NULL,      -- DNS-safe label, unique per network
    hostname           text        NOT NULL DEFAULT '',
    os                 text        NOT NULL DEFAULT '',
    os_version         text        NOT NULL DEFAULT '',
    client_version     text        NOT NULL DEFAULT '',
    node_key           bytea       NOT NULL,      -- WireGuard public key
    disco_key          bytea       NOT NULL,      -- disco public key
    credential_hash    bytea,                     -- SHA-256 of device bearer credential
    ipv4               inet        NOT NULL,
    ipv6               inet        NOT NULL,
    status             text        NOT NULL DEFAULT 'pending',
    ephemeral          boolean     NOT NULL DEFAULT false,
    tags               text[]      NOT NULL DEFAULT '{}',
    endpoints          jsonb       NOT NULL DEFAULT '[]',   -- last reported ip:port candidates
    home_relay_region  integer,
    advertised_routes  cidr[]      NOT NULL DEFAULT '{}',
    approved_routes    cidr[]      NOT NULL DEFAULT '{}',
    is_exit_node       boolean     NOT NULL DEFAULT false,
    key_expires_at     timestamptz,
    last_seen_at       timestamptz,
    approved_at        timestamptz,
    approved_by        uuid        REFERENCES users(id) ON DELETE SET NULL,
    revoked_at         timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT devices_status        CHECK (status IN ('pending', 'approved', 'rejected', 'revoked')),
    CONSTRAINT devices_node_key_len  CHECK (octet_length(node_key) = 32),
    CONSTRAINT devices_disco_key_len CHECK (octet_length(disco_key) = 32),
    CONSTRAINT devices_cred_len      CHECK (credential_hash IS NULL OR octet_length(credential_hash) = 32),
    CONSTRAINT devices_ipv4_host     CHECK (family(ipv4) = 4 AND masklen(ipv4) = 32),
    CONSTRAINT devices_ipv6_host     CHECK (family(ipv6) = 6 AND masklen(ipv6) = 128),
    CONSTRAINT devices_name_format   CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    CONSTRAINT devices_endpoints_arr CHECK (jsonb_typeof(endpoints) = 'array')
);
CREATE UNIQUE INDEX devices_node_key_key      ON devices (node_key);
CREATE UNIQUE INDEX devices_credential_key    ON devices (credential_hash) WHERE credential_hash IS NOT NULL;
CREATE UNIQUE INDEX devices_network_ipv4_key  ON devices (network_id, ipv4);
CREATE UNIQUE INDEX devices_network_ipv6_key  ON devices (network_id, ipv6);
CREATE UNIQUE INDEX devices_network_name_key  ON devices (network_id, name);
CREATE INDEX devices_user_idx ON devices (user_id);

-- ---------------------------------------------------------------------------
-- Access control policy (one current document per network, with history)
-- ---------------------------------------------------------------------------
CREATE TABLE acl_policies (
    network_id  uuid PRIMARY KEY REFERENCES networks(id) ON DELETE CASCADE,
    version     integer     NOT NULL DEFAULT 1,
    policy      jsonb       NOT NULL,
    updated_by  uuid        REFERENCES users(id) ON DELETE SET NULL,
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE acl_policy_history (
    id          bigserial PRIMARY KEY,
    network_id  uuid        NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    version     integer     NOT NULL,
    policy      jsonb       NOT NULL,
    updated_by  uuid        REFERENCES users(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (network_id, version)
);

-- ---------------------------------------------------------------------------
-- Relay infrastructure
-- ---------------------------------------------------------------------------
CREATE TABLE relay_regions (
    id          integer PRIMARY KEY,               -- small stable number used on the wire
    code        text        NOT NULL UNIQUE,       -- e.g. "fra"
    name        text        NOT NULL,              -- e.g. "Frankfurt"
    enabled     boolean     NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT relay_regions_id_range CHECK (id BETWEEN 1 AND 65535)
);

CREATE TABLE relay_nodes (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    region_id   integer     NOT NULL REFERENCES relay_regions(id) ON DELETE CASCADE,
    name        text        NOT NULL UNIQUE,
    hostname    text        NOT NULL,              -- TLS name
    ipv4        inet,
    ipv6        inet,
    stun_port   integer     NOT NULL DEFAULT 3478,
    relay_port  integer     NOT NULL DEFAULT 8443,
    enabled     boolean     NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT relay_nodes_stun_port  CHECK (stun_port  BETWEEN 1 AND 65535),
    CONSTRAINT relay_nodes_relay_port CHECK (relay_port BETWEEN 1 AND 65535)
);

-- ---------------------------------------------------------------------------
-- Audit log (append-only from the application's point of view)
-- ---------------------------------------------------------------------------
CREATE TABLE audit_logs (
    id               bigserial PRIMARY KEY,
    network_id       uuid        REFERENCES networks(id) ON DELETE SET NULL,
    actor_user_id    uuid        REFERENCES users(id)    ON DELETE SET NULL,
    actor_device_id  uuid        REFERENCES devices(id)  ON DELETE SET NULL,
    action           text        NOT NULL,             -- e.g. "device.approve"
    target_type      text        NOT NULL DEFAULT '',
    target_id        text        NOT NULL DEFAULT '',
    ip               inet,
    user_agent       text        NOT NULL DEFAULT '',
    metadata         jsonb       NOT NULL DEFAULT '{}',
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_logs_network_idx ON audit_logs (network_id, id DESC);
CREATE INDEX audit_logs_actor_idx   ON audit_logs (actor_user_id, id DESC);
