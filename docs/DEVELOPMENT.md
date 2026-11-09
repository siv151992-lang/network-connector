# Development, Testing and Deployment Guide

## Prerequisites
* Go 1.24+
* PostgreSQL 16 (via Docker: `make dev-db`, or a local install)
* Docker + Docker Compose v2 (for deployment)

## Phase 2: run and test locally

```bash
make dev-db            # starts postgres on 127.0.0.1:5432 (user/pass/db: wiremesh)
make test              # unit tests (integration tests auto-skip)
make test-integration  # unit + integration tests against real PostgreSQL
make migrate-status    # shows pending migrations
make run               # migrates and serves on :8080
```

In another terminal:

```bash
curl -s localhost:8080/healthz          # {"status":"ok"}
curl -s localhost:8080/readyz           # {"checks":{"database":"ok"},"status":"ready"}
curl -s localhost:8080/api/v1/version
curl -si localhost:8080/api/v1/nope     # JSON 404 with X-Request-ID
```

## Phase 3: accounts and device enrollment

```bash
make build
export WIREMESH_DATABASE_URL="postgres://wiremesh:wiremesh@localhost:5432/wiremesh?sslmode=disable"
./bin/wiremesh-server create-admin --email you@example.com   # prompts for a password
make run
```
Then follow the curl walkthrough in [API.md](API.md): sign in, create a
network, create an auth key and enroll a device with real WireGuard public keys
(`wg genkey | wg pubkey`). Without SMTP in development, verification and reset
emails, links included, are printed to the server log.

### What the tests cover
| Package | Kind | Covers |
|---|---|---|
| `internal/config` | unit | defaults, production-only requirements, all-errors-at-once reporting |
| `internal/secretbox` | unit | AES-GCM round trip, tamper/wrong-key/wrong-AD rejection |
| `internal/api/httpx` | unit | strict JSON decoding (unknown fields, trailing data, size, type), error mapping hides internals |
| `internal/api/middleware` | unit | X-Forwarded-For spoofing resistance, request IDs, panic recovery, CORS allow-list, body limit, token-bucket limiter with IPv6 /64 bucketing |
| `internal/api` | unit | health/readiness/version/404 over a real HTTP server |
| `internal/db` | unit + integration | migration naming, idempotency, 4 concurrent migrators, checksum tampering |
| `internal/auth` | unit | Argon2id hash/verify/rehash, malicious-parameter rejection, password policy, token prefixes, CSRF HMAC, RFC 6238 vectors, TOTP skew and replay, email header injection |
| `internal/ipam` | unit | lowest-free allocation, reuse after release, exhaustion, IPv4→IPv6 mapping, ULA generation |
| `internal/devices` | unit + integration | name sanitizing/dedup, key parsing, session and auth-key enrollment, single-use keys not burned by failed registrations, expired keys, **20 concurrent registrations get distinct IPs and names** |
| `internal/api` (E2E) | integration | full HTTP flows over a real server and database: registration + verification, enumeration-safe sign-up, CSRF and Origin checks, TOTP enable/login/replay/disable, password reset and change revoking sessions, lockout, auth rate limit, admin user management, network RBAC (owner/admin/member/auditor/outsider), auth keys, device enrollment, approval, rotation, revocation, ephemeral logout, member removal deleting devices, audit trail |
| `internal/store` | integration | users (case-insensitive email, lockout), sessions (revocation scoping), networks (last-owner protection incl. concurrent race), devices (uniqueness of IP/name/key, status state machine, revocation clears credential, cross-network isolation), audit (keyset pagination) |

Integration tests need a role that can `CREATE DATABASE`. Each test creates
`wiremesh_test_<random>`, migrates it, and drops it afterwards, so tests run in
parallel and leave nothing behind.

```bash
WIREMESH_TEST_DATABASE_URL=postgres://postgres:secret@localhost:5432/postgres go test -race ./...
```

## Configuration
All settings are `WIREMESH_*` environment variables (see `.env.example`).
Invalid configuration aborts startup and lists every problem at once. In
`production` mode the server also requires an `https` public URL and a 32-byte
`WIREMESH_SECRET_KEY`.

## Migrations
* SQL files live in `internal/db/migrations/NNNN_name.sql` and are embedded in the binary.
* `serve` applies them automatically (`WIREMESH_AUTO_MIGRATE=true`, the default), or run `wiremesh-server migrate up`.
* A PostgreSQL advisory lock serializes concurrent replicas.
* The runner stores a SHA-256 of each file. Editing a shipped migration is a startup error. Add a new file instead.
* A database that has migrations this binary doesn't know (i.e. a downgrade) is also refused.

---

## Production deployment on a VPS

### 1. Server and DNS
* Ubuntu 24.04 / Debian 12 VPS, 1 vCPU / 1 GB RAM is plenty for hundreds of devices.
* Create DNS `A` (and `AAAA`) records: `vpn.example.com → <VPS IP>`.

### 2. Firewall
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp      # ACME HTTP-01 challenge + redirect
sudo ufw allow 443/tcp     # dashboard, API, device control plane
sudo ufw allow 443/udp     # HTTP/3
# Phase 6 (relay):
# sudo ufw allow 3478/udp  # STUN
# sudo ufw allow 8443/tcp  # relay
sudo ufw enable
```
Docker publishes ports by editing iptables directly, so it bypasses UFW. The
compose file publishes only Caddy's ports. PostgreSQL and Redis sit on an
`internal` network with no published ports.

### 3. Install and start
```bash
curl -fsSL https://get.docker.com | sh
git clone <your fork> wiremesh && cd wiremesh
cp .env.example .env
sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(openssl rand -base64 24 | tr -d '/+=')|" .env
sed -i "s|^WIREMESH_SECRET_KEY=.*|WIREMESH_SECRET_KEY=$(openssl rand -base64 32)|" .env
nano .env                              # set WIREMESH_DOMAIN and ACME_EMAIL
chmod 600 .env
docker compose -f deploy/docker-compose.yml --env-file .env up -d --build
curl -s https://vpn.example.com/readyz

# Create the first administrator (registration is closed by default)
docker compose -f deploy/docker-compose.yml exec server \
  wiremesh-server create-admin --email you@example.com
```
Configure SMTP in `.env` (`WIREMESH_SMTP_*`) before inviting users:
production refuses to start with email verification on and no SMTP server.

### 4. TLS
Caddy gets and renews Let's Encrypt certificates automatically for
`WIREMESH_DOMAIN` (port 80 must be reachable for the first issuance) and
serves TLS 1.2+/1.3 with modern ciphers and HSTS. The control server listens
only on the internal Docker network and trusts `X-Forwarded-For` only from
Docker's private ranges.

### 5. Backup and recovery
Back up two things: **the database** and **`WIREMESH_SECRET_KEY`**. Without
the key, encrypted columns (TOTP secrets) can't be recovered.

```bash
# Daily logical backup (add to root's crontab)
docker compose -f deploy/docker-compose.yml exec -T postgres \
  pg_dump -U wiremesh -d wiremesh -Fc > /var/backups/wiremesh-$(date +%F).dump
find /var/backups -name 'wiremesh-*.dump' -mtime +14 -delete
```
Copy backups off-site (e.g. `restic` or `rclone` to object storage) and store
`.env` in a password manager.

Restore:
```bash
docker compose -f deploy/docker-compose.yml stop server
docker compose -f deploy/docker-compose.yml exec -T postgres \
  pg_restore -U wiremesh -d wiremesh --clean --if-exists < /var/backups/wiremesh-YYYY-MM-DD.dump
docker compose -f deploy/docker-compose.yml start server
```
Test a restore into a scratch database regularly. An untested backup isn't a backup.

### 6. Upgrades
```bash
git pull && docker compose -f deploy/docker-compose.yml --env-file .env up -d --build
```
Migrations run on start. Take a backup before upgrading. Rollback means
restoring the backup taken before the upgrade, because migrations are forward-only.
