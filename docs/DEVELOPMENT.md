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

## Phase 4: real tunnels

```bash
go build -o bin/wiremesh ./cmd/wiremesh
# on each Linux machine (root; uses /dev/net/tun):
sudo WIREMESH_AUTH_KEY=wmk_… ./bin/wiremesh up --server https://vpn.example.com --iface wm0
sudo ./bin/wiremesh status        # peers, endpoints, last handshake, rx/tx
```

* State (private keys + credential) lives in `/var/lib/wiremesh/state.json`
  with mode 0600. The client refuses to start if other users can read it.
* WireGuard listens on UDP **51820** (`--port`). Allow it in the firewall of
  machines that should accept direct connections.
* `wg show` works too, because the client serves WireGuard's standard UAPI socket.
* Until Phase 5 (NAT traversal), devices must reach each other's reported
  addresses directly: the same LAN, or one side with a public IP.

**Full tunnel test** (root, Linux, PostgreSQL), using real namespaces, real
WireGuard and real ACL enforcement:
```bash
sudo make test-netns TEST_DB=postgres://postgres:secret@localhost:5432/postgres
```

## Phase 5: push stream and NAT traversal

Devices now hold a WebSocket control stream (`GET /api/v1/device/stream`).
Map changes, presence and call-me-maybe are pushed instantly, so polling is gone.
To traverse NATs, the control server needs at least one STUN server:

```bash
go build -o bin/wiremesh-relay ./cmd/wiremesh-relay
./bin/wiremesh-relay --stun-addr :3478                      # on a public host (UDP 3478 open)
WIREMESH_STUN_SERVERS=vpn.example.com:3478 make run         # control server advertises it
```

`wiremesh status --json` shows each peer's live path (`endpoint`): a peer's
NAT public address means a hole-punched direct connection.

**NAT test** (root, Linux, PostgreSQL): two sites behind real `MASQUERADE`
NATs, 4 router hops apart.
```bash
sudo WIREMESH_TEST_DATABASE_URL=postgres://postgres:secret@localhost:5432/postgres scripts/nat-e2e.sh
```
It checks hole punching, roaming (site A's public IP changes) and that a
symmetric NAT correctly yields no direct path. Optional variables:
`WIREMESH_TEST_LOGS=<dir>` keeps logs, `WIREMESH_TEST_CONNTRACK=1` dumps the
routers' conntrack tables during roaming, and `WIREMESH_TEST_SKIP_CASE2=1`
skips the symmetric-NAT case.

## Phase 6: relay

```bash
export WIREMESH_SECRET_KEY=$(openssl rand -base64 32)   # same key as the control server
./bin/wiremesh-relay --stun-addr :3478 --relay-addr :8443 --control-key "$(./bin/wiremesh-server relay-pubkey)"
WIREMESH_RELAY_URLS=http://localhost:8443/relay WIREMESH_STUN_SERVERS=localhost:3478 make run
```
In production Caddy serves the relay at `https://<domain>/relay` (port 443),
so only UDP 3478 needs opening in addition. `wiremesh status` shows `relay`
as the endpoint for relayed peers.

## Phase 9: Linux client

* `wiremeshd` (systemd service, `clients/linux/wiremeshd.service`, sandboxed to
  network capabilities) owns the tunnel and serves a local API on
  `/run/wiremesh/wiremeshd.sock` (root + `wiremesh` group).
* `wiremesh up | down | status [--json] | logout` talk to it. `down` is
  remembered across reboots. `wiremesh run` is the daemon-less foreground mode.
* **Device-code login**: `wiremesh up --server URL` without an auth key prints
  `https://<server>/activate?code=XXXX-XXXX`. Approving it in the dashboard
  enrolls the device; approval by a network owner or admin also activates it.
* **MagicDNS**: each device answers `<device>.<network-slug>.wm.internal` on
  its tunnel address. With systemd-resolved, `resolvectl` routes that domain
  there automatically.
* Packaging: `make deb` (or `clients/linux/build-deb.sh <version> <arch>`).

## Phase 8: Windows

`make windows` cross-builds `dist/wiremesh-windows-<arch>-<version>.zip`, which
contains `wiremeshd.exe` (the "WireMesh" Windows service: wireguard-go +
Wintun, addresses/routes via winipcfg), `wiremesh.exe` (same CLI as Linux),
`wiremesh-tray.exe` (tray app) and `install.ps1`/`uninstall.ps1`. The
installer fetches Wintun and checks its WireGuard LLC Authenticode signature.
The local API is an AF_UNIX socket in `C:\ProgramData\WireMesh` (SYSTEM,
Administrators and the interactive user may connect; `state.json` is
SYSTEM/Administrators-only).

Status: compiled and vetted for windows/amd64 and arm64, but **not yet run
on a Windows machine**.

## Phase 10: web dashboard

```bash
cd web && npm install
WIREMESH_API=http://localhost:8080 npm run dev     # http://localhost:5173, API proxied (same-origin)
```
Set `WIREMESH_PUBLIC_URL=http://localhost:5173` on the server while developing:
the CSRF check compares the browser's Origin with it. Production builds are
baked into the Caddy image (`deploy/docker/caddy.Dockerfile`) and served with
a strict Content-Security-Policy.

End-to-end test (real server + PostgreSQL + Chromium; needs Playwright):
```bash
make web-e2e TEST_DB=postgres://postgres:secret@localhost:5432/postgres
```

## Phase 11: security and production checks

```bash
# Fuzz a parser (others: see .github/workflows/ci.yml)
go test -run='^$' -fuzz='^FuzzDecodeAndVerify$' -fuzztime=1m ./pkg/relayproto
# Netmap load benchmark (1000 devices)
go test -run='^$' -bench=Netmap1000 -benchmem ./internal/acl
# Backup/restore drill against any PostgreSQL that allows CREATE DATABASE
DB_ADMIN=postgres://postgres:secret@localhost:5432/postgres scripts/backup-drill.sh
```
CI (`.github/workflows/ci.yml`) runs all of these plus staticcheck,
govulncheck, npm audit, Trivy, the netns/NAT tunnel tests, the dashboard E2E
and the package builds on every push. See `docs/SECURITY.md`.

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
| `internal/acl` | unit | validation (every error reported), identity semantics (users, groups, tags, `autogroup:self`/`member`/`tagged`), peer visibility, filter compilation, ports/protocols (port rules never open ICMP), IPv4+IPv6 |
| `pkg/protocol` | unit | X25519 key derivation (RFC 7748 vector), JSON forms |
| `pkg/client` | unit | IPv4/IPv6 parsing incl. extension headers and fragments, malformed packets, default deny, conntrack replies/expiry, atomic rule swap, incremental WireGuard peer diff, UAPI stats parsing, state file permissions |
| `internal/api` netmap/ACL | integration | map contents and secrecy, ETag/304, endpoint validation, ACL versioning and validation, test endpoint and draft policies, pending/expired devices, key rotation restoring peers |
| `pkg/stun` | unit + fuzz | RFC 5769 test vector, round trips (v4/v6), malformed input, server counters |
| `pkg/disco` | unit + fuzz | NaCl box seal/open, wrong key, tampering, truncation |
| `pkg/client/magicsock` | integration | real wireguard-go devices over the magic socket: direct path discovery, one-sided candidates, call-me-maybe, unknown/foreign traffic dropped, path expiry |
| `internal/api` stream | integration | WebSocket auth (401/403), push on join/approve/ACL change, presence, endpoints over the stream, call-me-maybe forwarding with server-stamped sender, ACL blocks forwarding, revocation message |
| `pkg/relayproto`, `internal/acl`, `pkg/client` | fuzz | relay frames/tokens (canonical encoding only), ACL policies, inbound packet filter, MagicDNS |
| `scripts/backup-drill.sh` | system | dump a live server, restore into an empty DB, verify logins, devices, keys, encrypted secrets, audit log |
| `relay` | unit | forwarding with relay-stamped sender, forged/expired/garbage tokens rejected, network isolation, token and frame codecs |
| `pkg/client/magicsock` relay | integration | real WireGuard over the relay with no direct candidates, then automatic upgrade to a direct path |
| `scripts/nat-e2e.sh` | system | real NATs + STUN + relay: hole punch (~4 s), roaming recovers via relay (~10 s) then direct (~45 s), symmetric NAT works via relay |
| `scripts/netns-e2e.sh` | system | two namespaces, real `wiremesh` clients: enroll, handshake, ping both ways, live policy push (TCP 8080 allowed, 8081 and ICMP blocked, replies tracked), revocation tears down the tunnel |
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

## Windows server without Docker (standalone)

`deploy/windows/build-server.sh VERSION` builds
`dist/wiremesh-server-windows-amd64-VERSION.zip`: `wiremesh-server.exe`, the
dashboard and PostgreSQL 16 for Windows (zonky embedded binaries, pinned by
SHA-256). On the Windows PC: unzip and double-click `Install.bat`. It installs
the `WireMeshServer` service (runs as NetworkService) and opens TCP 80 and
UDP 3478 in the firewall, then opens the dashboard. The first person to sign
up becomes the admin (`WIREMESH_FIRST_USER_SETUP`). Data, secret key and log
live in `%ProgramData%\WireMesh Server`.

`wiremesh-server standalone` runs one process with embedded PostgreSQL
(listening on 127.0.0.1 only), the API, the dashboard, the relay (`/relay`)
and STUN, all configured automatically. Flags: `--data`, `--addr`, `--url`,
`--web`, `--postgres`. It also works on Linux as a non-root user (tested
here); on Windows it has only been cross-compiled.

## Home/office LAN server with Docker (no domain)

On a Windows PC with Docker Desktop, in an elevated PowerShell in `deploy/`:
```powershell
powershell -ExecutionPolicy Bypass -File .\lan-setup.ps1 -Ip 192.168.1.100 -Email you@example.com
```
It generates `.env`, builds and starts the stack with `docker-compose.lan.yml`
(plain HTTP on the IP, no certificate), opens TCP 80 / UDP 3478 in the
firewall and creates the admin. Devices join with
`wiremesh up --server http://192.168.1.100`. Open the dashboard at exactly
`http://<that IP>` (the CSRF check compares the browser's origin with it).
LAN only: the dashboard login isn't encrypted; device traffic still is
(WireGuard).

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
sudo ufw allow 3478/udp    # STUN (NAT traversal)
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
Test a restore into a scratch database regularly (`scripts/backup-drill.sh` automates the check). An untested backup isn't a backup. Back up `WIREMESH_SECRET_KEY` separately: encrypted secrets can't be read without it.

### 6. Upgrades
```bash
git pull && docker compose -f deploy/docker-compose.yml --env-file .env up -d --build
```
Migrations run on start. Take a backup before upgrading. Rollback means
restoring the backup taken before the upgrade, because migrations are forward-only.
