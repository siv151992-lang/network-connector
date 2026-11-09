# WireMesh — System Architecture

WireMesh is a self-hostable private mesh VPN built on WireGuard. A **control
plane** (Go, PostgreSQL) authenticates users and devices, allocates private
addresses, applies access policy and hands each device the list of peers it may
talk to. The **data plane** is device-to-device WireGuard. Packets go peer to
peer whenever NAT traversal succeeds, and through an encrypted **relay**
otherwise. The control plane and relays never see plaintext traffic and never
hold device private keys.

---

## 1. Components

| Component | Binary / app | Responsibility |
|---|---|---|
| Control server | `wiremesh-server` (Go) | REST API, WebSocket map stream, auth, device registry, IPAM, ACL compilation, audit log |
| Relay + STUN | `wiremesh-relay` (Go) | STUN (UDP 3478) for endpoint discovery; encrypted packet relay over HTTPS/WebSocket (TCP 443) for when direct UDP fails |
| Client core | `pkg/client` (Go) | wireguard-go engine, custom `conn.Bind` ("meshconn") for hole punching and relay fallback, TUN management, packet filter, control-plane client |
| Linux client | `wiremeshd` + `wiremesh` CLI | systemd daemon with TUN or kernel WireGuard; CLI over a local Unix socket |
| Windows client | `wiremesh-service` + Wails GUI | Windows service (wireguard-go + Wintun); GUI talks to the service over a named pipe |
| Android client | Kotlin app + `libwiremesh.aar` | `VpnService` supplies the TUN fd; the Go core is built with `gomobile bind` |
| Dashboard | `web/` (React + TS + Tailwind) | Admin and user UI over the REST API |
| PostgreSQL | — | System of record |
| Redis (optional) | — | Pub/sub fan-out and shared rate limits when running more than one control-server replica |
| Reverse proxy | Caddy | TLS termination (automatic ACME), HTTP/2, WebSocket upgrade, static dashboard |

### Why a modular monolith for the control server

The services in the brief (auth, device registry, IPAM, coordination, peer
discovery, NAT coordination, relay management, ACL, presence) are separate Go
packages behind interfaces. They ship as **one binary**. For a self-hosted VPS
this removes network hops, distributed transactions and N deployments, and IP
allocation stays a single serializable transaction. If you outgrow one node,
add replicas with Redis pub/sub. The package boundaries already match a later
service split.

---

## 2. Architecture diagram

```
                              ┌────────────────────────────────────────────┐
                              │                  VPS                        │
   Browser (dashboard)        │  ┌──────────┐    ┌────────────────────┐    │
  ───────── HTTPS 443 ───────▶│  │  Caddy   │───▶│  wiremesh-server   │    │
                              │  │ TLS/ACME │    │  REST + WebSocket  │    │
   Devices (control)          │  │  static  │    │ ┌────────────────┐ │    │
  ───── HTTPS/WSS 443 ───────▶│  │  web/    │    │ │ auth  │ devices│ │    │
                              │  └──────────┘    │ │ ipam  │ acl    │ │    │
                              │                  │ │ coord │ presence│ │   │
                              │                  │ └────────────────┘ │    │
                              │                  └───┬──────────┬─────┘    │
                              │                      │          │          │
                              │               ┌──────▼───┐ ┌────▼────┐     │
                              │               │PostgreSQL│ │ Redis   │     │
                              │               └──────────┘ │(optional)│    │
                              │                            └─────────┘     │
                              │  ┌──────────────────────────────────┐      │
   Devices (STUN) UDP 3478 ──▶│  │ wiremesh-relay  STUN + relay     │      │
   Devices (relay) TCP 8443 ─▶│  │ forwards WireGuard ciphertext    │      │
                              │  └──────────────────────────────────┘      │
                              └────────────────────────────────────────────┘

        Data plane (never touches the control server):

   ┌───────────────┐   WireGuard UDP (direct, hole-punched)   ┌───────────────┐
   │ Laptop        │◀════════════════════════════════════════▶│ Android phone │
   │ 100.64.0.1    │                                          │ 100.64.0.2    │
   └──────┬────────┘                                          └───────┬───────┘
          │  if direct UDP fails: WireGuard ciphertext framed        │
          └──────────────▶  wiremesh-relay (TCP/TLS)  ◀──────────────┘
```

### Device lifecycle (sequence)

```
Device                         Control server                    Relay
  │ 1. generate node key (WG), disco key; private halves stay local
  │ 2. POST /api/v1/device/register {auth_key | user session, node_key, disco_key, hostname, os}
  │──────────────────────────────▶│ validate key/session, check ACL tags
  │                               │ status = pending|approved
  │                               │ allocate 100.64.x.y + fdxx::/48 address (tx)
  │◀── device_id, credential, addresses ─│
  │ 3. WSS /api/v1/device/stream  (Bearer device credential)
  │──────────────────────────────▶│ send NetworkMap{self, peers[], relays[], filter, dns}
  │ 4. STUN binding request ─────────────────────────────────────────▶│
  │◀────────────────────────────── reflexive ip:port ────────────────│
  │ 5. stream: endpoint_update {local + reflexive candidates}
  │──────────────────────────────▶│ fan out a peer delta to every authorized peer
  │ 6. disco ping/pong to each candidate (both sides send at once = hole punch)
  │ 7a. success → WireGuard over the direct UDP path
  │ 7b. timeout → WireGuard over the relay; keep probing direct paths in the background
  │ 8. network change (Wi-Fi→LTE) → re-STUN, new candidates, re-probe; WireGuard roams on its own
```

---

## 3. Key design decisions and trade-offs

### 3.1 Userspace WireGuard vs kernel WireGuard
* **Recommended default: userspace `wireguard-go` with a custom `conn.Bind`.**
  NAT traversal has to share WireGuard's UDP socket (the punched hole belongs to
  that socket's 5-tuple) and has to switch transparently between a direct path
  and a relay. The kernel module owns its socket, so it can do neither.
  `wireguard-go` lets us implement `conn.Bind` and decide per packet where
  ciphertext goes. Tailscale's `magicsock` uses the same approach.
* **Optional kernel mode (Linux only)** for servers with a public, stable
  endpoint. It is faster, but has no relay fallback and no hole punching from
  its side.
* Android and Windows always use userspace: `VpnService` TUN fd on Android,
  Wintun on Windows.

### 3.2 Key model (private keys never leave the device)
| Key | Type | Lives | Purpose |
|---|---|---|---|
| Node key | Curve25519 (WireGuard) | private: device only; public: server | WireGuard tunnel identity; rotated on expiry |
| Disco key | Curve25519 | private: device only | NaCl-box sealed ping/pong/call-me-maybe for path discovery, so relays and on-path attackers can't forge path probes |
| Device credential | 256-bit random | device keystore; server stores SHA-256 only | authenticates the device to the control plane (REST + stream) |
| Relay token | Ed25519-signed, 10 min | issued by control, verified offline by relay | proves a device may use the relay, bound to its node key |
| Server secret key | 256-bit, env var | server only | AES-256-GCM encryption of sensitive columns (TOTP secrets) |

Device credentials are random bearer tokens over TLS, stored hashed. They can
be revoked with one row update, and there's no signature-verification code to
get wrong. JWT would add little, because every stream connection checks the
database anyway, and JWTs make revocation harder.

### 3.3 User auth: server-side sessions, not JWT
Dashboard sessions are opaque 256-bit tokens in an `HttpOnly; Secure;
SameSite=Strict` cookie. The database stores the SHA-256 hash. State-changing
requests also require a CSRF header. Revoking a session (logout, password
change, admin action) takes effect immediately. Passwords use **Argon2id**
(m=64 MiB, t=3, p=2). Optional TOTP 2FA (RFC 6238); the TOTP secret is
encrypted at rest.

### 3.4 Address allocation
* IPv4: the CGNAT range `100.64.0.0/10` (RFC 6598). It's unlikely to collide with
  home or office LANs. Each network gets a configurable sub-range.
* IPv6: a random ULA `/48` per network (RFC 4193, `fdXX:XXXX:XXXX::/48`), generated
  when the network is created.
* Allocation runs in one transaction with a `UNIQUE(network_id, ipv4)`
  constraint. The allocator picks the lowest free host address. The DB
  constraint closes any race between replicas, and the allocator retries on conflict.

### 3.5 Access control
The policy is a JSON document per network (groups, tags, rules `src → dst:ports`),
default-deny. The control server compiles it per device into:
1. **Peer visibility.** A device receives only peers it may reach or be reached by,
   so unauthorized peers don't learn each other's endpoints or keys.
2. **A packet filter**, enforced **inbound on the receiving device** in the
   userspace engine. A compromised peer can't bypass it by editing its own
   config.

### 3.5b NAT traversal (implemented in Phase 5, `pkg/client/magicsock`)
* **One UDP socket** per address family carries WireGuard, disco and STUN, so
  the public mapping STUN reports is the one WireGuard uses.
* WireGuard peers are configured with **identity endpoints** (`wm:<node key>`).
  The magicsock `Bind` picks the path for each packet. A path is only used once
  an authenticated disco pong confirms it, and inbound WireGuard packets are
  accepted only from verified addresses (private LAN addresses collide across
  sites).
* **Low-TTL hole punching.** On Linux NATs (most home routers), a probe that
  reaches the peer's NAT before the peer has an outbound mapping makes
  conntrack remap the peer's port, and the punch deadlocks. Verified
  empirically; see `scripts/nat-e2e.sh` with `WIREMESH_TEST_CONNTRACK=1`.
  Probes are therefore sent first with TTL 2-4 (they open our NAT but die
  before the peer's), then a **call-me-maybe** via the control stream makes the
  peer answer with normal packets.
* **Synchronized quiescing.** After a path dies mid-flow (e.g. a public IP
  change), stale packets can poison the NAT anyway. When 3 normal pings go
  unanswered, a `quiesce` call-me-maybe makes both sides go silent for 32 s
  (more than conntrack's 30 s), and both then retry with fresh state. Measured
  roaming recovery is 50-65 s; the Phase 6 relay carries traffic meanwhile.
* **Symmetric NATs** (random port per destination) can't be traversed this
  way; those pairs will use the relay.

### 3.6 Relay protocol
The relay is a custom protocol, not TURN. TURN allocates per-flow ports and
needs UDP. Our relay runs over TLS on TCP 443/8443, so it passes restrictive
firewalls and proxies. It keys forwarding on the destination node's public key
and only ever sees WireGuard ciphertext. A frame is
`type(1) | len(4) | dst_node_key(32) | payload`. Relays are stateless and
horizontally scalable; devices pick a home relay by lowest STUN RTT.

### 3.7 Real-time updates
*Phase 4 status:* devices poll `GET /device/netmap` every 10 s with
`If-None-Match`, so unchanged maps cost a `304`. The WebSocket stream below
replaces polling in Phase 5. WireGuard peers are updated incrementally (only
changed peers are touched), so polling never disrupts established sessions.

Each device holds one WebSocket (`/api/v1/device/stream`). The server sends a
full `NetworkMap`, then deltas when peers join or leave, endpoints change, the
policy changes, or a device is revoked. Presence (online/offline) comes from
stream liveness (ping every 30 s, offline after 75 s), never from guesses. With
more than one server replica, changes fan out through Redis pub/sub
(`wiremesh:net:<id>`).

---

## 4. Technology stack

| Layer | Choice | Rationale |
|---|---|---|
| Tunnel | WireGuard (`golang.zx2c4.com/wireguard`), kernel module optional | Audited, small, fast crypto (Noise IK, ChaCha20-Poly1305) |
| NAT traversal | STUN (RFC 5389 subset) + disco ping/pong + simultaneous open | Works for most NATs; symmetric NAT ↔ symmetric NAT falls back to relay |
| Relay | Custom framed relay over TLS | Firewall-friendly; relays only see ciphertext |
| Control server | Go 1.24, `net/http` (1.22+ routing), `pgx/v5`, `coder/websocket` | Minimal dependencies, same language as clients |
| Database | PostgreSQL 16 | Transactions for IPAM, `inet`/`cidr` types, JSONB for policies |
| Cache/bus | Redis 7 (optional) | Multi-replica pub/sub and rate limits |
| Dashboard | React 18, TypeScript, Vite, Tailwind CSS, TanStack Query | Typed, fast, responsive; dark/light via Tailwind `dark:` |
| Android | Kotlin, Jetpack Compose, `VpnService`, gomobile-built Go core | One NAT-traversal implementation shared by all platforms |
| Windows | Go service + Wintun, Wails v2 GUI (React) | Same Go core; GUI reuses dashboard components |
| Linux | Go daemon, systemd unit, netlink (`vishvananda/netlink`) | Native routes/DNS; optional kernel WG via `wgctrl` |
| Proxy | Caddy 2 | Automatic Let's Encrypt, sensible TLS defaults |
| Packaging | Docker Compose | One-command self-hosting |

---

## 5. Database schema

The authoritative definition is `internal/db/migrations/0001_init.sql`.
Entity overview:

```
users ─┬─< network_members >─ networks ─┬─< devices
       │                                 ├─< auth_keys
       ├─< sessions                      ├─< teams ─< team_members >─ users
       ├─< user_tokens (verify/reset)    ├── acl_policies (1:1) ─< acl_policy_history
       └─< audit_logs >──────────────────┘
relay_regions ─< relay_nodes
```

| Table | Key columns |
|---|---|
| `users` | id, email (lower-case, unique), password_hash (argon2id PHC string), display_name, system_role (`admin`/`user`), email_verified_at, totp_secret_enc, totp_enabled, disabled_at |
| `user_tokens` | token_hash (pk), user_id, purpose (`verify_email`/`reset_password`), expires_at, used_at |
| `sessions` | id, token_hash (unique), user_id, mfa_passed, ip, user_agent, expires_at, last_seen_at, revoked_at |
| `networks` | id, name, slug, ipv4_cidr, ipv6_cidr, device_approval_required, key_expiry_days |
| `network_members` | (network_id, user_id), role (`owner`/`admin`/`member`/`auditor`) |
| `teams`, `team_members` | named groups of users referenced in ACLs as `group:<name>` |
| `auth_keys` | id, network_id, key_hash, prefix, reusable, ephemeral, preauthorized, tags[], expires_at, uses, revoked_at |
| `devices` | id, network_id, user_id, name, hostname, os, node_key (32 B, unique), disco_key, credential_hash, ipv4, ipv6, status (`pending`/`approved`/`rejected`/`revoked`), tags[], endpoints (jsonb), home_relay_region, advertised_routes[], approved_routes[], key_expires_at, last_seen_at |
| `acl_policies` | network_id (pk), version, policy (jsonb), updated_by |
| `relay_regions`, `relay_nodes` | region code/name; node hostname, IPs, stun_port, relay_port |
| `audit_logs` | id, network_id, actor_user_id, actor_device_id, action, target_type, target_id, ip, metadata (jsonb), created_at |

Integrity is enforced in the database, not only in Go:
`UNIQUE(network_id, ipv4)`, `UNIQUE(network_id, ipv6)`, `UNIQUE(node_key)`,
`CHECK(octet_length(node_key)=32)`, `CHECK(email = lower(email))`, and enum
`CHECK`s on status and role columns.

---

## 6. API design

Base path `/api/v1`. JSON in and out. Errors always use this shape:

```json
{ "error": { "code": "not_found", "message": "device not found", "request_id": "…" } }
```

Authentication: **U** = user session cookie (+ `X-CSRF-Token` on mutations),
**D** = `Authorization: Bearer <device credential>`, **A** = network admin/owner,
**S** = system admin, `—` = public (rate-limited).

### System
| Method | Path | Auth | Phase |
|---|---|---|---|
| GET | `/healthz` | — | 2 |
| GET | `/readyz` | — | 2 |
| GET | `/api/v1/version` | — | 2 |

### Authentication (Phase 3)
Self-registration is **off by default** (`WIREMESH_ALLOW_REGISTRATION=false`). The first
admin is created on the server with `wiremesh-server create-admin`, so nobody on the
internet can race you to it. Further accounts come from `POST /admin/users`. Full
request/response details: [API.md](API.md).

| Method | Path | Auth |
|---|---|---|
| POST | `/api/v1/auth/register` | — |
| POST | `/api/v1/auth/verify-email` | — |
| POST | `/api/v1/auth/login` | — |
| POST | `/api/v1/auth/login/mfa` | partial session |
| POST | `/api/v1/auth/logout` | U |
| POST | `/api/v1/auth/password/forgot` / `/reset` | — |
| GET | `/api/v1/auth/me` | U |
| GET/DELETE | `/api/v1/auth/sessions[/{id}]` | U |
| POST | `/api/v1/auth/mfa/totp/setup` / `/enable` / `/disable` | U |

### Networks, members, teams
| Method | Path | Auth |
|---|---|---|
| GET/POST | `/api/v1/networks` | U |
| GET/PATCH/DELETE | `/api/v1/networks/{nid}` | U / A |
| GET/POST | `/api/v1/networks/{nid}/members` | A |
| PATCH/DELETE | `/api/v1/networks/{nid}/members/{uid}` | A |
| GET/POST | `/api/v1/networks/{nid}/teams` | A |
| PUT/DELETE | `/api/v1/networks/{nid}/teams/{tid}[/members/{uid}]` | A |

### Devices (dashboard side)
| Method | Path | Auth |
|---|---|---|
| GET | `/api/v1/networks/{nid}/devices` | U (members see their own; admins see all) |
| GET/PATCH/DELETE | `/api/v1/networks/{nid}/devices/{did}` | U owner / A |
| POST | `/api/v1/networks/{nid}/devices/{did}/approve` / `/reject` / `/revoke` | A |
| POST | `/api/v1/networks/{nid}/devices/{did}/routes` | A |
| GET/POST | `/api/v1/networks/{nid}/auth-keys` | A |
| DELETE | `/api/v1/networks/{nid}/auth-keys/{kid}` | A |

### Device control plane (client side)
| Method | Path | Auth |
|---|---|---|
| POST | `/api/v1/device/register` | auth key in body, or U (interactive login) |
| POST | `/api/v1/device/login/start` → `/poll` | — (device-code flow for headless/TV/CLI; Phase 9) |
| GET | `/api/v1/device/self` | D |
| GET (WS) | `/api/v1/device/stream` | D |
| POST | `/api/v1/device/rotate-key` | D |
| POST | `/api/v1/device/relay-token` | D |
| POST | `/api/v1/device/logout` | D |

Stream messages (JSON frames, `type` discriminator):
`map` (full NetworkMap), `peer_upsert`, `peer_remove`, `filter`, `relays`,
`revoked`, `ping` ↔ client `pong`, `endpoint_update`, `call_me_maybe`.

### Policy, relays, audit, admin
| Method | Path | Auth |
|---|---|---|
| GET/PUT | `/api/v1/networks/{nid}/acl` | U read / A write (validated, versioned, `If-Match`) |
| POST | `/api/v1/networks/{nid}/acl/test` | A (dry-run "can A reach B:port?") |
| GET | `/api/v1/networks/{nid}/audit-logs?cursor=&action=` | A / auditor |
| GET | `/api/v1/networks/{nid}/status` | U (live peer/path summary) |
| GET/POST/PATCH/DELETE | `/api/v1/admin/relays…` | S |
| GET/PATCH | `/api/v1/admin/users…` | S |
| GET/PATCH | `/api/v1/admin/settings` | S |

---

## 7. Folder structure

```
wiremesh/
├── go.mod                       # single Go module: server, relay, clients, mobile bindings
├── Makefile
├── .env.example
├── cmd/
│   ├── wiremesh-server/         # control server entrypoint            (Phase 2)
│   ├── wiremesh-relay/          # relay + STUN entrypoint              (Phase 6)
│   ├── wiremeshd/               # Linux daemon                         (Phase 9)
│   └── wiremesh/                # CLI (up/down/status/ping)            (Phase 9)
├── internal/                    # server-only packages
│   ├── config/                  # env config + validation             (Phase 2)
│   ├── logging/                 # slog setup                          (Phase 2)
│   ├── db/ + db/migrations/     # pgx pool, embedded SQL migrations   (Phase 2)
│   ├── store/                   # repositories (users, devices, …)    (Phase 2)
│   ├── api/                     # router, handlers                    (Phase 2+)
│   │   ├── httpx/               # JSON/error helpers                  (Phase 2)
│   │   └── middleware/          # request id, logging, recover, rate limit, CORS, headers
│   ├── secretbox/               # AES-256-GCM for columns at rest     (Phase 2)
│   ├── version/
│   ├── auth/                    # passwords, tokens, TOTP, email      (Phase 3)
│   ├── devices/                 # enrollment, naming, credentials     (Phase 3)
│   ├── ipam/                    # address allocator                   (Phase 3)
│   ├── acl/                     # policy parse/validate/compile       (Phase 4)
│   ├── coord/                   # netmap builder (Phase 4); stream hub, presence (Phase 5)
│   └── relayadmin/              # relay registry, relay tokens        (Phase 6)
├── pkg/                         # shared by server and clients
│   ├── protocol/                # wire types: NetworkMap, Peer, stream msgs (Phase 4)
│   ├── stun/                    # STUN codec                          (Phase 5)
│   ├── disco/                   # disco message sealing               (Phase 5)
│   ├── relayproto/              # relay framing                       (Phase 6)
│   └── client/                  # engine: wireguard-go, meshconn Bind, tun, filter (Phase 4–6)
│       └── mobile/              # gomobile façade for Android         (Phase 7)
├── relay/                       # relay server implementation         (Phase 6)
├── clients/
│   ├── android/                 # Gradle project (Kotlin, Compose)    (Phase 7)
│   ├── windows/                 # Wails app + service installer       (Phase 8)
│   └── linux/                   # systemd unit, packaging             (Phase 9)
├── web/                         # React + TS + Tailwind dashboard     (Phase 10)
├── deploy/
│   ├── docker/                  # Dockerfiles
│   ├── caddy/                   # Caddyfile
│   └── docker-compose.yml
└── docs/
    ├── ARCHITECTURE.md          # this file
    ├── DEVELOPMENT.md           # running and testing each phase
    └── ROADMAP.md
```

---

## 8. Threat model (summary)

| Threat | Mitigation |
|---|---|
| Control server compromised | Can't decrypt traffic (no private keys). It *can* inject a malicious peer, so devices show new peers, and an optional "tailnet lock"-style signed node-key list is planned after v1 |
| Relay compromised | Sees only WireGuard ciphertext plus metadata (who talks to whom, volume) |
| Stolen device credential | Bound to a node key; revocable; can't produce WireGuard sessions without the node private key |
| Credential stuffing / brute force | Argon2id, per-IP and per-account rate limits, optional TOTP, audit log |
| Database leak | Tokens stored as SHA-256; passwords Argon2id; TOTP secrets AES-GCM with an off-DB key |
| Lateral movement inside the mesh | Default-deny ACL, server-side peer filtering, inbound packet filter on each device |
| CSRF / XSS on dashboard | SameSite=Strict cookies, CSRF header, strict CSP, React escaping |
