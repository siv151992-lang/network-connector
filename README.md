# WireMesh

A self-hostable private mesh VPN built on WireGuard: a Go control server
coordinates your devices, and traffic flows end-to-end encrypted directly
between them, or through an encrypted relay when NATs block direct paths.

> **Status: Phases 1–6, 9 and 10 complete** (Android/Windows clients pending). Accounts, networks, roles, auth keys and
> device enrollment work over the API. The Linux client brings up **real
> WireGuard tunnels** with ACL-enforced packet filtering, pushes and receives
> changes instantly over a control stream, and connects devices **directly
> through NATs** (STUN + hole punching), falling back to an encrypted relay
> when no direct path exists (symmetric NAT/CGNAT, blocked UDP).
> See [docs/ROADMAP.md](docs/ROADMAP.md).

* [Architecture, schema, API design](docs/ARCHITECTURE.md)
* Web dashboard: `web/` (React + TypeScript + Tailwind), served by Caddy at your domain
* [API reference + curl walkthrough](docs/API.md)
* [Access control policies](docs/ACL.md)
* [Development, testing & production deployment](docs/DEVELOPMENT.md)
* [Roadmap](docs/ROADMAP.md)

## Join a device (Linux)
```bash
make deb && sudo dpkg -i dist/wiremesh_*_amd64.deb     # installs + starts wiremeshd
sudo wiremesh up --server https://vpn.example.com        # prints a link + code to approve in the dashboard
wiremesh status                                         # peers, direct/relay path, traffic
ssh nas.home.wm.internal                                # MagicDNS names (with systemd-resolved)
```
Unattended: `sudo wiremesh up --server … --auth-key wmk_…`. Without the daemon: `sudo wiremesh run --server …`.

## Quick start (development)
```bash
make dev-db && make test-integration
WIREMESH_DATABASE_URL=postgres://wiremesh:wiremesh@localhost:5432/wiremesh?sslmode=disable \
  ./bin/wiremesh-server create-admin --email you@example.com
make run      # then follow the curl walkthrough in docs/API.md
```

## Repository layout
```
cmd/wiremesh-server   control server entrypoint (serve | migrate | create-admin | version)
cmd/wiremesh          Linux client (up | status [--json] | logout)
cmd/wiremesh-relay    STUN server + encrypted packet relay
relay, pkg/relayproto relay server; relay frames and Ed25519 relay tokens
pkg/client/magicsock  WireGuard transport: one socket for WireGuard/disco/STUN, path selection, hole punching
pkg/stun, pkg/disco   STUN codec/server; encrypted path-discovery messages
pkg/protocol          wire types shared by server and clients (NetworkMap, keys, filter rules)
pkg/client            device engine: wireguard-go tunnel, packet filter + conntrack, control client
internal/acl          policy parser/validator/compiler
internal/coord        per-device network map builder
internal/config       WIREMESH_* environment configuration + validation
internal/db           pgx pool, embedded migrations, advisory-locked migration runner
internal/store        repositories: users, sessions, networks, members, devices, audit
internal/api          HTTP handlers (auth, networks, devices, admin); httpx; middleware
internal/auth         Argon2id passwords, tokens/CSRF, TOTP, SMTP mailer
internal/devices      device enrollment (auth keys, IP allocation, naming, credentials)
internal/ipam         IPv4 allocator, IPv6 ULA derivation
internal/secretbox    AES-256-GCM encryption for sensitive columns
deploy/               Dockerfile, docker-compose (prod + dev), Caddyfile
docs/                 architecture, development guide, roadmap
```

## License
Choose before publishing (Apache-2.0 or BSD-3-Clause recommended; wireguard-go is MIT).
