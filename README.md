# WireMesh

A self-hostable private mesh VPN built on WireGuard: a Go control server
coordinates your devices, and traffic flows end-to-end encrypted directly
between them, or through an encrypted relay when NATs block direct paths.

> **Status: Phases 1–4 complete.** Accounts, networks, roles, auth keys and
> device enrollment work over the API, and the Linux client brings up **real
> WireGuard tunnels** between devices with ACL-enforced packet filtering.
> Devices currently connect directly over reachable addresses (same LAN or a
> public IP); NAT traversal and relays come in Phases 5–6.
> See [docs/ROADMAP.md](docs/ROADMAP.md).

* [Architecture, schema, API design](docs/ARCHITECTURE.md)
* [API reference + curl walkthrough](docs/API.md)
* [Access control policies](docs/ACL.md)
* [Development, testing & production deployment](docs/DEVELOPMENT.md)
* [Roadmap](docs/ROADMAP.md)

## Join a device (Linux)
```bash
go build -o wiremesh ./cmd/wiremesh
sudo WIREMESH_AUTH_KEY=wmk_… ./wiremesh up --server https://vpn.example.com
sudo ./wiremesh status
```

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
cmd/wiremesh          Linux client (up | status | logout)
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
