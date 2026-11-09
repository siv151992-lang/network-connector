# WireMesh

A self-hostable private mesh VPN built on WireGuard: a Go control server
coordinates your devices, and traffic flows end-to-end encrypted directly
between them, or through an encrypted relay when NATs block direct paths.

> **Status: Phases 1–3 complete.** Accounts (email verification, TOTP 2FA,
> password reset), networks, roles, auth keys, device enrollment with private
> IP allocation, approval and revocation all work over the API. The WireGuard
> data plane comes next (Phase 4). See [docs/ROADMAP.md](docs/ROADMAP.md).

* [Architecture, schema, API design](docs/ARCHITECTURE.md)
* [API reference + curl walkthrough](docs/API.md)
* [Development, testing & production deployment](docs/DEVELOPMENT.md)
* [Roadmap](docs/ROADMAP.md)

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
