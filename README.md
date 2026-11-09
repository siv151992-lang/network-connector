# WireMesh

A self-hostable private mesh VPN built on WireGuard: a Go control server
coordinates your devices, and traffic flows end-to-end encrypted directly
between them, or through an encrypted relay when NATs block direct paths.

> **Status: Phases 1–2 complete** (architecture, control-server foundation,
> database). The control server runs and is tested, but devices can't join
> yet. See [docs/ROADMAP.md](docs/ROADMAP.md).

* [Architecture, schema, API design](docs/ARCHITECTURE.md)
* [Development, testing & production deployment](docs/DEVELOPMENT.md)
* [Roadmap](docs/ROADMAP.md)

## Quick start (development)
```bash
make dev-db && make test-integration && make run
curl localhost:8080/readyz
```

## Repository layout
```
cmd/wiremesh-server   control server entrypoint (serve | migrate up | migrate status | version)
internal/config       WIREMESH_* environment configuration + validation
internal/db           pgx pool, embedded migrations, advisory-locked migration runner
internal/store        repositories: users, sessions, networks, members, devices, audit
internal/api          HTTP handler; httpx (JSON/errors) and middleware
internal/secretbox    AES-256-GCM encryption for sensitive columns
deploy/               Dockerfile, docker-compose (prod + dev), Caddyfile
docs/                 architecture, development guide, roadmap
```

## License
Choose before publishing (Apache-2.0 or BSD-3-Clause recommended; wireguard-go is MIT).
