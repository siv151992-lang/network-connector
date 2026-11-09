# Development Roadmap

Each phase ends with code that builds, tests that pass, and a "how to verify" section in `DEVELOPMENT.md`.

| Phase | Deliverable | Exit criteria |
|---|---|---|
| **1. Architecture** ✅ | `docs/ARCHITECTURE.md`, repo layout, config conventions | Design reviewed; schema and API agreed |
| **2. Backend API & DB** ✅ | `wiremesh-server` with config, logging, middleware (request ID, recovery, security headers, CORS, rate limiting, body limits), JSON error envelope, full schema migration, migration runner with checksums + advisory lock, repositories for users, sessions, networks, members, devices, audit logs; column encryption helper; Docker Compose for dev | `make test` and `make test-integration` pass against real PostgreSQL; `/healthz` and `/readyz` respond |
| **3. Auth & device registration** ✅ | Argon2id passwords, register/verify/login/logout, sessions + CSRF, TOTP, password reset, SMTP mailer, RBAC middleware, auth keys, `POST /device/register`, device approve/reject/revoke/delete | E2E HTTP tests: register → verify → login → create auth key → register device → approve. The IPv4/IPv6 allocator was pulled forward from Phase 4 because registration needs addresses. The device-code login flow for headless clients moved to Phase 9 (the CLI is its first user). |
| **4. WireGuard & ACLs** ✅ | `pkg/protocol` NetworkMap types, ACL parser/compiler, client engine on wireguard-go + TUN, Linux bring-up | Two Linux network namespaces ping each other over WireGuard with addresses issued by the server: **`scripts/netns-e2e.sh`** (also checks ACL enforcement and revocation). Maps are polled with ETags until Phase 5's push stream. |
| **5. Peer discovery & NAT traversal** ✅ | WebSocket stream hub, presence, STUN client/server, disco ping/pong, call-me-maybe, endpoint selection, roaming | Two namespaces behind separate iptables MASQUERADE NATs connect directly: **`scripts/nat-e2e.sh`**. Includes low-TTL hole punching, synchronized quiescing for Linux conntrack deadlocks, and roaming recovery (~1 min, the relay will bridge that gap). Symmetric NATs need the Phase 6 relay. |
| 6. Relay | `wiremesh-relay`, relay tokens, relay framing, meshconn relay path, automatic upgrade to direct | Same test with UDP between NATs blocked: traffic flows via relay, then upgrades when unblocked |
| 7. Android | Compose app, login (device-code flow), `VpnService`, gomobile core, always-on VPN support | Phone pings a Linux peer; survives Wi-Fi ↔ LTE switch |
| 8. Windows | Windows service (Wintun), Wails GUI, MSI via WiX | Windows host pings Linux and Android peers |
| 9. Linux client | `wiremeshd` systemd service, CLI, device-code login flow, DNS (systemd-resolved), subnet routes, optional kernel mode, .deb/.rpm | `wiremesh up/status/down` on Debian/Fedora |
| 10. Dashboard | All 10 screens, dark/light theme, live status via WebSocket | Playwright E2E across main flows |
| 11. Security & production | gosec/govulncheck/trivy in CI, fuzzing for parsers (STUN, relay frames, ACL), load tests, backup/restore drills, hardening guide | Checklist in `docs/SECURITY.md` complete |
