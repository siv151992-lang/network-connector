# Security

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's **Security → Report a vulnerability** on this repository. Don't open a public issue. Include the steps to reproduce, the affected version (`wiremesh-server version`) and the impact. We aim to acknowledge reports within 3 days.

## Threat model

| Asset | Protection |
|---|---|
| Traffic between devices | WireGuard (Noise IK, ChaCha20-Poly1305). Private keys are generated on the device and never leave it. The server and relays only see public keys. |
| Who may talk to whom | Default-deny ACL, compiled per device by the server. Each **receiving** device enforces its own inbound packet filter, so a compromised peer can't bypass the filter by sending crafted packets. |
| Control-plane accounts | Argon2id passwords, optional TOTP (with replay protection), session cookies scoped to `__Host-` with an HMAC CSRF token, and rate-limited login. |
| Device credentials | Random bearer tokens (`wmd_`); only their hashes are stored. They are revocable: revocation disconnects the device's live stream immediately. |
| Secrets at rest | TOTP secrets and pending device-login credentials are encrypted with AES-GCM under `WIREMESH_SECRET_KEY`, bound to their row (associated data). |
| Relay | Forwards only between devices of the same network. It needs Ed25519 tokens signed by the control server (key derived via HKDF from `WIREMESH_SECRET_KEY`) and carries only WireGuard ciphertext. |
| Endpoint spoofing | The data path accepts packets only from addresses verified by disco (NaCl box ping/pong). The server stamps call-me-maybe senders and checks them against the ACL. |

**What a compromised control server can do:** add devices to a network and change ACLs, so it is fully trusted for *authorization*. It can't decrypt traffic between devices, and it can't impersonate an existing device's WireGuard key. **What a compromised relay can do:** drop or delay packets. It can't read or forge them.

## Hardening checklist

Status of the Phase 11 checklist. Each item is enforced in CI (`.github/workflows/ci.yml`) unless noted otherwise.

- [x] **Static analysis:** `gofmt`, `go vet`, `staticcheck` (Linux and Windows builds).
- [x] **Dependency scanning:** `govulncheck` for Go, `npm audit --omit=dev` for the dashboard (0 production advisories), Trivy for the server image (HIGH/CRITICAL fail the build).
- [x] **Fuzzing** of every parser that takes untrusted input:
  - ACL policies (`internal/acl`)
  - decrypted peer packets / inbound filter (`pkg/client`)
  - MagicDNS queries (`pkg/client`)
  - relay frames and tokens (`pkg/relayproto`)
  - STUN (`pkg/stun`)
  - disco (`pkg/disco`)

  Fuzzing found and fixed relay-token malleability: tokens with non-canonical base64 or embedded CR/LF were accepted. The crashers are kept as regression seeds in `pkg/relayproto/testdata/fuzz`.
- [x] **Real-network tests:** WireGuard tunnels, ACL enforcement, revocation, NAT traversal and relay fallback through real NAT routers (`scripts/netns-e2e.sh`, `scripts/nat-e2e.sh`).
- [x] **Load:** `BenchmarkNetmap1000` recomputes visibility and filters for every device of a 1000-device network in ≈0.6 s on 4 vCPUs. That cost is paid only when a network changes, not per packet.
- [x] **Backup/restore drill:** `scripts/backup-drill.sh` dumps a live server, restores it into an empty database and verifies logins, devices, auth keys, encrypted secrets and the audit log.
- [x] **Browser security:** strict CSP (no inline scripts or styles, `frame-ancestors 'none'`), `nosniff`, `Referrer-Policy: no-referrer` and HSTS (Caddy for the dashboard; the API sets `X-Frame-Options: DENY` too). The dashboard E2E runs under the production CSP.
- [x] **Least privilege:** the server and relay run as non-root in containers. `wiremeshd` uses a hardened systemd unit, and its local socket is limited to root plus the `wiremesh` group (explicit ACLs on Windows).
- [ ] **Not done yet:** running the Windows client on real Windows (only compile-verified), an external penetration test, and reproducible builds/signing of release artifacts.

## Operating securely

- Generate `WIREMESH_SECRET_KEY` with `openssl rand -base64 32` and back it up **separately** from database dumps. Without it, encrypted secrets in a restored database can't be read. Anyone holding both can mint relay tokens.
- Keep `WIREMESH_ALLOW_REGISTRATION=false` unless you want open sign-up, and require TOTP for admins.
- Expose only 80/443 (TCP), 3478 (UDP, STUN) and the relay through Caddy. PostgreSQL and Redis must not be reachable from outside (see the firewall section in `DEVELOPMENT.md`).
- Review the audit log (`/audit`) after membership or ACL changes. Revoke lost devices from the dashboard. Revocation takes effect immediately.
- Back up daily, copy backups off-site, and run `scripts/backup-drill.sh` against a recent dump regularly.

## Known accepted risks

- `vite`/`esbuild` advisories affect only the local **dev server**. The production dashboard is static files served by Caddy, so these are kept on vite 5 until a major upgrade.
- Device-code login codes have a ~2^34 search space, are valid for 10 minutes and are rate-limited. Approving a code also requires a signed-in network member, who sees the device's hostname and OS before approving.
