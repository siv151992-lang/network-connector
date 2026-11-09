# WireMesh API Reference (v1)

Base URL: `https://<your-domain>/api/v1`. All bodies are JSON; unknown fields are rejected.

## Conventions

**Errors** always look like:
```json
{"error": {"code": "validation_failed", "message": "request validation failed",
           "fields": {"password": "password must be at least 10 characters"},
           "request_id": "9f2c…"}}
```
| Status | Typical `code` |
|---|---|
| 400 | `bad_request` (malformed JSON, invalid/expired link token) |
| 401 | `unauthorized`, `invalid_credentials`, `mfa_required`, `invalid_code`, `invalid_auth_key` |
| 403 | `forbidden`, `csrf_failed`, `email_not_verified`, `account_disabled`, `registration_disabled`, `invalid_password` |
| 404 | `not_found` (also for resources you aren't allowed to see) |
| 409 | `conflict`, `address_space_exhausted` |
| 413 / 415 | `body_too_large` / `unsupported_media_type` |
| 422 | `validation_failed` (with `fields`), `invalid` (business rule, e.g. "a network must keep at least one owner") |
| 429 | `rate_limited` (see `Retry-After`) |

**Dashboard authentication** uses an `HttpOnly; SameSite=Strict` session cookie
(`__Host-wm_session` over HTTPS). Login returns a `csrf_token`. Every
`POST/PUT/PATCH/DELETE` with the cookie must send it as `X-CSRF-Token`, and a
browser `Origin` header, if present, must match the server's public URL.

**Device authentication** uses `Authorization: Bearer wmd_…`, the credential
returned once by `/device/register`. No CSRF token is needed.

**Rate limits:** a general per-IP limit applies to everything. A stricter one
(`WIREMESH_AUTH_RATE_LIMIT_PER_MIN`, default 12/min) applies to login,
MFA, register, verify, password reset and device registration. After 10
consecutive failed password or TOTP attempts an account is locked for 15
minutes. Responses during lockout look like a wrong password.

**Roles:** network roles are `owner` > `admin` > `member`, plus `auditor`
(read-only: sees all devices and the audit log, can't add devices). System role
`admin` grants `/admin/*`.

---

## Authentication

| Method & path | Auth | Body → Response |
|---|---|---|
| `POST /auth/register` | — | `{email, password, display_name?}` → `202` (verification on) or `201 {user}`. Disabled unless `WIREMESH_ALLOW_REGISTRATION=true`. Existing emails also get `202`; the owner is emailed instead (no account enumeration). |
| `POST /auth/verify-email` | — | `{token}` → `200`. Tokens are single-use, valid 24 h. |
| `POST /auth/verify-email/resend` | — | `{email}` → always `202` |
| `POST /auth/login` | — | `{email, password}` → `200 {user, csrf_token, mfa_required}` + cookie. With TOTP enabled the cookie is a 10-minute *partial* session. |
| `POST /auth/login/mfa` | partial session + CSRF | `{code}` → `200 {user, csrf_token}`; issues a fresh full session. Codes are single-use. |
| `POST /auth/logout` | session | → `204` |
| `GET /auth/me` | session | → `{user, csrf_token}` (use this to recover the CSRF token after a page reload) |
| `PATCH /auth/me` | session | `{display_name}` → `{user}` |
| `POST /auth/password/change` | session | `{current_password, new_password}` → revokes your other sessions |
| `POST /auth/password/forgot` | — | `{email}` → always `202`; link valid 1 h |
| `POST /auth/password/reset` | — | `{token, new_password}` → revokes all sessions, marks email verified |
| `GET /auth/sessions` | session | → `{sessions:[{…, current}]}` |
| `DELETE /auth/sessions/{id}` | session | → `204` |
| `POST /auth/mfa/totp/setup` | session | `{password}` → `{secret, otpauth_uri}` (render the URI as a QR code) |
| `POST /auth/mfa/totp/enable` | session | `{code}` → `200` |
| `POST /auth/mfa/totp/disable` | session | `{password, code}` → `200` |

## Networks and members

| Method & path | Role | Notes |
|---|---|---|
| `GET /networks` | any user | your networks, each with your `role` |
| `POST /networks` | any user | `{name, slug?, device_approval_required? (true), key_expiry_days? (180, 0 = never)}`. You become owner. Address space: `WIREMESH_IPV4_RANGE` + a random IPv6 ULA `/48`. |
| `GET /networks/{nid}` | member | `{network, role}`; non-members get 404 |
| `PATCH /networks/{nid}` | admin | `{name?, device_approval_required?, key_expiry_days?}` |
| `DELETE /networks/{nid}` | owner | deletes devices, keys and policy |
| `GET /networks/{nid}/members` | member | |
| `POST /networks/{nid}/members` | admin | `{email, role}`; the user must already have an account; only owners add owners |
| `PATCH /networks/{nid}/members/{uid}` | admin | `{role}`; only owners grant or remove `owner`; the last owner can't be demoted |
| `DELETE /networks/{nid}/members/{uid}` | admin, or yourself (leave) | also deletes that user's devices in the network |
| `GET /networks/{nid}/audit-logs?action=&before=&limit=` | admin, auditor | newest first; page with `before=<next_before>` |

## Auth keys (unattended enrollment)

| Method & path | Role | Notes |
|---|---|---|
| `GET /networks/{nid}/auth-keys` | admin | hashes are never returned |
| `POST /networks/{nid}/auth-keys` | admin | `{description?, reusable?, ephemeral?, preauthorized?, tags?: ["tag:servers"], expires_in_hours? (24, max 2160)}` → `201 {auth_key, key}`. **`key` is shown only once.** |
| `DELETE /networks/{nid}/auth-keys/{kid}` | admin | revoke |

* `reusable`: can enroll many devices (otherwise single-use).
* `preauthorized`: devices skip admin approval.
* `ephemeral`: the device is deleted when it logs out (CI runners, containers).
* `tags`: applied to enrolled devices for ACLs (Phase 4).

## Devices: dashboard

| Method & path | Who | Notes |
|---|---|---|
| `GET /networks/{nid}/devices?status=` | member | members see their own devices; admins and auditors see all |
| `GET /networks/{nid}/devices/{did}` | same visibility | |
| `PATCH /networks/{nid}/devices/{did}` | owner of device or admin (`name`); admin (`tags`) | `{name?, tags?}` |
| `DELETE /networks/{nid}/devices/{did}` | owner of device or admin | frees its addresses |
| `POST …/devices/{did}/approve` | admin | `pending`/`rejected` → `approved` |
| `POST …/devices/{did}/reject` | admin | `pending` → `rejected` |
| `POST …/devices/{did}/revoke` | admin or device owner | terminal; the device's credential stops working immediately |

## Devices: control plane (used by clients)

| Method & path | Auth | Notes |
|---|---|---|
| `POST /device/register` | `auth_key` in body, **or** dashboard session + CSRF + `network_id` | `{node_key, disco_key, hostname?, name?, os?, os_version?, client_version?}`. Keys are WireGuard-format base64 public keys; **private keys never leave the device**. → `201 {device, credential, network}`. Store `credential` securely: it's shown once. |
| `GET /device/self` | device | the device's record and status (poll this while `pending`) |
| `POST /device/rotate-key` | device | `{node_key, disco_key}`; approved devices only; renews key expiry |
| `POST /device/logout` | device | clears the credential (ephemeral devices are deleted) |

| `GET /device/netmap` | device | the compiled network map: `{version, network, self, peers[], packet_filter[], poll_interval}`. Send `If-None-Match: "<version>"` to get `304` when nothing changed. `403 device_not_approved` while pending. |
| `POST /device/endpoints` | device | `{endpoints: ["192.0.2.1:51820", …], listen_port}`: where peers can reach this device (max 16; loopback, link-local, multicast rejected) |

| `GET /device/stream` | device | WebSocket control stream, see below |

Planned: (WebSocket network map, Phase 5),
`POST /device/relay-token` (Phase 6), and the device-code login flow for
headless clients (Phase 9).

### Control stream

`GET /api/v1/device/stream` with `Authorization: Bearer wmd_…` upgrades to a
WebSocket (`403 device_not_approved` while pending). Frames are JSON:

| Direction | `type` | Body |
|---|---|---|
| server → device | `map` | `{"map": NetworkMap}`: on connect and on every change (devices joining or leaving, approval, presence, endpoints, ACL, settings) |
| server → device | `call_me_maybe` | `{"call_me_maybe": {"from": <peer node key>, "endpoints": [...], "quiesce": bool}}`: probe this peer now. `from` is set by the server from the authenticated sender. Forwarded only between devices the ACL lets see each other |
| server → device | `revoked` | the credential was revoked; the device must shut down |
| device → server | `endpoints` | `{"endpoints": {"endpoints": [...], "listen_port": n}}` |
| device → server | `call_me_maybe` | `{"call_me_maybe": {"to": <peer node key>, "endpoints": [...], "quiesce": bool}}` (rate-limited) |

The server pings every 30 s, and holding the stream is what makes a device
`online` (also shown on `GET …/devices`). Devices fall back to reconnecting
with exponential backoff, and the tunnel keeps running on the last map.

## Access control

Details and policy syntax: [ACL.md](ACL.md).

| Method & path | Role | Notes |
|---|---|---|
| `GET /networks/{nid}/acl` | member | `{policy, version, is_default}` |
| `PUT /networks/{nid}/acl` | admin | `{version, policy}`; `version` must equal the stored one (`409 stale_version` otherwise); `422 invalid_policy` lists every problem |
| `POST /networks/{nid}/acl/test` | admin, auditor | `{src, dst, proto?, port?, policy?}`: src/dst are device names, ids or addresses; an optional draft `policy` is evaluated without saving → `{allowed}` |

## System administration

| Method & path | Notes |
|---|---|
| `GET /admin/users?limit=&offset=` | `{users, total}` |
| `POST /admin/users` | `{email, password, display_name?, system_role?: user\|admin}`: creates a verified account |
| `PATCH /admin/users/{uid}` | `{disabled?, system_role?}`: disabling revokes all sessions; you can't change yourself |

---

## Walkthrough with curl

```bash
B=https://vpn.example.com/api/v1
# 1. Sign in (cookie jar + CSRF token)
CSRF=$(curl -s -c jar -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"…"}' $B/auth/login | jq -r .csrf_token)

# 2. Create a network
NID=$(curl -s -b jar -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' \
  -d '{"name":"Home"}' $B/networks | jq -r .network.id)

# 3. Create a single-use, pre-approved auth key
KEY=$(curl -s -b jar -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' \
  -d '{"preauthorized":true}' $B/networks/$NID/auth-keys | jq -r .key)

# 4. On the device: generate WireGuard keys locally and enroll
wg genkey | tee node.key | wg pubkey > node.pub
wg genkey | wg pubkey > disco.pub
curl -s -H 'Content-Type: application/json' -d "{\"auth_key\":\"$KEY\",
  \"node_key\":\"$(cat node.pub)\",\"disco_key\":\"$(cat disco.pub)\",\"hostname\":\"$(hostname)\"}" \
  $B/device/register
# -> {"device":{"ipv4":"100.64.0.1","ipv6":"fd…::6440:1","status":"approved",…},"credential":"wmd_…"}
```
