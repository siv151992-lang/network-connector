#!/usr/bin/env bash
# Backup/restore drill: proves a pg_dump of a live control server can be
# restored into an empty database and served again with all state intact:
# password logins, networks, auth keys, device credentials, audit logs and
# secrets encrypted with WIREMESH_SECRET_KEY.
#
# Usage: DB_ADMIN=postgres://postgres@localhost:5432/postgres scripts/backup-drill.sh
# Requires: go, curl, python3, psql, pg_dump, pg_restore.
set -euo pipefail

DB_ADMIN=${DB_ADMIN:-${WIREMESH_TEST_DATABASE_URL:-postgres://postgres@localhost:5432/postgres}}
SRC=wm_drill_src_$$ DST=wm_drill_dst_$$
WORK=$(mktemp -d)
PORT=$((20000 + RANDOM % 20000))
URL=http://127.0.0.1:$PORT API=http://127.0.0.1:$PORT/api/v1
PASS='Drill-Passw0rd-2026!'
SERVER_PID=

ok()   { echo "  ok   $*"; }
fail() { echo "  FAIL $*"; exit 1; }
cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null || true
  psql "$DB_ADMIN" -qc "DROP DATABASE IF EXISTS $SRC" -c "DROP DATABASE IF EXISTS $DST" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
dburl() { python3 -c "import sys,urllib.parse as u;p=u.urlparse(sys.argv[1]);print(p._replace(path='/'+sys.argv[2]).geturl())" "$DB_ADMIN" "$1"; }
json()  { python3 -c "import sys,json;d=json.load(sys.stdin);print(eval('d'+sys.argv[1]))" "$1"; }
key()   { head -c32 /dev/urandom | base64; }

go build -o "$WORK/wiremesh-server" ./cmd/wiremesh-server
export WIREMESH_HTTP_ADDR=127.0.0.1:$PORT WIREMESH_PUBLIC_URL=$URL WIREMESH_SECRET_KEY=$(key) \
       WIREMESH_LOG_FORMAT=text WIREMESH_AUTH_RATE_LIMIT_PER_MIN=600

start() { # database
  WIREMESH_DATABASE_URL=$(dburl "$1") "$WORK/wiremesh-server" serve >>"$WORK/server.log" 2>&1 & SERVER_PID=$!
  for _ in $(seq 100); do curl -fs "$URL/readyz" >/dev/null && return; sleep 0.1; done
  cat "$WORK/server.log"; fail "server did not start"
}
stop() { kill "$SERVER_PID"; wait "$SERVER_PID" 2>/dev/null || true; SERVER_PID=; }
login() {
  CSRF=$(curl -fs -c "$WORK/jar" -H 'Content-Type: application/json' \
    -d "{\"email\":\"admin@example.com\",\"password\":\"$PASS\"}" "$API/auth/login" | json "['csrf_token']")
}
call() { curl -fsS -b "$WORK/jar" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' "$@"; }

echo "== populate $SRC"
psql "$DB_ADMIN" -qc "CREATE DATABASE $SRC" -c "CREATE DATABASE $DST" >/dev/null
WIREMESH_DATABASE_URL=$(dburl $SRC) WIREMESH_ADMIN_PASSWORD="$PASS" "$WORK/wiremesh-server" create-admin --email admin@example.com >/dev/null
start $SRC
login
NID=$(call -d '{"name":"Drill"}' "$API/networks" | json "['network']['id']")
AKEY=$(call -d '{"reusable":true,"preauthorized":true}' "$API/networks/$NID/auth-keys" | json "['key']")
CRED=$(curl -fsS -H 'Content-Type: application/json' -d "{\"auth_key\":\"$AKEY\",\"node_key\":\"$(key)\",\"disco_key\":\"$(key)\",\"hostname\":\"drill-a\"}" \
  "$API/device/register" | json "['credential']")
# A device-code login approved but not yet collected: its credential is
# stored encrypted with WIREMESH_SECRET_KEY.
START=$(curl -fsS -H 'Content-Type: application/json' -d "{\"node_key\":\"$(key)\",\"disco_key\":\"$(key)\",\"hostname\":\"drill-b\"}" "$API/device/login/start")
CODE=$(echo "$START" | json "['code']"); POLL=$(echo "$START" | json "['poll_token']")
call -d "{\"code\":\"$CODE\",\"network_id\":\"$NID\"}" "$API/device/login/approve" >/dev/null
AUDIT_BEFORE=$(call "$API/networks/$NID/audit-logs" | json "['entries'].__len__()")
ok "network, auth key, 2 devices, $AUDIT_BEFORE audit entries"

echo "== backup (server running) and restore into $DST"
pg_dump -Fc -d "$(dburl $SRC)" -f "$WORK/backup.dump"
ok "dump $(du -h "$WORK/backup.dump" | cut -f1)"
stop
pg_restore --no-owner -d "$(dburl $DST)" "$WORK/backup.dump"
ok "restored"

echo "== verify the restored server"
start $DST
login && ok "admin password login"
[ "$(call "$API/networks" | json "['networks'][0]['id']")" = "$NID" ] && ok "network present" || fail "network missing"
[ "$(call "$API/networks/$NID/devices" | json "['devices'].__len__()")" = 2 ] && ok "both devices present" || fail "devices missing"
curl -fs -H "Authorization: Bearer $CRED" "$API/device/self" >/dev/null && ok "device credential still valid" || fail "device credential rejected"
curl -fsS -H 'Content-Type: application/json' -d "{\"auth_key\":\"$AKEY\",\"node_key\":\"$(key)\",\"disco_key\":\"$(key)\",\"hostname\":\"drill-c\"}" \
  "$API/device/register" >/dev/null && ok "auth key still valid" || fail "auth key rejected"
[ "$(curl -fsS -H 'Content-Type: application/json' -d "{\"poll_token\":\"$POLL\"}" "$API/device/login/poll" | json "['status']")" = approved ] \
  && ok "encrypted login credential decrypts with the same secret key" || fail "encrypted secret unreadable"
AUDIT_AFTER=$(call "$API/networks/$NID/audit-logs" | json "['entries'].__len__()")
[ "$AUDIT_AFTER" -ge "$AUDIT_BEFORE" ] && ok "audit log intact ($AUDIT_AFTER entries)" || fail "audit log lost"
echo "PASS: backup/restore drill"
