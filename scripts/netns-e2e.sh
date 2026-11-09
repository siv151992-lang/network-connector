#!/usr/bin/env bash
# End-to-end tunnel test with real WireGuard (wireguard-go) tunnels.
#
# Topology: a bridge in the root namespace (10.99.0.1, runs the control
# server) and two network namespaces "wm-a" / "wm-b" (10.99.0.11 / .12), each
# running the real `wiremesh` client. Checks:
#   1. both devices enroll with an auth key and get 100.64.x / fd.. addresses
#   2. A <-> B ping over IPv4 and IPv6 through the tunnel
#   3. a restrictive ACL is pushed: A may only reach B on TCP 8080
#      -> ping A->B blocked, TCP 8080 allowed, TCP 8081 blocked,
#         B->A blocked (replies to A's connection still flow)
#   4. revoking B shuts B's client down and removes B from A's map
#
# Requirements: Linux, root, iproute2, ping, python3, curl, PostgreSQL.
# Usage: sudo WIREMESH_TEST_DATABASE_URL=postgres://user@host:5432/postgres scripts/netns-e2e.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d /tmp/wm-netns.XXXXXX)
DB_ADMIN=${WIREMESH_TEST_DATABASE_URL:?set WIREMESH_TEST_DATABASE_URL (role that can CREATE DATABASE)}
DB_NAME=wm_netns_$$
SERVER_IP=10.99.0.1
PORT=18090
URL=http://$SERVER_IP:$PORT
API=$URL/api/v1
PASS="netns test passphrase"
PIDS=()

log()  { printf '\n\033[1;34m== %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32m✓ %s\033[0m\n' "$*"; }
fail() { printf '   \033[31m✗ %s\033[0m\n' "$*"; dump_logs; exit 1; }
dump_logs() {
  for f in "$WORK"/*.log; do echo "--- $f (tail)"; tail -n 25 "$f"; done
}

cleanup() {
  set +e
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
  sleep 1
  ip netns del wm-a 2>/dev/null; ip netns del wm-b 2>/dev/null
  ip link del wmbr0 2>/dev/null
  psql "$DB_ADMIN" -qc "DROP DATABASE IF EXISTS $DB_NAME WITH (FORCE)" >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }

log "build"
(cd "$ROOT" && go build -o "$WORK/wiremesh-server" ./cmd/wiremesh-server && go build -o "$WORK/wiremesh" ./cmd/wiremesh)
ok "binaries built"

log "network namespaces"
ip link add wmbr0 type bridge && ip addr add $SERVER_IP/24 dev wmbr0 && ip link set wmbr0 up
for n in a b; do
  ip netns add wm-$n
  ip link add veth-$n type veth peer name eth0 netns wm-$n
  ip link set veth-$n master wmbr0 up
  ip -n wm-$n link set lo up
  ip -n wm-$n link set eth0 up
done
ip -n wm-a addr add 10.99.0.11/24 dev eth0
ip -n wm-b addr add 10.99.0.12/24 dev eth0
ip netns exec wm-a ping -c1 -W2 10.99.0.12 >/dev/null && ok "underlay: wm-a reaches wm-b on 10.99.0.0/24"

log "control server"
psql "$DB_ADMIN" -qc "CREATE DATABASE $DB_NAME" >/dev/null
DB_URL=$(python3 -c "import sys,urllib.parse as u;p=u.urlparse(sys.argv[1]);print(p._replace(path='/$DB_NAME').geturl())" "$DB_ADMIN")
export WIREMESH_DATABASE_URL=$DB_URL WIREMESH_HTTP_ADDR=$SERVER_IP:$PORT WIREMESH_PUBLIC_URL=$URL \
       WIREMESH_SECRET_KEY=$(head -c32 /dev/urandom | base64) WIREMESH_LOG_FORMAT=text \
       WIREMESH_AUTH_RATE_LIMIT_PER_MIN=600
WIREMESH_ADMIN_PASSWORD="$PASS" "$WORK/wiremesh-server" create-admin --email admin@example.com >/dev/null
"$WORK/wiremesh-server" serve >"$WORK/server.log" 2>&1 & PIDS+=($!)
for _ in $(seq 50); do curl -fs $URL/readyz >/dev/null && break; sleep 0.2; done
ok "server ready at $URL"

json() { python3 -c "import sys,json;d=json.load(sys.stdin);print(eval('d'+sys.argv[1]))" "$1"; }
CSRF=$(curl -fs -c "$WORK/jar" -H 'Content-Type: application/json' \
  -d "{\"email\":\"admin@example.com\",\"password\":\"$PASS\"}" $API/auth/login | json "['csrf_token']")
call() { curl -fsS -b "$WORK/jar" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' "$@"; }
NID=$(call -d '{"name":"Netns Test"}' $API/networks | json "['network']['id']")
KEY=$(call -d '{"reusable":true,"preauthorized":true}' $API/networks/$NID/auth-keys | json "['key']")
ok "network $NID and auth key created"

log "start clients"
start_client() { # name iface
  ip netns exec wm-$1 env WIREMESH_AUTH_KEY="$KEY" "$WORK/wiremesh" up --server $URL \
    --state "$WORK/$1.json" --iface "$2" --hostname "node-$1" >"$WORK/client-$1.log" 2>&1 &
  PIDS+=($!)
}
start_client a wma0
start_client b wmb0

wait_for() { # description, command...
  local d=$1; shift
  for _ in $(seq 60); do "$@" >/dev/null 2>&1 && { ok "$d"; return 0; }; sleep 0.5; done
  fail "$d"
}
peers_of() { grep -c "network map applied.*peers=1" "$WORK/client-$1.log"; }
wait_for "A sees B as a peer" peers_of a
wait_for "B sees A as a peer" peers_of b

A4=$(ip netns exec wm-a ip -4 -o addr show dev wma0 | awk '{print $4}' | cut -d/ -f1)
B4=$(ip netns exec wm-b ip -4 -o addr show dev wmb0 | awk '{print $4}' | cut -d/ -f1)
A6=$(ip netns exec wm-a ip -6 -o addr show dev wma0 scope global | awk '{print $4}' | cut -d/ -f1)
B6=$(ip netns exec wm-b ip -6 -o addr show dev wmb0 scope global | awk '{print $4}' | cut -d/ -f1)
echo "   A = $A4 / $A6     B = $B4 / $B6"

log "connectivity through the tunnel"
wait_for "ping A -> B over IPv4 ($B4)" ip netns exec wm-a ping -c1 -W1 "$B4"
wait_for "ping B -> A over IPv4 ($A4)" ip netns exec wm-b ping -c1 -W1 "$A4"
if [ -d /proc/sys/net/ipv6 ]; then
  wait_for "ping A -> B over IPv6 ($B6)" ip netns exec wm-a ping -6 -c1 -W1 "$B6"
else
  echo "   - kernel has no IPv6: skipping the IPv6 ping (clients run IPv4-only)"
fi
# Prove the packets really travel inside WireGuard: the handshake happened.
ip netns exec wm-a "$WORK/wiremesh" status --state "$WORK/a.json" --iface wma0 | tee "$WORK/status-a.txt"
grep -q "ago" "$WORK/status-a.txt" && ok "WireGuard handshake completed (status shows it)" || fail "no handshake"

log "access control"
ip netns exec wm-b python3 -m http.server 8080 --bind "$B4" >"$WORK/http8080.log" 2>&1 & PIDS+=($!)
ip netns exec wm-b python3 -m http.server 8081 --bind "$B4" >"$WORK/http8081.log" 2>&1 & PIDS+=($!)
sleep 1
POLICY="{\"version\":0,\"policy\":{\"acls\":[{\"action\":\"accept\",\"src\":[\"$A4\"],\"dst\":[\"$B4:8080\"],\"proto\":\"tcp\"}]}}"
BEFORE=$(grep -c "network map applied" "$WORK/client-b.log")
call -X PUT -d "$POLICY" $API/networks/$NID/acl >/dev/null && ok "policy pushed: only A -> B tcp/8080"
new_map_on_b() { [ "$(grep -c "network map applied" "$WORK/client-b.log")" -gt "$BEFORE" ]; }
wait_for "B applied a new map with the new filter" new_map_on_b
sleep 1
blocked() { ! "$@"; }
wait_for "ping A -> B now blocked" blocked ip netns exec wm-a ping -c1 -W1 "$B4"
ip netns exec wm-a curl -fs -m 5 "http://$B4:8080/" >/dev/null && ok "TCP A -> B:8080 allowed (replies pass A's filter via conntrack)" || fail "TCP 8080 blocked"
ip netns exec wm-a curl -fs -m 3 "http://$B4:8081/" >/dev/null && fail "TCP 8081 should be blocked" || ok "TCP A -> B:8081 blocked"
ip netns exec wm-b ping -c1 -W1 "$A4" >/dev/null && fail "B -> A should be blocked" || ok "ping B -> A blocked (no rule toward A)"

log "revocation"
BID=$(python3 -c "import json;print(json.load(open('$WORK/b.json'))['device_id'])")
call -X POST $API/networks/$NID/devices/$BID/revoke >/dev/null && ok "B revoked by admin"
wait_for "B's client shut down" grep -q "credential revoked" "$WORK/client-b.log"
wait_for "A's map no longer contains B" grep -q "network map applied.*peers=0" "$WORK/client-a.log"
wait_for "tunnel to B is gone" blocked ip netns exec wm-a ping -c1 -W1 "$B4"

log "ALL CHECKS PASSED"
