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
  ip netns del wm-a 2>/dev/null; ip netns del wm-b 2>/dev/null; ip netns del wm-c 2>/dev/null
  ip link del wmbr0 2>/dev/null
  psql "$DB_ADMIN" -qc "DROP DATABASE IF EXISTS $DB_NAME WITH (FORCE)" >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }

log "build"
(cd "$ROOT" && for b in wiremesh-server wiremesh wiremeshd; do go build -o "$WORK/$b" ./cmd/$b; done)
ok "binaries built"

log "network namespaces"
ip link add wmbr0 type bridge && ip addr add $SERVER_IP/24 dev wmbr0 && ip link set wmbr0 up
for n in a b c; do
  ip netns add wm-$n
  ip link add veth-$n type veth peer name eth0 netns wm-$n
  ip link set veth-$n master wmbr0 up
  ip -n wm-$n link set lo up
  ip -n wm-$n link set eth0 up
done
ip -n wm-a addr add 10.99.0.11/24 dev eth0
ip -n wm-b addr add 10.99.0.12/24 dev eth0
ip -n wm-c addr add 10.99.0.13/24 dev eth0
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
start_client() { # name iface: wiremeshd in the namespace, then `wiremesh up` through its socket
  ip netns exec wm-$1 "$WORK/wiremeshd" --state "$WORK/$1.json" --socket "$WORK/$1.sock" --iface "$2" >"$WORK/client-$1.log" 2>&1 &
  PIDS+=($!)
  for _ in $(seq 50); do [ -S "$WORK/$1.sock" ] && break; sleep 0.1; done
  ip netns exec wm-$1 "$WORK/wiremesh" up --socket "$WORK/$1.sock" --server $URL --auth-key "$KEY" --hostname "node-$1" --timeout 30s
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
ip netns exec wm-a "$WORK/wiremesh" status --socket "$WORK/a.sock" | tee "$WORK/status-a.txt"
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
b_says_revoked() { ip netns exec wm-b "$WORK/wiremesh" status --socket "$WORK/b.sock" | grep -q "revoked"; }
wait_for "wiremesh status on B explains the revocation" b_says_revoked
wait_for "A's map no longer contains B" grep -q "network map applied.*peers=0" "$WORK/client-a.log"
wait_for "tunnel to B is gone" blocked ip netns exec wm-a ping -c1 -W1 "$B4"

log "Linux client: device-code login, MagicDNS, down/up, logout"
call -X PUT -d '{"version":1,"policy":{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}}' $API/networks/$NID/acl >/dev/null
ip netns exec wm-c "$WORK/wiremeshd" --state "$WORK/c.json" --socket "$WORK/c.sock" --iface wmc0 >"$WORK/client-c.log" 2>&1 & PIDS+=($!)
for _ in $(seq 50); do [ -S "$WORK/c.sock" ] && break; sleep 0.1; done
ip netns exec wm-c "$WORK/wiremesh" up --socket "$WORK/c.sock" --server $URL --hostname node-c --timeout 60s >"$WORK/up-c.out" 2>&1 & UP=$!
wait_for "\`wiremesh up\` without an auth key prints a login link and code" grep -q "confirm the code" "$WORK/up-c.out"
CODE=$(grep -oE '[A-Z]{4}-[A-Z]{4}' "$WORK/up-c.out" | head -1)
grep -q "/activate?code=$CODE" "$WORK/up-c.out" && ok "login link points at the dashboard: /activate?code=$CODE"
call -d "{\"code\":\"$CODE\",\"network_id\":\"$NID\"}" $API/device/login/approve >/dev/null && ok "user approved the code (as in the dashboard)"
wait "$UP" || fail "\`wiremesh up\` failed: $(cat "$WORK/up-c.out")"
ok "\`wiremesh up\` finished: $(grep 'connected to' "$WORK/up-c.out")"
C4=$(ip netns exec wm-c ip -4 -o addr show dev wmc0 | awk '{print $4}' | cut -d/ -f1)
wait_for "C reaches A over the tunnel" ip netns exec wm-c ping -c1 -W1 "$A4"
dnsq() { # ns server name -> first A record
  ip netns exec "$1" python3 -c "
import socket,struct,sys
srv,name=sys.argv[1],sys.argv[2]
q=struct.pack('>HHHHHH',0x1234,0x0100,1,0,0,0)+b''.join(bytes([len(l)])+l.encode() for l in name.split('.'))+b'\x00'+struct.pack('>HH',1,1)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);s.sendto(q,(srv,53));r=s.recv(512)
if struct.unpack('>H',r[6:8])[0]==0: sys.exit(1)
print(socket.inet_ntoa(r[-4:]))" "$2" "$3"
}
GOT=$(dnsq wm-c "$C4" "node-a.netns-test.wm.internal")
[ "$GOT" = "$A4" ] && ok "MagicDNS: node-a.netns-test.wm.internal -> $GOT" || fail "MagicDNS answered '$GOT', expected $A4"
dnsq wm-c "$C4" "nothere.netns-test.wm.internal" >/dev/null 2>&1 && fail "unknown name resolved" || ok "MagicDNS: unknown names get no answer"
ip netns exec wm-c "$WORK/wiremesh" status --socket "$WORK/c.sock" | tee "$WORK/status-c.txt" | grep -q "node-a" && ok "\`wiremesh status\` lists peers"

ip netns exec wm-c "$WORK/wiremesh" down --socket "$WORK/c.sock" >/dev/null
ip netns exec wm-c ip link show wmc0 >/dev/null 2>&1 && fail "interface still present after down" || ok "\`wiremesh down\` removed the tunnel interface"
pkill -f -- "--socket $WORK/c.sock" || true; sleep 1
ip netns exec wm-c "$WORK/wiremeshd" --state "$WORK/c.json" --socket "$WORK/c.sock" --iface wmc0 >>"$WORK/client-c.log" 2>&1 & PIDS+=($!)
for _ in $(seq 50); do [ -S "$WORK/c.sock" ] && break; sleep 0.1; done; sleep 1
ip netns exec wm-c "$WORK/wiremesh" status --socket "$WORK/c.sock" | grep -q stopped && ok "after a daemon restart the tunnel stays down (down is remembered)"
ip netns exec wm-c "$WORK/wiremesh" up --socket "$WORK/c.sock" --timeout 30s >/dev/null && ok "\`wiremesh up\` reconnects without a new login"
wait_for "C reaches A again" ip netns exec wm-c ping -c1 -W1 "$A4"
CCRED=$(python3 -c "import json;print(json.load(open('$WORK/c.json'))['credential'])")
ip netns exec wm-c "$WORK/wiremesh" logout --socket "$WORK/c.sock" >/dev/null
[ ! -f "$WORK/c.json" ] && ok "\`wiremesh logout\` deleted the keys" || fail "state file still present"
[ "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $CCRED" $API/device/self)" = 401 ] && ok "logout revoked the credential on the server" || fail "credential still valid"

log "ALL CHECKS PASSED"
