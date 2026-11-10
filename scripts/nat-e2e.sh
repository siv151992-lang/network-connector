#!/usr/bin/env bash
# NAT traversal test with real WireGuard tunnels, real NATs (iptables
# MASQUERADE in router namespaces) and real STUN, across a multi-hop "internet".
#
#   c-a 192.168.10.2 ── r-a (NAT) 198.18.1.2 ── core1 ── core2 ── core3 ── 198.18.3.2 r-b (NAT) ── c-b 192.168.20.2
#                                                          │
#                                     control server + STUN 198.18.99.1 (root namespace)
#
# The core routers make the topology realistic: a peer's NAT is several hops
# away, which is what low-TTL hole punching relies on. 198.18.0.0/15 is a
# reserved, non-private range, so clients treat these addresses as public.
#
# Cases:
#   1. NAT <-> NAT (Linux MASQUERADE on both sides, port-preserving): hole
#      punched, direct path through both NATs; then site A's public IP
#      changes (roaming) and the tunnel recovers on its own.
#      With the relay, the tunnel comes back within seconds and then moves to
#      the new direct path.
#   2. NAT <-> symmetric NAT (--random-fully: new random port per destination):
#      no direct path is possible, so traffic flows through the relay.
#
# Usage: sudo WIREMESH_TEST_DATABASE_URL=postgres://user@host:5432/postgres scripts/nat-e2e.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d /tmp/wm-nat.XXXXXX)
DB_ADMIN=${WIREMESH_TEST_DATABASE_URL:?set WIREMESH_TEST_DATABASE_URL}
DB_NAME=wm_nat_$$
URL=http://198.18.99.1:18091
API=$URL/api/v1
PASS="nat test passphrase"
PIDS=()
CLIENT_PIDS=()

log()  { printf '\n\033[1;34m== %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32m✓ %s\033[0m\n' "$*"; }
fail() {
  printf '   \033[31m✗ %s\033[0m\n' "$*"
  for f in "$WORK"/*.log; do echo "--- $f"; grep -v "level=DEBUG" "$f" | tail -n 15; done
  [ -n "${WIREMESH_TEST_LOGS:-}" ] && echo "logs will be saved to $WIREMESH_TEST_LOGS"
  exit 1
}

teardown_net() {
  for n in c-a c-b r-a r-b core1 core2 core3; do ip netns del $n 2>/dev/null || true; done
  ip link del srv0 2>/dev/null || true
}
cleanup() {
  set +e
  stop_clients
  [ -n "${WIREMESH_TEST_LOGS:-}" ] && mkdir -p "$WIREMESH_TEST_LOGS" && cp "$WORK"/*.log "$WIREMESH_TEST_LOGS"/ 2>/dev/null
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
  sleep 1
  teardown_net
  psql "$DB_ADMIN" -qc "DROP DATABASE IF EXISTS $DB_NAME WITH (FORCE)" >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }

wait_for() { # timeout-seconds description command...  (real deadline, not an iteration count)
  local t=$1 d=$2 start=$SECONDS; shift 2
  while [ $((SECONDS - start)) -lt "$t" ]; do
    "$@" >/dev/null 2>&1 && { ok "$d ($((SECONDS - start))s)"; return 0; }
    sleep 0.5
  done
  fail "$d (gave up after ${t}s)"
}
never() { # seconds description command...: assert command never succeeds
  local t=$1 d=$2 start=$SECONDS; shift 2
  while [ $((SECONDS - start)) -lt "$t" ]; do "$@" >/dev/null 2>&1 && fail "$d"; sleep 0.5; done
  ok "$d"
}

ns_router() { ip netns add $1; ip -n $1 link set lo up; ip netns exec $1 sysctl -qw net.ipv4.ip_forward=1; }
link() { # nsA ifA addrA nsB ifB addrB  (nsA may be "root")
  if [ "$1" = root ]; then ip link add $2 type veth peer name $5 netns $4; ip addr add $3 dev $2; ip link set $2 up
  else ip link add $2 netns $1 type veth peer name $5 netns $4; ip -n $1 addr add $3 dev $2; ip -n $1 link set $2 up; fi
  ip -n $4 addr add $6 dev $5; ip -n $4 link set $5 up
}

# setup_site NAME LAN_OCTET WAN_ADDR CORE_NS CORE_ADDR NAT_FLAGS
setup_site() {
  local s=$1 o=$2 wan=$3 core=$4 coreaddr=$5 flags=$6
  ns_router r-$s; ip netns add c-$s; ip -n c-$s link set lo up
  link $core to-$s $coreaddr/24 r-$s wan $wan/24
  ip -n r-$s route add default via $coreaddr
  ip netns exec r-$s iptables -t nat -A POSTROUTING -o wan -j MASQUERADE $flags
  link r-$s lan 192.168.$o.1/24 c-$s eth0 192.168.$o.2/24
  ip -n c-$s route add default via 192.168.$o.1
}

setup_net() { # NAT flags for site a, site b
  teardown_net
  ns_router core1; ns_router core2; ns_router core3
  link core1 c12 198.18.12.1/24 core2 c21 198.18.12.2/24
  link core2 c23 198.18.23.1/24 core3 c32 198.18.23.2/24
  link root srv0 198.18.99.1/24 core2 srv 198.18.99.254/24
  ip route replace 198.18.0.0/16 via 198.18.99.254
  setup_site a 10 198.18.1.2 core1 198.18.1.1 "$1"
  setup_site b 20 198.18.3.2 core3 198.18.3.1 "$2"
  ip -n core1 route add default via 198.18.12.2
  ip -n core3 route add default via 198.18.23.1
  ip -n core2 route add 198.18.1.0/24 via 198.18.12.1
  ip -n core2 route add 198.18.3.0/24 via 198.18.23.2
}

log "build"
(cd "$ROOT" && for b in wiremesh-server wiremesh wiremesh-relay; do go build -o "$WORK/$b" ./cmd/$b; done)
ok "binaries built"

setup_net "" ""

log "control server + STUN + relay"
psql "$DB_ADMIN" -qc "CREATE DATABASE $DB_NAME" >/dev/null
export WIREMESH_DATABASE_URL=$(python3 -c "import sys,urllib.parse as u;p=u.urlparse(sys.argv[1]);print(p._replace(path='/$DB_NAME').geturl())" "$DB_ADMIN")
export WIREMESH_HTTP_ADDR=198.18.99.1:18091 WIREMESH_PUBLIC_URL=$URL WIREMESH_LOG_FORMAT=text \
       WIREMESH_SECRET_KEY=$(head -c32 /dev/urandom | base64) WIREMESH_AUTH_RATE_LIMIT_PER_MIN=600 \
       WIREMESH_STUN_SERVERS=198.18.99.1:3478 WIREMESH_RELAY_URLS=http://198.18.99.1:8443/relay
"$WORK/wiremesh-relay" --stun-addr 198.18.99.1:3478 --relay-addr 198.18.99.1:8443 \
  --control-key "$("$WORK/wiremesh-server" relay-pubkey)" >"$WORK/relay.log" 2>&1 & PIDS+=($!)
WIREMESH_ADMIN_PASSWORD="$PASS" "$WORK/wiremesh-server" create-admin --email admin@example.com >/dev/null
"$WORK/wiremesh-server" serve >"$WORK/server.log" 2>&1 & PIDS+=($!)
for _ in $(seq 50); do curl -fs $URL/readyz >/dev/null && break; sleep 0.2; done
json() { python3 -c "import sys,json;d=json.load(sys.stdin);print(eval('d'+sys.argv[1]))" "$1"; }
CSRF=$(curl -fs -c "$WORK/jar" -H 'Content-Type: application/json' \
  -d "{\"email\":\"admin@example.com\",\"password\":\"$PASS\"}" $API/auth/login | json "['csrf_token']")
call() { curl -fsS -b "$WORK/jar" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' "$@"; }
NID=$(call -d '{"name":"NAT Test"}' $API/networks | json "['network']['id']")
KEY=$(call -d '{"reusable":true,"preauthorized":true,"ephemeral":true}' $API/networks/$NID/auth-keys | json "['key']")
ok "server, STUN, relay and network ready"

CASE=0
start_clients() {
  CASE=$((CASE + 1))
  for s in a b; do
    ip netns exec c-$s env WIREMESH_AUTH_KEY="$KEY" "$WORK/wiremesh" up --server $URL \
      --state "$WORK/$s-$CASE.json" --iface wm$s$CASE --hostname "$s-case$CASE" --log-level debug \
      >"$WORK/client-$s.log" 2>&1 &
    CLIENT_PIDS+=($!)
  done
  sleep 1
}
stop_clients() {
  for p in "${CLIENT_PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  for p in "${CLIENT_PIDS[@]}"; do wait "$p" 2>/dev/null || true; done
  CLIENT_PIDS=()
}
tun_ip() { ip netns exec c-$1 ip -4 -o addr show dev wm$1$CASE | awk '{print $4}' | cut -d/ -f1; }
has_tun_ip() { [ -n "$(tun_ip "$1" 2>/dev/null)" ]; }
pings() { ip netns exec c-$1 ping -c1 -W1 "$2"; }
path_of() { # client: the WireGuard path currently in use (wiremesh status --json)
  ip netns exec c-$1 "$WORK/wiremesh" status --json --state "$WORK/$1-$CASE.json" --iface wm$1$CASE 2>/dev/null |
    python3 -c "import sys,json;p=json.load(sys.stdin)['peers'];print(p[0].get('endpoint','') if p else '')"
}
path_is() { [ "$(path_of "$1")" = "$2" ]; }

# --------------------------------------------------------------------------
log "case 1: NAT <-> NAT"
ip netns exec c-b python3 -c "
import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',5555));s.settimeout(3)
try: s.recv(10); open('$WORK/unsolicited','w').write('received')
except Exception: pass" &
sleep 0.5
ip netns exec c-a python3 -c "
import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
for _ in range(5): s.sendto(b'hi',('198.18.3.2',5555))"
wait $! || true
[ ! -f "$WORK/unsolicited" ] && ok "NAT is real: unsolicited UDP from site A to site B's public IP is dropped" || fail "NAT let unsolicited traffic in"
never 2 "site A cannot reach site B's private address" pings a 192.168.20.2

start_clients
wait_for 20 "both clients enrolled and configured" sh -c "$(declare -f has_tun_ip tun_ip); CASE=$CASE; has_tun_ip a && has_tun_ip b"
A=$(tun_ip a); B=$(tun_ip b); echo "   tunnel addresses: A=$A B=$B"
wait_for 10 "STUN discovered A's public endpoint (198.18.1.2)" grep -q "reported endpoints.*198.18.1.2:" "$WORK/client-a.log"
wait_for 10 "STUN discovered B's public endpoint (198.18.3.2)" grep -q "reported endpoints.*198.18.3.2:" "$WORK/client-b.log"
wait_for 30 "ping A -> B through both NATs" pings a "$B"
wait_for 10 "ping B -> A through both NATs" pings b "$A"
wait_for 15 "A's WireGuard path is B's NAT public address (direct, hole-punched)" path_is a 198.18.3.2:51820
wait_for 15 "B's WireGuard path is A's NAT public address" path_is b 198.18.1.2:51820
grep -q "direct path selected" "$WORK/client-a.log" && ok "magicsock confirmed the path with disco"

log "case 1b: site A's public IP changes (roaming)"
ip -n r-a addr del 198.18.1.2/24 dev wan   # MASQUERADE drops conntrack entries for the old address
ip -n r-a addr add 198.18.1.3/24 dev wan
ip -n r-a route replace default via 198.18.1.1
ok "r-a WAN address 198.18.1.2 -> 198.18.1.3"
if [ -n "${WIREMESH_TEST_CONNTRACK:-}" ]; then
  ( while sleep 10; do for r in r-a r-b; do echo "--- $(date +%T) $r"; ip netns exec $r cat /proc/net/nf_conntrack 2>/dev/null | grep 51820 | sed -E 's/^ipv4 +2 +udp +17 +//; s/ mark=0 zone=0 use=[0-9]+//'; done; done >"$WORK/conntrack.log" 2>&1 ) &
  PIDS+=($!)
fi
wait_for 30 "tunnel recovered via the relay after the address change (A -> B)" pings a "$B"
wait_for 100 "direct path re-established: B uses A's new public address" path_is b 198.18.1.3:51820
wait_for 60 "control stream reconnected from the new address" grep -q "control stream connected" <(grep -A1000 "control stream down" "$WORK/client-a.log")
stop_clients

# --------------------------------------------------------------------------
[ -n "${WIREMESH_TEST_SKIP_CASE2:-}" ] && { log "ALL CHECKS PASSED (case 2 skipped)"; exit 0; }
log "case 2: NAT <-> symmetric NAT (random port per destination)"
setup_net "" "--random-fully"
start_clients
wait_for 20 "both clients configured" sh -c "$(declare -f has_tun_ip tun_ip); CASE=$CASE; has_tun_ip a && has_tun_ip b"
A=$(tun_ip a); B=$(tun_ip b)
wait_for 20 "ping A -> B through the relay" pings a "$B"
wait_for 10 "ping B -> A through the relay" pings b "$A"
wait_for 10 "A's path to B is the relay" path_is a relay
grep -q "direct path selected" "$WORK/client-a.log" && fail "a direct path was unexpectedly selected" || ok "no direct path (symmetric NAT), relay carries the traffic"
stop_clients

log "ALL CHECKS PASSED"
