#!/usr/bin/env bash
# One-command WireMesh server for a Linux cloud VM (Ubuntu/Debian/Oracle Linux):
#
#   curl -fsSL https://raw.githubusercontent.com/siv151992-lang/network-connector/main/deploy/linux/install-server.sh | sudo bash
#
# Installs to /opt/wiremesh-server, runs as the 'wiremesh' user under systemd,
# serves HTTPS with a free Let's Encrypt certificate on <public-ip>.sslip.io
# (or DOMAIN=vpn.example.com), and opens the needed ports in the OS firewall.
set -euo pipefail
REPO=siv151992-lang/network-connector
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }

case $(uname -m) in
  x86_64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "unsupported CPU $(uname -m)" >&2; exit 1 ;;
esac

if [ -z "${DOMAIN:-}" ]; then
  IP=$(curl -4 -fsS --max-time 10 https://api.ipify.org || curl -4 -fsS --max-time 10 https://ifconfig.me)
  [[ $IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "could not detect the public IP; run with DOMAIN=your.domain" >&2; exit 1; }
  DOMAIN="${IP//./-}.sslip.io"
fi
echo "==> Server address: $DOMAIN"

echo "==> Downloading WireMesh server ($ARCH)"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
URL=${WIREMESH_TARBALL_URL:-https://github.com/$REPO/releases/latest/download/wiremesh-server-linux-$ARCH.tar.gz}
curl -fSL --retry 3 -o "$TMP/s.tgz" "$URL"
systemctl stop wiremesh-server 2>/dev/null || true
rm -rf /opt/wiremesh-server
tar -C /opt -xzf "$TMP/s.tgz"

id wiremesh >/dev/null 2>&1 || useradd --system --home-dir /var/lib/wiremesh-server --shell /usr/sbin/nologin wiremesh
install -d -o wiremesh -g wiremesh -m 0700 /var/lib/wiremesh-server

cat > /etc/systemd/system/wiremesh-server.service <<UNIT
[Unit]
Description=WireMesh server (control plane, dashboard, relay)
After=network-online.target
Wants=network-online.target

[Service]
User=wiremesh
Group=wiremesh
ExecStart=/opt/wiremesh-server/wiremesh-server standalone --data /var/lib/wiremesh-server --domain $DOMAIN
Restart=always
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/wiremesh-server
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT

echo "==> Opening ports 80/tcp, 443/tcp, 3478/udp in the OS firewall"
if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd --permanent --add-port=80/tcp --add-port=443/tcp --add-port=3478/udp >/dev/null
  firewall-cmd --reload >/dev/null
elif command -v iptables >/dev/null; then
  for r in "tcp 80" "tcp 443" "udp 3478"; do
    set -- $r
    iptables -C INPUT -p "$1" --dport "$2" -j ACCEPT 2>/dev/null || iptables -I INPUT -p "$1" --dport "$2" -j ACCEPT
  done
  command -v netfilter-persistent >/dev/null && netfilter-persistent save >/dev/null 2>&1 || true
fi
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null; ufw allow 3478/udp >/dev/null
fi

systemctl daemon-reload
systemctl enable --now wiremesh-server >/dev/null 2>&1
echo "==> Starting (first start sets up the database and gets a certificate, ~1 minute)"
for _ in $(seq 60); do
  curl -fs --max-time 5 "https://$DOMAIN/readyz" >/dev/null 2>&1 && break
  sleep 3
done
echo
if curl -fs --max-time 5 "https://$DOMAIN/readyz" >/dev/null 2>&1; then
  echo "WireMesh server is running."
  echo
  echo "  1. Open https://$DOMAIN and create your admin account (do it now: the first sign-up becomes admin)."
  echo "  2. On each PC, install the WireMesh app and connect to:  $DOMAIN"
else
  echo "Not reachable at https://$DOMAIN yet."
  echo "Most likely the cloud firewall: allow TCP 80, TCP 443 and UDP 3478 from 0.0.0.0/0"
  echo "(Oracle: Networking > Virtual cloud networks > your VCN > Security Lists > Default > Add Ingress Rules)."
  echo "It retries automatically; check:  journalctl -u wiremesh-server -n 30"
fi
