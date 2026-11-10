#!/usr/bin/env bash
# Builds wiremesh_<version>_<arch>.deb (wiremesh CLI + wiremeshd + systemd unit).
#   clients/linux/build-deb.sh [version] [amd64|arm64]
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
VERSION=${1:-$(git -C "$ROOT" describe --tags --always 2>/dev/null | sed 's/^v//' || echo 0.0.0)}
[[ "$VERSION" =~ ^[0-9] ]] || VERSION="0.0.0+$VERSION"
ARCH=${2:-amd64}
OUT=${OUT:-$ROOT/dist}
PKG=$(mktemp -d)
trap 'rm -rf "$PKG"' EXIT
chmod 0755 "$PKG"  # mktemp creates 0700; dpkg must not see a private root
LDFLAGS="-s -w -X github.com/siv151992-lang/network-connector/internal/version.Version=$VERSION"
mkdir -p "$PKG/DEBIAN" "$PKG/usr/bin" "$PKG/lib/systemd/system" "$OUT"
for b in wiremesh wiremeshd; do
  (cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -ldflags "$LDFLAGS" -o "$PKG/usr/bin/$b" ./cmd/$b)
done
install -m 0644 "$ROOT/clients/linux/wiremeshd.service" "$PKG/lib/systemd/system/wiremeshd.service"
install -m 0755 "$ROOT/clients/linux/debian/postinst" "$ROOT/clients/linux/debian/prerm" "$PKG/DEBIAN/"
cat > "$PKG/DEBIAN/control" <<CTL
Package: wiremesh
Version: $VERSION
Architecture: $ARCH
Maintainer: WireMesh maintainers
Section: net
Priority: optional
Recommends: systemd-resolved
Description: WireMesh mesh VPN client
 WireGuard-based private mesh networking with NAT traversal and relays.
 Includes the wiremeshd service and the wiremesh command-line tool.
CTL
dpkg-deb --root-owner-group --build "$PKG" "$OUT/wiremesh_${VERSION}_${ARCH}.deb" >/dev/null
echo "$OUT/wiremesh_${VERSION}_${ARCH}.deb"
