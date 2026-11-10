#!/usr/bin/env bash
# Builds the all-in-one Linux server tarball (no Docker): server + dashboard +
# relay + embedded PostgreSQL.
#   deploy/linux/build-server.sh [version] [amd64|arm64]  ->  dist/wiremesh-server-linux-<arch>.tar.gz
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
VERSION=${1:-dev}
ARCH=${2:-amd64}
OUT=${OUT:-$ROOT/dist}
PG=16.4.0
case $ARCH in
  amd64) ZARCH=amd64;   TXZ=postgres-linux-x86_64.txz; SHA=14a5cf546aee7d327a2f5b46be6c571f2f724a2b485c270d46f3e44a1ac3df18 ;;
  arm64) ZARCH=arm64v8; TXZ=postgres-linux-arm_64.txz; SHA=5a281952dd35191be97809ce657d6cb1a7b42a8d8ca6195125dd368d47eb8c42 ;;
  *) echo "unsupported arch $ARCH" >&2; exit 2 ;;
esac
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
cd "$ROOT"

JAR=$ROOT/.cache/embedded-postgres-binaries-linux-$ZARCH-$PG.jar
mkdir -p "$ROOT/.cache"
if [ ! -f "$JAR" ]; then
  curl -fsSL --retry 5 --retry-delay 5 -o "$JAR.tmp" \
    "https://repo1.maven.org/maven2/io/zonky/test/postgres/embedded-postgres-binaries-linux-$ZARCH/$PG/embedded-postgres-binaries-linux-$ZARCH-$PG.jar"
  mv "$JAR.tmp" "$JAR"
fi
echo "$SHA  $JAR" | sha256sum -c --quiet
D=$STAGE/wiremesh-server
mkdir -p "$D"
unzip -p "$JAR" "$TXZ" > "$D/postgres-linux-$ARCH.txz"

(cd web && { [ -d node_modules ] || npm ci --no-audit --no-fund; } && npm run build >/dev/null)
cp -r web/dist "$D/web"
LDFLAGS="-s -w -X github.com/siv151992-lang/network-connector/internal/version.Version=$VERSION"
GOOS=linux GOARCH=$ARCH CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" -o "$D/wiremesh-server" ./cmd/wiremesh-server

mkdir -p "$OUT"
TAR="$OUT/wiremesh-server-linux-$ARCH.tar.gz"
tar -C "$STAGE" -czf "$TAR" wiremesh-server
echo "$TAR"
