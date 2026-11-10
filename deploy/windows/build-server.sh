#!/usr/bin/env bash
# Builds the all-in-one Windows server zip (no Docker): server + dashboard +
# relay + embedded PostgreSQL.
#   deploy/windows/build-server.sh [version]  ->  dist/wiremesh-server-windows-amd64-<version>.zip
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
VERSION=${1:-dev}
OUT=${OUT:-$ROOT/dist}
PG=16.4.0
PG_JAR_SHA256=5748a1b03f3771cd7a6d8aa624975e2777f62525694bf63af9640deaa48cc87a
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
cd "$ROOT"

# PostgreSQL for Windows (zonky embedded-postgres-binaries), pinned by hash.
CACHE=$ROOT/.cache
JAR=$CACHE/embedded-postgres-binaries-windows-amd64-$PG.jar
mkdir -p "$CACHE"
if [ ! -f "$JAR" ]; then
  curl -fsSL --retry 5 --retry-delay 5 -o "$JAR.tmp" \
    "https://repo1.maven.org/maven2/io/zonky/test/postgres/embedded-postgres-binaries-windows-amd64/$PG/embedded-postgres-binaries-windows-amd64-$PG.jar"
  mv "$JAR.tmp" "$JAR"
fi
echo "$PG_JAR_SHA256  $JAR" | sha256sum -c --quiet
unzip -p "$JAR" postgres-windows-x86_64.txz > "$STAGE/postgres-windows-amd64.txz"

# Dashboard.
(cd web && { [ -d node_modules ] || npm ci --no-audit --no-fund; } && npm run build >/dev/null)
cp -r web/dist "$STAGE/web"

LDFLAGS="-s -w -X github.com/siv151992-lang/network-connector/internal/version.Version=$VERSION"
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" -o "$STAGE/wiremesh-server.exe" ./cmd/wiremesh-server
cp deploy/windows/install-server.ps1 deploy/windows/uninstall-server.ps1 "$STAGE/"
cp deploy/windows/Install.bat deploy/windows/Uninstall.bat "$STAGE/"
cp deploy/windows/README-server.txt "$STAGE/README.txt"
sed -i 's/\r*$/\r/' "$STAGE"/*.bat "$STAGE/README.txt" # Windows line endings

mkdir -p "$OUT"
ZIP="$OUT/wiremesh-server-windows-amd64-$VERSION.zip"
rm -f "$ZIP"
(cd "$STAGE" && python3 - "$ZIP" <<'PY'
import os, sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED) as z:
    for root, _, files in os.walk("."):
        for f in sorted(files):
            p = os.path.join(root, f)
            z.write(p, os.path.relpath(p, "."))
PY
)
echo "$ZIP"
