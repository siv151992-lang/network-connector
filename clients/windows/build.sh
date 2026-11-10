#!/usr/bin/env bash
# Cross-builds the Windows release zip (no CGO needed):
#   clients/windows/build.sh [version] [amd64|arm64]  ->  dist/wiremesh-windows-<arch>-<version>.zip
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
VERSION=${1:-dev}
ARCH=${2:-amd64}
OUT=${OUT:-$ROOT/dist}
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
LDFLAGS="-s -w -X github.com/siv151992-lang/network-connector/internal/version.Version=$VERSION"
export GOOS=windows GOARCH=$ARCH CGO_ENABLED=0
cd "$ROOT"
go build -trimpath -ldflags "$LDFLAGS" -o "$STAGE/wiremesh.exe" ./cmd/wiremesh
go build -trimpath -ldflags "$LDFLAGS" -o "$STAGE/wiremeshd.exe" ./cmd/wiremeshd
go build -trimpath -ldflags "$LDFLAGS -H windowsgui" -o "$STAGE/wiremesh-tray.exe" ./cmd/wiremesh-tray
cp clients/windows/install.ps1 clients/windows/uninstall.ps1 clients/windows/README.txt "$STAGE/"
mkdir -p "$OUT"
ZIP="$OUT/wiremesh-windows-$ARCH-$VERSION.zip"
(cd "$STAGE" && rm -f "$ZIP" && python3 -c "import sys,zipfile,os;z=zipfile.ZipFile(sys.argv[1],'w',zipfile.ZIP_DEFLATED);[z.write(f) for f in sorted(os.listdir('.'))]" "$ZIP")
echo "$ZIP"
