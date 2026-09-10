#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
GO="${GO:-go}"
[ "$(uname -s)-$(uname -m)" = Linux-x86_64 ] || { echo 'Validated packaging target is Linux x86_64' >&2; exit 1; }
version=${1:-$(git describe --tags --exact-match 2>/dev/null || echo dev)}
name="paldron-${version}-linux-x86_64"
# Baseline CPU: never ship host-specific instructions. Pure Go (no cgo),
# so the binary is static and runs anywhere on x86_64 Linux.
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$GO" build -ldflags "-X main.version=${version}" -o "dist-stage/${name}/paldron" ./cmd/paldron
stage=dist-stage
mkdir -p "$stage/$name" dist
cp README.md LICENSE "$stage/$name/"
tar -C "$stage" -czf "dist/$name.tar.gz" "$name"
(cd dist && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")
rm -rf "$stage/$name"
printf 'Created dist/%s.tar.gz and checksum (not published)\n' "$name"
