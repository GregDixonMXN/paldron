#!/bin/sh
# Package paldron into a versioned tarball + checksum.
#
# Usage: scripts/package.sh [version]
#   version defaults to the exact git tag, or "dev" when not on a tag.
#   scripts/package.sh --help | -h prints this help.
#
# Env:
#   GOOS   target OS (default: host OS). Supported: linux darwin windows
#   GOARCH target arch (default: host arch). Supported: amd64 arm64
#   GO     go toolchain (default: go)
#
# Notes:
# - Pure Go (no cgo), so cross-packaging from any host works.
# - Kernel-boundary isolation (Landlock/seccomp) enforces only on Linux.
#   darwin/windows binaries run policy gate + output scan; full isolation
#   refuses with a clear error unless require_os_isolation=false.
set -eu
cd "$(dirname "$0")/.."
GO="${GO:-go}"

case "${1:-}" in
  -h|--help|help)
    sed -n '2,20p' "$0"
    exit 0
    ;;
esac

host_os=$(uname -s | tr '[:upper:]' '[:lower:]')
host_arch=$(uname -m)
case "$host_arch" in
  x86_64) host_arch=amd64 ;;
  aarch64|arm64) host_arch=arm64 ;;
esac
GOOS="${GOOS:-$host_os}"
GOARCH="${GOARCH:-$host_arch}"
case "$GOOS" in
  linux|darwin|windows) ;;
  *) echo "unsupported GOOS: $GOOS (linux, darwin, windows)" >&2; exit 1 ;;
esac
case "$GOARCH" in
  amd64|arm64) ;;
  *) echo "unsupported GOARCH: $GOARCH (amd64, arm64)" >&2; exit 1 ;;
esac

version=${1:-$(git describe --tags --exact-match 2>/dev/null || echo dev)}
name="paldron-${version}-${GOOS}-${GOARCH}"
# Baseline CPU: never ship host-specific instructions. Pure Go (no cgo),
# so the binary is static and runs anywhere on the target.
bin="paldron"
[ "$GOOS" = windows ] && bin="paldron.exe"
CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" "$GO" build -ldflags "-X main.version=${version}" -o "dist-stage/${name}/${bin}" ./cmd/paldron
stage=dist-stage
mkdir -p "$stage/$name" dist
cp README.md LICENSE "$stage/$name/"
tar -C "$stage" -czf "dist/$name.tar.gz" "$name"
(cd dist && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")
rm -rf "$stage/$name"
printf 'Created dist/%s.tar.gz and checksum (not published)\n' "$name"
