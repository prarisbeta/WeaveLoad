#!/bin/bash
# release.sh — same steps as `make release`, for shells without make
# (e.g. Git Bash on Windows). Builds bin/haproxy-gui via the Go container,
# then packs it with deploy/ and README.md into a versioned tarball.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

VER="${VER:-$(git rev-parse --short HEAD)}"
IMG=golang:1.26-alpine

echo "==> building bin/haproxy-gui (linux/amd64, static) at $VER"
MSYS_NO_PATHCONV=1 docker run --rm -v "$PWD":/src -w /src \
  -v gocache:/root/.cache/go-build -v gomod:/go/pkg/mod \
  -e GOOS=linux -e GOARCH=amd64 -e CGO_ENABLED=0 \
  "$IMG" sh -c "go build -trimpath -ldflags='-s -w -X main.version=${VER} -X main.licensePublicKey=${LICENSE_PUBKEY:-}' -o bin/haproxy-gui ./cmd/haproxy-gui && go build -trimpath -ldflags='-s -w' -o bin/konsolgw-mcp ./cmd/konsolgw-mcp"

DIST="dist/haproxy-gui-${VER}"
rm -rf "dist/haproxy-gui-${VER}" "dist/haproxy-gui-${VER}.tar.gz" "dist/haproxy-gui-${VER}.tar.gz.sha256"
mkdir -p "$DIST/bin" "$DIST/deploy"
cp bin/haproxy-gui bin/konsolgw-mcp "$DIST/bin/"
cp deploy/*.sh deploy/*.service deploy/*.example deploy/*.snippet deploy/sudoers.haproxy-gui "$DIST/deploy/"
if [ -d "deploy/errors" ]; then
  cp -r deploy/errors "$DIST/deploy/"
fi
cp README.md "$DIST/"

( cd dist && tar czf "haproxy-gui-${VER}.tar.gz" "haproxy-gui-${VER}" )
( cd dist && sha256sum "haproxy-gui-${VER}.tar.gz" > "haproxy-gui-${VER}.tar.gz.sha256" )

echo "==> release: dist/haproxy-gui-${VER}.tar.gz"
cat "dist/haproxy-gui-${VER}.tar.gz.sha256"
