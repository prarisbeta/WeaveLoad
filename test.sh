#!/bin/bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
IMG=golang:1.26-alpine
MSYS_NO_PATHCONV=1 docker run --rm -v "$PWD":/src -w /src \
  -v gocache:/root/.cache/go-build -v gomod:/go/pkg/mod \
  "$IMG" go test ./... -cover
