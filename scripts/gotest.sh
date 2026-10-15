#!/usr/bin/env bash
# Run gofmt, go vet and the test suite inside the Go container (no local Go
# needed). Pass package patterns to narrow the run, default ./...
set -euo pipefail
cd "$(dirname "$0")/.."
PKGS="${*:-./...}"
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "$PWD":/src -w /src \
  -v gocache:/root/.cache/go-build -v gomod:/go/pkg/mod \
  golang:1.26-alpine sh -c "gofmt -l \$(find . -name '*.go' -not -path './dist/*') | grep -v -e internal/haproxycfg -e internal/i18n -e internal/web/chrome.go -e internal/web/errorpages.go -e internal/web/pool_actions.go -e internal/web/users.go || true; go vet $PKGS && go test $PKGS 2>&1 | grep -v 'no test files'"
