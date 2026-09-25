.PHONY: build test vet fmt release

IMG := golang:1.26-alpine
VER := $(shell git rev-parse --short HEAD)

# Cross-compiles a static Linux binary using the Go container, so the
# Windows laptop this is developed on never needs a local Go install.
build:
	docker run --rm -v "$(CURDIR)":/src -w /src -v gocache:/root/.cache/go-build -v gomod:/go/pkg/mod \
		-e GOOS=linux -e GOARCH=amd64 -e CGO_ENABLED=0 \
		$(IMG) go build -trimpath -ldflags="-s -w" -o bin/haproxy-gui ./cmd/haproxy-gui

test:
	docker run --rm -v "$(CURDIR)":/src -w /src -v gocache:/root/.cache/go-build -v gomod:/go/pkg/mod \
		$(IMG) go test ./... -cover

vet:
	docker run --rm -v "$(CURDIR)":/src -w /src -v gocache:/root/.cache/go-build -v gomod:/go/pkg/mod \
		$(IMG) go vet ./...

fmt:
	docker run --rm -v "$(CURDIR)":/src -w /src -v gocache:/root/.cache/go-build -v gomod:/go/pkg/mod \
		$(IMG) gofmt -l -w .

# Builds the binary, then packs it with everything under deploy/ into a
# versioned tarball + sha256 under dist/, ready to scp to haproxy-cni.
release: build
	rm -rf dist/haproxy-gui-$(VER)
	mkdir -p dist/haproxy-gui-$(VER)/bin dist/haproxy-gui-$(VER)/deploy
	cp bin/haproxy-gui dist/haproxy-gui-$(VER)/bin/
	cp deploy/*.sh deploy/*.service deploy/*.example deploy/*.snippet deploy/sudoers.haproxy-gui dist/haproxy-gui-$(VER)/deploy/
	cp README.md dist/haproxy-gui-$(VER)/
	tar czf dist/haproxy-gui-$(VER).tar.gz -C dist haproxy-gui-$(VER)
	sha256sum dist/haproxy-gui-$(VER).tar.gz > dist/haproxy-gui-$(VER).tar.gz.sha256
	@echo "release: dist/haproxy-gui-$(VER).tar.gz"
