.PHONY: build test vet fmt

IMG := golang:1.26-alpine

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
