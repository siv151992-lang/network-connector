GO      ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/siv151992-lang/network-connector/internal/version.Version=$(VERSION)
DEV_DB  ?= postgres://wiremesh:wiremesh@localhost:5432/wiremesh?sslmode=disable
TEST_DB ?= postgres://wiremesh:wiremesh@localhost:5432/postgres?sslmode=disable

.PHONY: deb windows web web-e2e build build-client test test-integration test-netns lint run migrate migrate-status dev-db docker

build:
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/wiremesh-server ./cmd/wiremesh-server

build-client:
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/wiremesh ./cmd/wiremesh

# Real WireGuard tunnels between two network namespaces (root, Linux).
test-netns:
	WIREMESH_TEST_DATABASE_URL="$(TEST_DB)" ./scripts/netns-e2e.sh

# Debian/Ubuntu package (wiremesh + wiremeshd + systemd unit) into dist/.
deb:
	clients/linux/build-deb.sh "$(VERSION)" amd64

# Windows release zips (amd64 + arm64) into dist/.
windows:
	clients/windows/build.sh "$(VERSION)" amd64
	clients/windows/build.sh "$(VERSION)" arm64

web:
	cd web && npm ci && npm run build

# Dashboard end-to-end test in Chromium against a real server + PostgreSQL.
web-e2e: web
	cd web && WIREMESH_TEST_DATABASE_URL="$(TEST_DB)" npm run e2e

# Unit tests only; integration tests skip without a database.
test:
	$(GO) test -race ./...

# Unit + integration tests. Each test creates and drops its own database.
test-integration:
	WIREMESH_TEST_DATABASE_URL="$(TEST_DB)" $(GO) test -race -count=1 ./...

lint:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "needs gofmt:"; echo "$$out"; exit 1; fi
	$(GO) vet ./...

dev-db:
	docker compose -f deploy/docker-compose.dev.yml up -d --wait

run: build
	WIREMESH_DATABASE_URL="$(DEV_DB)" WIREMESH_LOG_FORMAT=text ./bin/wiremesh-server serve

migrate: build
	WIREMESH_DATABASE_URL="$(DEV_DB)" ./bin/wiremesh-server migrate up

migrate-status: build
	WIREMESH_DATABASE_URL="$(DEV_DB)" ./bin/wiremesh-server migrate status

docker:
	docker build -f deploy/docker/server.Dockerfile --build-arg VERSION=$(VERSION) -t wiremesh-server:$(VERSION) .
