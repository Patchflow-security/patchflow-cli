.PHONY: build test vet fmt lint clean all release release-snapshot release-check docker-build install-tools

VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS = -s -w \
	-X github.com/Patchflow-security/patchflow-cli/pkg/version.Version=$(VERSION) \
	-X github.com/Patchflow-security/patchflow-cli/pkg/version.Commit=$(COMMIT) \
	-X github.com/Patchflow-security/patchflow-cli/pkg/version.Date=$(DATE)

build:
	go build -ldflags "$(LDFLAGS)" -o patchflow .

test:
	go test ./... -timeout 10m

vet:
	go vet ./...

fmt:
	gofmt -w .

lint:
	go vet ./... && go test ./... -timeout 10m

clean:
	rm -f patchflow dist/

all: fmt vet test build

# Install release tooling (goreleaser, syft, cosign)
install-tools:
	@echo "Installing goreleaser..."
	@which goreleaser >/dev/null 2>&1 || brew install goreleaser 2>/dev/null || go install github.com/goreleaser/goreleaser/v2@latest
	@echo "Installing syft (SBOM)..."
	@which syft >/dev/null 2>&1 || brew install syft 2>/dev/null || curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
	@echo "Installing cosign (signing)..."
	@which cosign >/dev/null 2>&1 || brew install cosign 2>/dev/null || go install github.com/sigstore/cosign/v2/cmd/cosign@latest
	@echo "Done."

# Validate goreleaser config via snapshot build (no publish)
release-check:
	goreleaser release --snapshot --clean --skip=publish

# Release with goreleaser (requires goreleaser installed, run on tag push)
release:
	goreleaser release --clean

# Snapshot build for testing release pipeline locally (no publish)
release-snapshot:
	goreleaser release --snapshot --clean

# Build Docker image locally
docker-build:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg DATE=$(DATE) \
		-t ghcr.io/patchflow-security/cli:$(VERSION) \
		.
