.PHONY: build test vet fmt lint clean all release release-snapshot docker-build

VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS = -s -w \
	-X github.com/patchflow/patchflow-cli/pkg/version.Version=$(VERSION) \
	-X github.com/patchflow/patchflow-cli/pkg/version.Commit=$(COMMIT) \
	-X github.com/patchflow/patchflow-cli/pkg/version.Date=$(DATE)

build:
	go build -ldflags "$(LDFLAGS)" -o patchflow .

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

lint:
	go vet ./... && go test ./...

clean:
	rm -f patchflow

all: fmt vet test build

# Release with goreleaser (requires goreleaser installed)
release:
	goreleaser release --clean

# Snapshot build for testing release pipeline locally
release-snapshot:
	goreleaser release --snapshot --clean

# Build Docker image locally
docker-build:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg DATE=$(DATE) \
		-t patchflow/cli:$(VERSION) \
		.
