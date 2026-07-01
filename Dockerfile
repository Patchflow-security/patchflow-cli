# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /build

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build with version metadata
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
RUN CGO_ENABLED=0 go build -ldflags \
    "-s -w \
    -X github.com/Patchflow-security/patchflow-cli/pkg/version.Version=${VERSION} \
    -X github.com/Patchflow-security/patchflow-cli/pkg/version.Commit=${COMMIT} \
    -X github.com/Patchflow-security/patchflow-cli/pkg/version.Date=${DATE}" \
    -o patchflow .

# Runtime stage — distroless for minimal attack surface
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /build/patchflow /usr/local/bin/patchflow

ENTRYPOINT ["/usr/local/bin/patchflow"]
CMD ["--help"]
