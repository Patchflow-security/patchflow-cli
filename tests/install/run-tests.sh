#!/bin/sh
# Build and run containerized install tests for PatchFlow CLI.
# Supports both Docker and Podman (Podman is preferred if available).
# Usage: cd /Users/digitalcenter/patchflow-cli && tests/install/run-tests.sh
set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TAG_PREFIX="patchflow-install-test"

if command -v podman >/dev/null 2>&1; then
    RUNNER="podman"
elif command -v docker >/dev/null 2>&1; then
    RUNNER="docker"
else
    echo "Neither podman nor docker is installed. Cannot run container tests." >&2
    exit 1
fi

echo() { printf '%s\n' "$*"; }
info() { echo "[INFO] $*"; }
error() { echo "[ERROR] $*" >&2; }

PLATFORMS="
ubuntu-amd64
alpine-amd64
ubuntu-nonroot
"

# Optional: add arm64 test only if the runner is already running on arm64.
if $RUNNER info 2>/dev/null | grep -qi "aarch64\|arm64"; then
    PLATFORMS="${PLATFORMS} ubuntu-arm64"
    info "arm64 platform tests enabled (native runner)"
else
    info "Skipping arm64 native tests; runner is not on arm64"
fi

# Optional: Linuxbrew/Homebrew test is slow and fragile (downloads Homebrew).
# Enable it with INCLUDE_LINUXBREW=1.
if [ "${INCLUDE_LINUXBREW:-0}" -eq 1 ]; then
    PLATFORMS="${PLATFORMS} linuxbrew"
    info "Linuxbrew test enabled (slow)"
fi

FAILED=""
PASSED=""

for platform in $PLATFORMS; do
    info "Testing platform: $platform"
    if $RUNNER build -f "${ROOT}/tests/install/Dockerfile.${platform}" -t "${TAG_PREFIX}-${platform}" "${ROOT}"; then
        info "Image built for ${platform}"
    else
        error "Failed to build image for ${platform}"
        FAILED="${FAILED} ${platform}(build)"
        continue
    fi

    if $RUNNER run --rm "${TAG_PREFIX}-${platform}" > "${ROOT}/tests/install/results-${platform}.log" 2>&1; then
        info "Tests passed for ${platform}"
        PASSED="${PASSED} ${platform}"
    else
        error "Tests failed for ${platform}"
        FAILED="${FAILED} ${platform}(run)"
    fi
done

info "================================"
info "RUNNER: ${RUNNER}"
info "PASSED: ${PASSED:-none}"
info "FAILED: ${FAILED:-none}"

if [ -n "$FAILED" ]; then
    exit 1
fi
