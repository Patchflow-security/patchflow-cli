#!/bin/sh
set -eu

VERSION="${SYFT_VERSION:-v1.18.0}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
REPO="anchore/syft"

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Darwin) OS="darwin" ;;
    Linux) OS="linux" ;;
    *)
        echo "Unsupported OS for syft: $OS"
        exit 1
        ;;
esac

case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *)
        echo "Unsupported architecture for syft: $ARCH"
        exit 1
        ;;
esac

VERSION_NUM="${VERSION#v}"
ARCHIVE="syft_${VERSION_NUM}_${OS}_${ARCH}.tar.gz"
CHECKSUMS="syft_${VERSION_NUM}_checksums.txt"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading Syft ${VERSION} for ${OS}/${ARCH}..."
curl --proto '=https' --tlsv1.2 -fsSL -o "${TMPDIR}/${ARCHIVE}" "${BASE_URL}/${ARCHIVE}"
curl --proto '=https' --tlsv1.2 -fsSL -o "${TMPDIR}/${CHECKSUMS}" "${BASE_URL}/${CHECKSUMS}"

if ! awk -v archive="$ARCHIVE" '$2 == archive { print; found = 1 } END { exit found ? 0 : 1 }' "${TMPDIR}/${CHECKSUMS}" > "${TMPDIR}/checksum.expected"; then
    echo "Checksum entry for ${ARCHIVE} not found."
    exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
    (cd "$TMPDIR" && sha256sum -c checksum.expected)
else
    (cd "$TMPDIR" && shasum -a 256 -c checksum.expected)
fi

if ! tar -tzf "${TMPDIR}/${ARCHIVE}" | awk '
    /^\/|(^|\/)\.\.($|\/)/ {
        print "Unsafe archive path: " $0 > "/dev/stderr"
        bad = 1
    }
    END { exit bad ? 1 : 0 }
'; then
    echo "Archive contains unsafe paths; refusing to extract."
    exit 1
fi

tar -xzf "${TMPDIR}/${ARCHIVE}" -C "$TMPDIR"
if [ ! -f "${TMPDIR}/syft" ]; then
    echo "Archive did not contain the syft binary."
    exit 1
fi

mkdir -p "$INSTALL_DIR"
if ! install -m 0755 "${TMPDIR}/syft" "${INSTALL_DIR}/syft" 2>/dev/null; then
    cp "${TMPDIR}/syft" "${INSTALL_DIR}/syft"
    chmod 0755 "${INSTALL_DIR}/syft"
fi

echo "Installed syft ${VERSION} to ${INSTALL_DIR}/syft"
