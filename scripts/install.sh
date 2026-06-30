#!/bin/sh
# PatchFlow CLI install script
# Usage: curl -fsSL https://patchflow.dev/install.sh | bash
#   or: curl -fsSL https://patchflow.dev/install.sh | bash -s -- --version v0.1.0
set -e

# --- defaults ---
VERSION="latest"
INSTALL_DIR="${INSTALL_DIR:-${HOME}/.local/bin}"
REPO="Patchflow-security/patchflow-cli"

# --- parse args ---
while [ $# -gt 0 ]; do
    case "$1" in
        --version)
            VERSION="$2"
            shift 2
            ;;
        --install-dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --help)
            echo "Usage: curl -fsSL https://patchflow.dev/install.sh | bash -s -- [--version vX.Y.Z] [--install-dir /path]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# --- detect platform ---
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Darwin) OS="macos" ;;
    Linux)  OS="linux" ;;
    *)
        echo "Unsupported OS: $OS"
        echo "PatchFlow CLI supports Linux and macOS."
        exit 1
        ;;
esac

case "$ARCH" in
    x86_64|amd64) ARCH="x86_64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *)
        echo "Unsupported architecture: $ARCH"
        echo "PatchFlow CLI supports x86_64 and arm64."
        exit 1
        ;;
esac

# --- resolve version ---
if [ "$VERSION" = "latest" ]; then
    echo "Fetching latest release version..."
    VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    if [ -z "$VERSION" ]; then
        echo "Failed to determine latest version."
        echo "Specify explicitly: --version v0.1.0"
        exit 1
    fi
fi

# Strip leading 'v' for URL construction (GitHub releases use it, download URLs may not)
VERSION_NUM="${VERSION#v}"

# --- construct download URL ---
# goreleaser archive naming: patchflow_VERSION_OS_ARCH.tar.gz
ARCHIVE="patchflow_${VERSION_NUM}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE}"

echo "Downloading PatchFlow CLI ${VERSION} for ${OS}/${ARCH}..."
echo "  ${URL}"

# --- download ---
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

if ! curl -fsSL -o "${TMPDIR}/${ARCHIVE}" "$URL"; then
    echo "Download failed. Check that version ${VERSION} exists."
    exit 1
fi

# --- verify checksum ---
CHECKSUM_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"
if curl -fsSL -o "${TMPDIR}/checksums.txt" "$CHECKSUM_URL"; then
    echo "Verifying checksum..."
    # sha256sum on Linux, shasum -a 256 on macOS/BSD
    if command -v sha256sum >/dev/null 2>&1; then
        SHA_CMD="sha256sum -c -"
    else
        SHA_CMD="shasum -a 256 -c -"
    fi
    (cd "$TMPDIR" && grep "${ARCHIVE}" checksums.txt | $SHA_CMD) || {
        echo "Checksum verification failed!"
        exit 1
    }
else
    echo "Warning: checksums file not found. Skipping verification."
fi

# --- extract ---
echo "Extracting..."
tar -xzf "${TMPDIR}/${ARCHIVE}" -C "$TMPDIR"

# --- install ---
mkdir -p "$INSTALL_DIR"
mv "${TMPDIR}/patchflow" "${INSTALL_DIR}/patchflow"
chmod +x "${INSTALL_DIR}/patchflow"

echo ""
echo "Installed PatchFlow CLI ${VERSION} to ${INSTALL_DIR}/patchflow"

# --- check PATH ---
case ":${PATH}:" in
    *":${INSTALL_DIR}:"*)
        echo "patchflow is in your PATH."
        ;;
    *)
        echo "Add ${INSTALL_DIR} to your PATH:"
        echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
        if [ -f "${HOME}/.bashrc" ]; then
            echo "Or add to ~/.bashrc:"
            echo "  echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ~/.bashrc"
        elif [ -f "${HOME}/.zshrc" ]; then
            echo "Or add to ~/.zshrc:"
            echo "  echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ~/.zshrc"
        fi
        ;;
esac

echo ""
echo "Verify: patchflow version"
