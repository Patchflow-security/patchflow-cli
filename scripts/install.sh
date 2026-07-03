#!/bin/sh
# PatchFlow CLI install script
# Usage: curl -fsSL https://patchflow.dev/install.sh | bash
#   or: curl -fsSL https://patchflow.dev/install.sh | bash -s -- --version v0.1.0
set -eu

# --- defaults ---
VERSION="latest"
INSTALL_DIR="${INSTALL_DIR:-${HOME}/.local/bin}"
REPO="Patchflow-security/patchflow-cli"

# --- parse args ---
while [ $# -gt 0 ]; do
    case "$1" in
        --version)
            if [ $# -lt 2 ]; then
                echo "--version requires a value"
                exit 1
            fi
            VERSION="$2"
            shift 2
            ;;
        --install-dir)
            if [ $# -lt 2 ]; then
                echo "--install-dir requires a value"
                exit 1
            fi
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
    VERSION=$(curl --proto '=https' --tlsv1.2 -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
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

if ! curl --proto '=https' --tlsv1.2 -fsSL -o "${TMPDIR}/${ARCHIVE}" "$URL"; then
    echo "Download failed. Check that version ${VERSION} exists."
    exit 1
fi

# --- verify checksum ---
CHECKSUM_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"
if ! curl --proto '=https' --tlsv1.2 -fsSL -o "${TMPDIR}/checksums.txt" "$CHECKSUM_URL"; then
    echo "Checksum file not found; refusing to install an unverified archive."
    exit 1
fi

echo "Verifying checksum..."
if ! awk -v archive="$ARCHIVE" '$2 == archive { print; found = 1 } END { exit found ? 0 : 1 }' "${TMPDIR}/checksums.txt" > "${TMPDIR}/checksum.expected"; then
    echo "Checksum entry for ${ARCHIVE} not found."
    exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
    (cd "$TMPDIR" && sha256sum -c checksum.expected) || {
        echo "Checksum verification failed!"
        exit 1
    }
else
    (cd "$TMPDIR" && shasum -a 256 -c checksum.expected) || {
        echo "Checksum verification failed!"
        exit 1
    }
fi

# Verify the signed checksum when cosign is available. Checksum verification is
# still mandatory above so installs work on hosts without cosign.
if command -v cosign >/dev/null 2>&1; then
    SIG_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt.sig"
    CERT_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt.pem"
    if curl --proto '=https' --tlsv1.2 -fsSL -o "${TMPDIR}/checksums.txt.sig" "$SIG_URL" &&
       curl --proto '=https' --tlsv1.2 -fsSL -o "${TMPDIR}/checksums.txt.pem" "$CERT_URL"; then
        echo "Verifying checksum signature..."
        cosign verify-blob \
            --certificate "${TMPDIR}/checksums.txt.pem" \
            --signature "${TMPDIR}/checksums.txt.sig" \
            --certificate-identity "https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${VERSION}" \
            --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
            "${TMPDIR}/checksums.txt" >/dev/null
    else
        echo "Warning: checksum signature files not found; checksum verification completed without signature verification."
    fi
fi

# --- extract ---
echo "Extracting..."
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

# --- install ---
mkdir -p "$INSTALL_DIR"
if [ ! -f "${TMPDIR}/patchflow" ]; then
    echo "Archive did not contain the patchflow binary."
    exit 1
fi
if ! install -m 0755 "${TMPDIR}/patchflow" "${INSTALL_DIR}/patchflow" 2>/dev/null; then
    cp "${TMPDIR}/patchflow" "${INSTALL_DIR}/patchflow"
    chmod 0755 "${INSTALL_DIR}/patchflow"
fi

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
