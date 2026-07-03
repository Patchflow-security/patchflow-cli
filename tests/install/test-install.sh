#!/bin/sh
# Test runner for PatchFlow CLI install script across container platforms.
# Usage: run inside a container; the install script is mounted at /tmp/install.sh.
set -eu

INSTALL_SCRIPT="/tmp/install.sh"
LOG_FILE="/tmp/install-test.log"

echo() { printf '%s\n' "$*"; }
log() { echo "[$(date -Iseconds)] $*" | tee -a "$LOG_FILE"; }
fail() { echo "FAIL: $*" | tee -a "$LOG_FILE"; exit 1; }

log "Starting install test on $(uname -s)/$(uname -m)"
log "Current PATH: $PATH"
log "Current user: $(id -un)"
log "Current shell: ${SHELL:-unknown}"

# Ensure the install script is present.
[ -f "$INSTALL_SCRIPT" ] || fail "install script not mounted at $INSTALL_SCRIPT"

# Verify the script is valid POSIX sh.
log "Validating install script syntax"
sh -n "$INSTALL_SCRIPT" || fail "install script syntax error"

# Run the install script.
log "Running install script"
sh "$INSTALL_SCRIPT" > /tmp/install-output.txt 2>&1 || fail "install script failed\n$(cat /tmp/install-output.txt)"
cat /tmp/install-output.txt >> "$LOG_FILE"

# Inspect the installation location.
INSTALL_DIR="${HOME}/.local/bin"
[ -f "${INSTALL_DIR}/patchflow" ] || fail "patchflow binary not found at ${INSTALL_DIR}/patchflow"
log "Binary installed at ${INSTALL_DIR}/patchflow"

# Verify the binary is executable.
[ -x "${INSTALL_DIR}/patchflow" ] || fail "patchflow binary is not executable"
log "Binary is executable"

# Verify the binary can run without PATH edits in the current session.
"${INSTALL_DIR}/patchflow" version >/tmp/version-output.txt 2>&1 || fail "patchflow version failed\n$(cat /tmp/version-output.txt)"
log "patchflow version output:"
cat /tmp/version-output.txt >> "$LOG_FILE"

# Verify that the script prints a usable PATH hint.
if ! grep -q "export PATH" /tmp/install-output.txt; then
    fail "install script did not print PATH export hint"
fi
log "PATH hint is present"

# Verify the script supports --help.
sh "$INSTALL_SCRIPT" --help >/tmp/help-output.txt 2>&1 || fail "install script --help failed"
if ! grep -q "Usage" /tmp/help-output.txt; then
    fail "install script --help did not print usage"
fi
log "--help works"

# Verify the script supports --version and --install-dir.
sh "$INSTALL_SCRIPT" --version v0.1.2 --install-dir /tmp/custom-patchflow >/tmp/custom-output.txt 2>&1 || fail "custom install failed"
[ -f /tmp/custom-patchflow/patchflow ] || fail "custom install-dir did not contain binary"
log "--version and --install-dir flags work"

log "All install tests passed"
