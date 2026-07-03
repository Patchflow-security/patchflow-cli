#!/bin/sh
# Verify that the PatchFlow CLI is healthy after installation by exercising
# core commands. Commands that depend on project-specific config are checked
# for availability (help works) but do not fail the install test.
set -eu

PATCHFLOW="${1:-${HOME}/.local/bin/patchflow}"
LOG_FILE="/tmp/commands-test.log"

echo() { printf '%s\n' "$*"; }
log() { echo "[$(date -Iseconds)] $*" | tee -a "$LOG_FILE"; }
fail() { echo "FAIL: $*" | tee -a "$LOG_FILE"; exit 1; }

log "Testing CLI commands with $PATCHFLOW"
[ -x "$PATCHFLOW" ] || fail "binary not found or not executable: $PATCHFLOW"

# Add install dir to PATH so the binary can find itself.
INSTALL_DIR=$(dirname "$PATCHFLOW")
export PATH="${INSTALL_DIR}:${PATH}"

# 1. version --json (critical)
log "Running version --json"
$PATCHFLOW version --json >/tmp/version.json || fail "version --json failed"
log "version JSON: $(cat /tmp/version.json)"

# 2. doctor (critical)
log "Running doctor --json"
$PATCHFLOW doctor --json >/tmp/doctor.json || fail "doctor --json failed"
log "doctor JSON keys: $(cat /tmp/doctor.json | head -c 200)"

# 3. rules list (critical)
log "Running rules list"
$PATCHFLOW rules list >/tmp/rules-list.txt || fail "rules list failed"
log "rules list output length: $(wc -c < /tmp/rules-list.txt)"

# 4. rules list-frameworks (critical)
log "Running rules list-frameworks"
$PATCHFLOW rules list-frameworks >/tmp/frameworks.txt || fail "rules list-frameworks failed"
log "frameworks output length: $(wc -c < /tmp/frameworks.txt)"

# 5. help for commands that depend on project config (availability check)
for cmd in "rules validate --help" "config migrate --help" "explain --help" "scan run --help" "doctor --help"; do
    safe_name=$(echo "$cmd" | tr ' /' '__')
    log "Checking help for: $cmd"
    $PATCHFLOW $cmd >/tmp/help-${safe_name}.txt 2>&1 || fail "help failed for: $cmd\n$(cat /tmp/help-${safe_name}.txt)"
    log "help OK for: $cmd"
done

# 6. Smoke scan on an empty directory (must not crash; no network needed).
log "Running smoke scan in empty directory"
mkdir -p /tmp/empty-repo && cd /tmp/empty-repo
$PATCHFLOW scan run --no-sast --no-secrets --format json --output smoke-scan.json >/tmp/scan-run.txt 2>&1 || {
    log "scan run returned non-zero; output follows:"
    cat /tmp/scan-run.txt >> "$LOG_FILE"
    fail "scan run failed\n$(cat /tmp/scan-run.txt)"
}
[ -f /tmp/empty-repo/smoke-scan.json ] || fail "scan run did not produce JSON output\n$(cat /tmp/scan-run.txt)"
log "scan run output length: $(wc -c < /tmp/empty-repo/smoke-scan.json)"

log "All CLI command tests passed"
