# Onboarding rehearsal transcript

## Local rehearsal — 2026-07-18

Environment: macOS arm64. Published release installed: `v0.1.6`, commit
`c5e304a2f9463c98f8a56701c8b0061d40d56922`. Candidate source branch:
`agent/five-minute-onboarding`.

### Clean installation

```text
Downloading PatchFlow CLI v0.1.6 for macos/arm64...
Verifying checksum...
patchflow_0.1.6_macos_arm64.tar.gz: OK
Extracting...
Installed PatchFlow CLI v0.1.6
Installation verified.
patchflow version 0.1.6 (commit: c5e304a2f9463c98f8a56701c8b0061d40d56922)
```

Command:

```bash
INSTALL_DIR="$(mktemp -d)" ./scripts/install.sh --version v0.1.6
```

### Candidate quickstart verification

Command:

```bash
go build -o /tmp/patchflow-onboarding .
./scripts/verify-quickstart.sh /tmp/patchflow-onboarding /tmp/onboarding-evidence.json
```

Observed result:

```text
Quickstart verified in 9s; evidence: /tmp/onboarding-evidence.json
```

The vulnerable fixture produced both the regex `PY001` and AST-confirmed
`TS-PY001` views of the same unsafe call. The visible report’s leading finding
was:

```text
[MEDIUM] [AST] Use of eval() (AST-confirmed)
File: app.py:6
CWE: CWE-95
Fix: Avoid eval() entirely. Use ast.literal_eval() for literals only.
```

The clean fixture did not contain `PY001`. `patchflow explain --rule PY001`
included the rule identity and fix section. The generated file declared SARIF
`2.1.0` and contained `PY001`. `doctor --json` returned structured checks, and
every non-pass check included a remediation. No command used login or `--submit`.

### Verification commands

```text
go test ./... -timeout 10m              PASS
go vet ./...                            PASS
go build ./...                          PASS
python3 scripts/validate-claims.py      Claim registry valid: 5 claims
git diff --check                        PASS
```

This transcript is one engineering rehearsal, not a fresh-user session and not
the full platform matrix. The authoritative multi-platform evidence will be the
JSON artifacts from `.github/workflows/onboarding.yml`.
