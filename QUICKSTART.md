# PatchFlow CLI — Quickstart

`patchflow` is a native Go, local-first change-intelligence CLI for engineering
teams. It scans your repository for vulnerable dependencies (SCA via OSV.dev),
runs static analysis (SAST) with zero-install embedded scanners, detects
secrets, checks whether vulnerable packages are actually reachable, computes a
0–100 risk score, and simulates a PR review — all on your machine, with no
backend connection required.

This guide gets you from zero to a working scan in under five minutes.

---

## 1. Install

### Option A — Build from source (recommended for development)

Requires Go 1.25+ and `make`.

```bash
cd /Users/digitalcenter/patchflow-cli
make build          # produces ./patchflow
./patchflow version
```

The `make build` target bakes `Version`, `Commit`, and `Date` into the binary
via `-ldflags`, so `version` reports accurate provenance.

### Option B — Run the container image (no install)

Built with Podman; works with Docker too. The image is CGo-free.

```bash
podman run --rm -v "$PWD:/repo:ro,Z" -w /repo patchflow/cli:latest scan run
```

Mount your repository read-only and run any subcommand against it. For scans
that need git history (e.g. `pr-review`, `scan changed`), drop `:ro`.

### Option C — Pre-built release binary

Download a tarball from the
[releases page](https://github.com/Patchflow-security/patchflow-cli/releases) for your
platform (`linux_amd64`, `linux_arm64`, `macos_arm64`, `windows_amd64`, …),
extract it, and put `patchflow` on your `PATH`.

```bash
patchflow version
```

> If `version` reports `commit: dev` and `built: unknown`, you ran `go build`
> without the ldflags — use `make build` to embed provenance.

---

## 2. Verify your environment

`doctor` checks git, embedded scanners, and any optional external tools
(`gosec`, `bandit`, `semgrep`, `gitleaks`, `checkov`) that supplement the
embedded ones when installed.

```bash
patchflow doctor
```

Expected output (abridged):

```
PatchFlow Doctor
================
[OK] Git installed: git version 2.51.2
[OK] Inside a git repository: /repo
[OK] Remote configured: git@github.com:org/repo.git

Embedded SAST Scanners (always available, zero installation):
[OK] gosast-embedded      (go) — 35 rules
[OK] secrets-embedded     (secrets) — 35 rules
[OK] patterns-embedded    (multi) — 472 rules
[OK] taint-ssa            (go) — 9 rules
[OK] treesitter-ast       (multi) — 92 rules
[OK] taint-patterns       (multi) — 47 rules

External SAST Tools (optional supplements):
[OK] gosec  (go)       — installed
[OK] bandit (python)   — installed
...
```

The embedded scanners always run. External tools are optional supplements —
PatchFlow never fails if they are missing.

---

## 3. Initialize PatchFlow in your repo

`init` creates a `.patchflow/` directory with a default `config.yml`, a cache,
a baselines store, and a reports directory. It is idempotent and safe to commit
(the `config.yml` is intended for version control; `cache/` and `state.json`
are gitignored).

```bash
patchflow init
```

The default config enables local-only analysis and redacts secrets:

```yaml
mode: local
analysis:
    default_profile: standard
    changed_files_only: true
    include_reachability: true
    include_sast: true
    include_secrets: true
privacy:
    redact_secrets: true
    send_code_to_remote_ai: false
    retain_local_cache_days: 7
ignore:
    paths:
        - node_modules/**
        - dist/**
        - build/**
        - vendor/**
        - .git/**
```

---

## 4. Your first scan

`scan run` is the main command. It performs SCA (OSV.dev), SAST (embedded +
external), secret detection, reachability analysis, and risk scoring in one
pass — entirely locally.

```bash
patchflow scan run
```

Expected output (abridged):

```
PatchFlow Scan — standard profile
=================================
Repository:  /repo
Branch:      feat/my-branch
Files:       142 scanned

SCA (OSV.dev)
  Vulnerable dependencies: 3
    HIGH   github.com/example/vuln  v1.2.3   CVE-2024-1234

SAST (embedded + external)
  Findings: 5
    HIGH   G404  crypto/rand misuse        auth/token.go:42
    MEDIUM PY001 eval() call               app/runner.py:88

Secrets
  Findings: 1
    HIGH   AWS access key                 .env:4

Reachability
  github.com/example/vuln  → REACHABLE (imported in auth/token.go)

Risk Score: 72/100  (HIGH)
  - Sensitive files touched (auth, CI)
  - Dependency changes present
```

### Tune the scan depth

| Flag             | Effect                                                       |
|------------------|--------------------------------------------------------------|
| `--profile quick`    | Fastest; skips transitive SCA resolution.                |
| `--profile standard` | Default; balanced.                                       |
| `--profile deep`     | Full transitive dependency resolution + all scanners.    |
| `--changed-only`     | Only analyze files changed vs the base branch.           |
| `--since main`       | Scan files changed since the given branch/commit.        |
| `--staged`           | Only scan git-staged files (great for pre-commit).       |
| `--include-tests`    | Include test files in SAST (skipped by default).         |
| `--no-sast`          | Skip SAST.                                                |
| `--no-secrets`       | Skip secret detection.                                    |
| `--no-reachability`  | Skip reachability analysis.                               |

```bash
patchflow scan run --profile deep
patchflow scan run --changed-only --no-secrets
patchflow scan run --staged            # pre-commit hook style
```

---

## 5. Simulate a PR review before opening the PR

`pr-review` is the PatchFlow "is this change safe?" command. It runs the same
analysis as `scan run` but scoped to your branch diff, then produces a
terminal summary, reviewer suggestions, inline annotations, or a report file.

```bash
patchflow pr-review
```

Useful variants:

```bash
# Suggest reviewers from CODEOWNERS + git blame
patchflow pr-review --suggest-reviewers

# Generate inline code annotations for the PR diff
patchflow pr-review --annotations

# Generate safe fix proposals for detected vulnerabilities
patchflow pr-review --suggest-fixes

# Write a markdown report for the PR
patchflow pr-review --format markdown --output pr-report.md

# Compare against a specific base branch
patchflow pr-review --base main --head feat/my-branch
```

---

## 6. Dependency analysis

```bash
# List all dependencies (parses go.mod, package.json, requirements.txt, …)
patchflow deps list

# Show dependency tree grouped by ecosystem
patchflow deps tree

# Find vulnerable dependencies (queries OSV.dev)
patchflow deps vulnerable

# Show dependency changes against the base branch
patchflow deps diff
```

---

## 7. Reachability — is the vulnerable package actually used?

A vulnerable dependency that is never imported is far lower risk than one that
is. `reachability` parses import statements (Python, Go, JS/TS) and tells you
whether a package is reachable, with an explanation.

```bash
patchflow reachability --package github.com/example/vuln --explain
patchflow reachability --cve CVE-2024-1234 --explain
patchflow reachability --package flask --json
```

---

## 8. Reports and exports

`report` and `scan export` produce machine-readable artifacts for CI/CD, audit,
and downstream tools (GitHub code scanning, DefectDojo, etc.).

```bash
# Markdown report to stdout
patchflow report --format markdown

# SARIF report to file (upload to GitHub code scanning)
patchflow report --format sarif --output report.sarif

# JSON report to file
patchflow report --format json --output report.json

# Export scan results with real vulnerability findings
patchflow scan export --format sarif --output findings.sarif
patchflow scan export --format json   --output findings.json
```

---

## 9. Understand, fix, and suppress findings

PatchFlow is not a black box. Every finding has an explanation, a safe fix
proposal, and a suppression path.

### Explain a finding

```bash
patchflow explain G404
patchflow explain --file auth/token.go --line 42
patchflow explain --rule PY001
```

Shows what the issue is, why it's dangerous, where the evidence is, how to fix
it (with example code), and how to suppress it if it's a false positive.

### Generate and apply safe fixes

```bash
patchflow fix suggest                       # generate fix proposals
patchflow fix show <finding-id>             # inspect a specific proposal
patchflow fix apply --dry-run               # preview without writing
patchflow fix apply --yes --backup          # apply with backups
```

Fixes are generated from built-in templates (eval, command injection, SQL
injection, weak crypto, …). Each fix includes a confidence score, rationale,
and unified diff. Safe by design: never applies without confirmation unless
`--yes`, always previews, and supports `--backup`.

### Suppress false positives

Add a `//patchflow:ignore` directive on the line above or the same line:

```go
//patchflow:ignore G404 -- using math/rand for non-security purpose
n := rand.Intn(100)
```

```python
# patchflow:ignore PY001 -- eval is safe here, input is sanitized
result = eval(user_input)
```

- **Rule-specific**: `//patchflow:ignore G404` suppresses only G404.
- **Blanket**: `//patchflow:ignore` suppresses all rules on that line.
- Use `--show-suppressed` to include suppressed findings in output.
- Use `patchflow suppress <file> <line> <rule>` to insert the directive
  programmatically.

---

## 10. Baselines for CI noise reduction

A baseline snapshots known findings so subsequent scans report only **new**
ones — dramatically reducing CI noise on existing codebases. Baselines use
stable semantic fingerprints (rule id + scanner + normalized path + snippet),
so they survive line-number shifts from unrelated edits.

```bash
patchflow baseline create --name v1.0      # snapshot current findings
patchflow baseline list
patchflow baseline diff --from v1.0        # what's new since v1.0?
patchflow baseline delete --name v1.0

# In CI: only fail on findings not in the baseline
patchflow scan run --new-only --baseline v1.0
```

---

## 11. Configuration

PatchFlow reads configuration in order of precedence:

1. Command-line flags (`--api-url`, `--config`)
2. Environment variables
3. Config file (`~/.patchflow/config.yaml` and repo-level `.patchflow/config.yml`)
4. Defaults

### Config file

```yaml
apiurl: https://api.patchflow.dev
org: my-org
loglevel: info
```

### Environment variables

| Variable              | Description                |
|-----------------------|----------------------------|
| `PATCHFLOW_API_URL`   | PatchFlow API base URL     |
| `PATCHFLOW_TOKEN`     | API authentication token   |
| `PATCHFLOW_ORG`       | Default organization slug  |
| `PATCHFLOW_LOG_LEVEL` | Logging verbosity          |

### Common config commands

```bash
patchflow config show
patchflow config set org my-org
patchflow config set log_level debug
patchflow login --token my-api-token      # token is stored in the OS keyring
patchflow logout
patchflow auth status
```

> Setting `token` via `config set` is rejected; use `patchflow login --token`
> so the token is stored in the OS keyring, not on disk.

---

## 12. Common flags

| Flag             | Scope   | Description                                              |
|------------------|---------|----------------------------------------------------------|
| `--json`         | global  | Force JSON output for any subcommand (great for CI).    |
| `-q, --quiet`    | global  | Suppress non-essential output.                          |
| `-v, --verbose`  | global  | Enable development-level logging.                       |
| `--no-color`     | global  | Disable ANSI color (auto-detected in CI).               |
| `--config`       | global  | Path to an alternate config file.                       |
| `--api-url`      | global  | Override the PatchFlow API URL.                         |
| `--format`       | report  | `markdown`, `json`, `sarif`, `pr-summary`, `annotations`. |
| `--output`       | report  | Write to a file instead of stdout.                      |
| `--fail-on`      | scan    | Exit 1 if findings at/above severity: `low\|medium\|high\|critical`. |

---

## 13. A 60-second CI/CD recipe

Drop this into a CI step to scan every push, fail on high/critical findings,
emit a SARIF report for GitHub code scanning, and only alert on **new**
findings vs the release baseline.

```bash
set -euo pipefail

# Initialize (idempotent) and snapshot the baseline on the main branch
patchflow init
if [[ "${GITHUB_REF_NAME}" == "main" ]]; then
  patchflow baseline create --name main || true
  exit 0
fi

# Scan the branch diff, fail on high/critical, export SARIF
patchflow scan run \
  --changed-only \
  --new-only --baseline main \
  --fail-on high \
  --format sarif --output patchflow.sarif

# Upload patchflow.sarif as a GitHub code-scanning artifact
```

For pre-commit, scan only staged files and gate on critical:

```bash
patchflow scan run --staged --fail-on critical
```

---

## 14. Exit codes

| Code | Meaning                                       | CI action            |
|------|-----------------------------------------------|----------------------|
| `0`  | Success (no blocking findings)                | Proceed              |
| `1`  | Error / blocking findings (with `--fail-on`)  | Fail the build       |

Use `--fail-on` to make `scan run` exit non-zero when findings meet a severity
threshold, so CI can gate without parsing output.

```bash
patchflow scan run --fail-on high || exit 1
```

---

## 15. Verify the install

```bash
patchflow version
patchflow doctor
patchflow --help
patchflow scan run --help
patchflow scan run
```

If `version` reports `commit: dev` and `built: unknown`, you ran `go build`
without the ldflags — use `make build` to embed provenance.

---

## Where to go next

- **`patchflow <command> --help`** — full flag reference for any command.
- **[User Guide](docs/USER_GUIDE.md)** — installation, auth, configuration,
  every command with examples, CI/CD integration, troubleshooting, and the
  security/privacy model.
- **[Command Reference](docs/CLI_COMMANDS.md)** — quick reference for every
  command and flag.
- **[Developer Guide](docs/DEVELOPER_GUIDE.md)** — architecture, package
  reference, adding commands, testing, and the release process.
- **[Development Guide](docs/DEVELOPMENT.md)** — build, test, and project
  structure overview.

PatchFlow CLI is local-first by design: SCA, SAST, secrets, reachability, and
risk scoring all run on your machine with zero installation. Backend
authentication (`login`, `review pr --submit`) is optional and only needed for
deeper review analytics and team workflows.
