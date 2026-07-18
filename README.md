# PatchFlow CLI — Change Intelligence for Engineering Teams

PatchFlow CLI provides change intelligence for engineering teams. Use it to scan, review, and analyze code changes in your repositories.

## Canonical repository

[`Patchflow-security/patchflow-cli`](https://github.com/Patchflow-security/patchflow-cli)
is the source of truth for PatchFlow CLI development, issues, pull requests, tags,
and releases. Release artifacts must resolve to commits and tags that are reachable
from this public repository.

Older private copies are read-only mirrors for continuity. They are not upstreams,
must not publish releases, and are checked automatically against the public `main`
branch. See [RELEASE.md](RELEASE.md#repository-source-of-truth) for the maintainer
remote layout and provenance checks.

## Installation

### Homebrew (macOS)

```bash
brew install Patchflow-security/tap/patchflow
```

> **Note for Linux users:** The Patchflow Security tap does not currently publish Linux bottles. On Linux, `brew install` will fall back to building from source and requires a C compiler (`gcc` or `clang`). We recommend using the install script above for Linux and containerized environments.

### Scoop (Windows)

```powershell
scoop bucket add patchflow https://github.com/Patchflow-security/scoop-bucket
scoop install patchflow
```

### Install Script (recommended for Linux / CI / Docker)

```bash
curl -fsSL https://github.com/Patchflow-security/patchflow-cli/raw/main/scripts/install.sh | bash
```

If you prefer the binary to be in your PATH immediately (e.g., inside a Docker/Podman container), install to `/usr/local/bin`:

```bash
curl -fsSL https://github.com/Patchflow-security/patchflow-cli/raw/main/scripts/install.sh | bash -s -- --install-dir /usr/local/bin
```

Other options:

```bash
# Install a specific version
curl -fsSL https://github.com/Patchflow-security/patchflow-cli/raw/main/scripts/install.sh | bash -s -- --version v0.1.3

# Skip the post-install binary verification step (useful in CI)
NO_VERIFY=1 curl -fsSL https://github.com/Patchflow-security/patchflow-cli/raw/main/scripts/install.sh | bash
```

### Docker / Podman

```bash
podman pull ghcr.io/patchflow-security/cli:latest
podman run --rm -v "$PWD:/repo" ghcr.io/patchflow-security/cli:latest scan run --path /repo
```

### Go Install

```bash
go install github.com/Patchflow-security/patchflow-cli@latest
```

### Build from Source

```bash
git clone https://github.com/Patchflow-security/patchflow-cli.git
cd patchflow-cli
go build -o patchflow .
```

### Download Binary

Download the latest binary for your platform from the [releases page](https://github.com/Patchflow-security/patchflow-cli/releases).

## Quick Start

```bash
# Initialize PatchFlow in your repository
patchflow init

# Run a full security analysis (SCA + SAST + reachability + risk score)
patchflow scan run

# Simulate a PR risk review before opening a PR
patchflow pr-review

# List dependencies
patchflow deps list

# Find vulnerable dependencies (queries OSV.dev)
patchflow deps vulnerable

# Check if a vulnerable package is actually used
patchflow reachability --package <name> --explain

# Generate a report (markdown, JSON, or SARIF)
patchflow report --format sarif --output report.sarif
```

## Local-First Analysis

PatchFlow CLI runs **all analysis locally** — no backend connection required:

- **SCA (Software Composition Analysis)**: Parses dependency manifests (go.mod, package.json, requirements.txt, pyproject.toml, Cargo.toml, Gemfile, composer.json, pom.xml, build.gradle) and queries the [OSV.dev](https://osv.dev) public vulnerability database.
- **SAST (Static Analysis Security Testing)**: Uses three embedded scanners that require **zero installation**, plus external tools as supplements:
  - **gosast-embedded** — Go SAST scanner with 32 AST-based rules ported from gosec (G101-G601): SQL injection, command injection, weak crypto, unsafe pointers, hardcoded credentials, bad file permissions, path traversal, TLS misconfiguration, slowloris, decompression bombs, and more.
  - **secrets-embedded** — Secret scanner with 35 curated regex patterns (AWS, GitHub, Google, Stripe, Slack, private keys, database URLs, JWTs) plus Shannon entropy detection. Automatically skips `.venv/`, `node_modules/`, `.env.example`, and other false-positive sources.
  - **patterns-embedded** — Multi-language pattern scanner for Python, JavaScript/TypeScript, Ruby, and PHP with 40 rules covering OWASP Top 10 (eval, exec, shell=True, pickle, yaml.load, SQL injection, weak crypto, SSL verification, debug mode, dangerouslySetInnerHTML, and more).
  - **External tools** (optional): `gosec`, `bandit`, `semgrep`, `gitleaks` — run automatically when installed to supplement the embedded scanners.
- **Reachability Analysis**: Parses import statements (Python, Go, JavaScript/TypeScript) to determine whether vulnerable dependencies are actually used in the codebase.
- **Risk Scoring**: Computes a 0-100 risk score from findings, change size, and sensitivity (auth files, CI workflows, dependency changes).

### Suppression Directives

Suppress false positives with `//patchflow:ignore` comments:

```go
//patchflow:ignore G404 -- using math/rand for non-security purpose
n := rand.Intn(100)
```

```python
# patchflow:ignore PY001 -- eval is safe here, input is sanitized
result = eval(user_input)
```

- **Rule-specific**: `//patchflow:ignore G404` suppresses only G404 on the next line or same line
- **Blanket**: `//patchflow:ignore` suppresses all rules on the next line or same line
- Use `--show-suppressed` flag to include suppressed findings in output

## Commands

| Command | Description |
|---------|-------------|
| `patchflow version` | Print the version number |
| `patchflow doctor` | Check the CLI environment |
| `patchflow init` | Initialize PatchFlow in the current repository |
| `patchflow login --token <token>` | Authenticate with PatchFlow |
| `patchflow logout` | Remove stored credentials |
| `patchflow auth status` | Show authentication status |
| `patchflow config show` | Show current configuration |
| `patchflow config set <key> <value>` | Set a configuration value |
| `patchflow scan local` | Scan the local repository (manifest detection) |
| `patchflow scan changed` | Scan changed files only (manifest detection) |
| `patchflow scan run` | Run full security analysis (SCA + SAST + reachability + risk) |
| `patchflow scan export` | Export scan results with real vulnerability findings (JSON/SARIF) |
| `patchflow pr-review` | Simulate a PR risk review before opening a pull request |
| `patchflow deps list` | List all dependencies |
| `patchflow deps tree` | Show dependency tree by ecosystem |
| `patchflow deps vulnerable` | List vulnerable dependencies (queries OSV.dev) |
| `patchflow deps diff` | Show dependency changes against base branch |
| `patchflow reachability --package <name>` | Check if a package is reachable in the codebase |
| `patchflow reachability --cve <cve-id>` | Check reachability for a specific CVE |
| `patchflow report --format <fmt>` | Generate a report (markdown, json, sarif) |
| `patchflow review context` | Show review context for the current repository |
| `patchflow review pr` | Preview review data for a pull request |
| `patchflow review pr --submit` | Submit a review to the PatchFlow backend |
| `patchflow review diff` | Review a diff |

### `scan run` Flags

| Flag | Description |
|------|-------------|
| `--profile <quick\|standard\|deep>` | Scan depth (affects SCA transitive dependency resolution) |
| `--no-sast` | Skip SAST analysis (gosast-embedded, patterns-embedded, gosec, bandit, semgrep) |
| `--no-secrets` | Skip secret detection (secrets-embedded, gitleaks) |
| `--no-reachability` | Skip reachability analysis |
| `--changed-only` | Only analyze changed files (requires git) |
| `--include-tests` | Include test files in SAST findings (tests are skipped by default) |
| `--show-suppressed` | Show findings suppressed by `//patchflow:ignore` comments |
| `--format <markdown\|json\|sarif>` | Output format for report file |
| `--output <path>` | Write report to file (stdout if omitted) |

### Global Flags

| Flag | Description |
|------|-------------|
| `--config <path>` | Config file path |
| `--api-url <url>` | PatchFlow API URL |
| `--json` | Output in JSON format |
| `--verbose, -v` | Enable verbose logging |
| `--no-color` | Disable colored output |

## Configuration

PatchFlow CLI reads configuration from multiple sources, in order of precedence:

1. Command-line flags (`--api-url`, `--config`)
2. Environment variables
3. Config file (`~/.patchflow/config.yaml`)
4. Defaults

### Config File

Path: `~/.patchflow/config.yaml`

Example:

```yaml
apiurl: https://api.patchflow.dev
org: my-org
loglevel: info
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `PATCHFLOW_API_URL` | PatchFlow API base URL |
| `PATCHFLOW_TOKEN` | API authentication token |
| `PATCHFLOW_ORG` | Default organization |
| `PATCHFLOW_LOG_LEVEL` | Logging level |

### Configurable Keys

The `patchflow config set` command accepts the following keys:

- `api_url` — PatchFlow API base URL
- `org` — Default organization slug
- `log_level` — Logging verbosity

Setting `token` via `config set` is rejected; use `patchflow login --token <token>` instead.

### Default API URL

```
https://api.patchflow.dev
```

## JSON Output for CI/CD

All commands support `--json` for machine-readable output. This is useful for CI/CD pipelines and automation.

See [Machine-readable output contracts](docs/MACHINE_READABLE_OUTPUTS.md) for
stdout/stderr guarantees, SARIF conformance, compatibility rules, and release
validation requirements.

```bash
# Get version info as JSON
patchflow version --json

# Get review context as JSON
patchflow review context --json

# Get diff review as JSON
patchflow review diff --json

# Scan changed files as JSON
patchflow scan changed --json
```

## Security

By default, the CLI sends only metadata (file paths, branch names, diff stats). It does not send source code contents unless explicitly configured.

## Examples

### Authenticate

```bash
patchflow login --token my-api-token
```

### Check your setup

```bash
patchflow doctor
```

### View configuration

```bash
patchflow config show
```

### Update configuration

```bash
patchflow config set org my-org
patchflow config set log_level debug
```

### Review local changes

```bash
patchflow review context
```

### Submit a review

```bash
patchflow review pr --submit
```

### Review a diff as JSON

```bash
patchflow review diff --json
```

### Scan the repository

```bash
# Manifest detection only
patchflow scan local
patchflow scan changed

# Full security analysis (SCA + SAST + reachability + risk score)
patchflow scan run
patchflow scan run --profile deep
patchflow scan run --no-sast --no-secrets
patchflow scan run --include-tests

# Export scan results with real vulnerability findings
patchflow scan export --format sarif --output findings.sarif
patchflow scan export --format json --output findings.json
```

### PR risk review

```bash
# Simulate a PR review before opening a PR
patchflow pr-review

# Generate a markdown report for the PR
patchflow pr-review --format markdown --output pr-report.md

# Skip SAST and secret detection
patchflow pr-review --no-sast --no-secrets
```

### Dependency analysis

```bash
# List all dependencies
patchflow deps list

# Show dependency tree grouped by ecosystem
patchflow deps tree

# Find vulnerable dependencies (queries OSV.dev)
patchflow deps vulnerable

# Show dependency changes against base branch
patchflow deps diff
```

### Reachability analysis

```bash
# Check if a package is actually used in the codebase
patchflow reachability --package github.com/spf13/cobra --explain

# Check reachability for a specific CVE
patchflow reachability --cve CVE-2024-1234 --explain

# JSON output
patchflow reachability --package flask --json
```

### Generate reports

```bash
# Markdown report to stdout
patchflow report --format markdown

# SARIF report to file
patchflow report --format sarif --output report.sarif

# JSON report to file
patchflow report --format json --output report.json
```

## Documentation

- **[User Guide](docs/USER_GUIDE.md)** — Installation, authentication, configuration, all commands with examples, CI/CD integration, troubleshooting, and security model.
- **[Developer Guide](docs/DEVELOPER_GUIDE.md)** — Architecture, package reference, adding commands, testing, coding standards, and release process.
- **[Command Reference](docs/CLI_COMMANDS.md)** — Quick reference for every command and flag.
- **[Development Guide](docs/DEVELOPMENT.md)** — Build, test, and project structure overview.

## Development

Run tests:

```bash
make test
```

Build:

```bash
make build
```

See the [Developer Guide](docs/DEVELOPER_GUIDE.md) for the full developer documentation.
