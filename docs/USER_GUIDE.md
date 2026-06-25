# PatchFlow CLI — User Guide

PatchFlow CLI is a **change intelligence** tool for engineering teams. It runs locally in your terminal and helps you answer one practical question before opening a pull request:

> Is this change safe, understandable, and ready to review?

The CLI inspects your Git working state, detects dependency manifests, computes risk hints, and can submit review metadata to the PatchFlow backend for deeper analysis. It is designed to reduce cognitive load — not add another noisy scanner to your workflow.

---

## Table of Contents

- [What PatchFlow CLI Does](#what-patchflow-cli-does)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Authentication](#authentication)
- [Configuration](#configuration)
  - [Configuration Precedence](#configuration-precedence)
  - [Config File](#config-file)
  - [Environment Variables](#environment-variables)
  - [Configurable Keys](#configurable-keys)
  - [Configuration Profiles](#configuration-profiles)
- [Global Flags](#global-flags)
- [Commands](#commands)
  - [`patchflow version`](#patchflow-version)
  - [`patchflow doctor`](#patchflow-doctor)
  - [`patchflow login`](#patchflow-login)
  - [`patchflow logout`](#patchflow-logout)
  - [`patchflow auth status`](#patchflow-auth-status)
  - [`patchflow config show`](#patchflow-config-show)
  - [`patchflow config set`](#patchflow-config-set)
  - [`patchflow config profile`](#patchflow-config-profile)
  - [`patchflow scan local`](#patchflow-scan-local)
  - [`patchflow scan changed`](#patchflow-scan-changed)
  - [`patchflow scan run`](#patchflow-scan-run)
  - [`patchflow scan export`](#patchflow-scan-export)
  - [`patchflow init`](#patchflow-init)
  - [`patchflow pr-review`](#patchflow-pr-review)
  - [`patchflow deps`](#patchflow-deps)
  - [`patchflow reachability`](#patchflow-reachability)
  - [`patchflow report`](#patchflow-report)
  - [`patchflow review context`](#patchflow-review-context)
  - [`patchflow review pr`](#patchflow-review-pr)
  - [`patchflow review diff`](#patchflow-review-diff)
  - [`patchflow review status`](#patchflow-review-status)
- [JSON Output for CI/CD](#json-output-for-cicd)
- [SARIF and JSON Export](#sarif-and-json-export)
- [Exit Codes](#exit-codes)
- [Security and Privacy Model](#security-and-privacy-model)
- [CI/CD Integration Examples](#cicd-integration-examples)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)

---

## What PatchFlow CLI Does

PatchFlow CLI provides four categories of capability:

| Category | Commands | Purpose |
|----------|----------|---------|
| **Environment** | `version`, `doctor` | Verify your setup and CLI installation |
| **Authentication** | `login`, `logout`, `auth status` | Manage credentials for the PatchFlow backend |
| **Configuration** | `config show`, `config set`, `config profile` | Manage settings and multi-org profiles |
| **Scanning** | `scan local`, `scan changed`, `scan export` | Detect dependency manifests and changed files |
| **Review** | `review context`, `review pr`, `review diff`, `review status` | Collect review context, compute risk hints, submit to backend, poll for results |

The CLI focuses on **metadata** — file paths, branch names, diff statistics, manifest detection, and risk hints. By default it does **not** send source code contents to the backend.

---

## Requirements

- **Git** installed and available on your `PATH` (the CLI shells out to `git` for repository introspection)
- **Go 1.25+** (only required if building from source)
- A PatchFlow account and API token (only required for `review pr --submit` and `review status`)

Supported platforms: macOS, Linux, Windows. The OS keychain is used for token storage when available (macOS Keychain, Windows Credential Manager, Linux secret service / D-Bus), with a restricted-permission file fallback.

---

## Installation

### Option 1 — Download a prebuilt binary

Download the latest binary for your platform from the [releases page](https://github.com/patchflow/patchflow-cli/releases), make it executable, and place it on your `PATH`:

```bash
chmod +x patchflow
sudo mv patchflow /usr/local/bin/
patchflow version
```

### Option 2 — Build from source

```bash
git clone https://github.com/patchflow/patchflow-cli.git
cd patchflow-cli
go build -o patchflow .
./patchflow version
```

Or using the Makefile:

```bash
make build      # produces ./patchflow
make all        # fmt + vet + test + build
```

### Option 3 — Install with Go

```bash
go install github.com/patchflow/patchflow-cli@latest
```

---

## Quick Start

```bash
# 1. Verify your environment
patchflow doctor

# 2. Authenticate with your API token
patchflow login --token <your-api-token>

# 3. Confirm authentication
patchflow auth status

# 4. See review context for your current branch
patchflow review context

# 5. Submit the review to the PatchFlow backend
patchflow review pr --submit

# 6. Check the status of the submitted review
patchflow review status <job-id>
```

---

## Authentication

PatchFlow CLI supports two authentication methods.

### Method 1 — API token (recommended for CI/CD)

```bash
patchflow login --token <your-api-token>
```

The token is stored securely and never written to the config file. On supported platforms it is persisted to the OS keychain (service: `PatchFlow`, account: `api-token`). On headless systems or when the keychain is unavailable, it falls back to a restricted-permission file.

### Method 2 — GitHub OAuth device flow (interactive)

```bash
patchflow login --device --client-id <your-github-oauth-client-id>
```

This initiates the GitHub OAuth device authorization grant. The CLI prints a verification URL and user code; after you authorize in the browser, the CLI polls GitHub for an access token and stores it.

> **Note:** The `--client-id` flag is required when using `--device`. It must be a GitHub OAuth App client ID with `read:user` and `repo` scopes.

### Checking authentication status

```bash
patchflow auth status
```

Output (human):

```
Authentication: authenticated (token: ****t123, storage: keychain)
```

Output (JSON):

```bash
patchflow auth status --json
```

```json
{
  "Authenticated": true,
  "MaskedToken": "****t123",
  "StorageType": "keychain"
}
```

The token is always **masked** in output — only the last 4 characters are shown. The raw token is never logged or printed.

### Logging out

```bash
patchflow logout
```

Removes the token from secure storage and clears any token lingering in the config file. This operation is idempotent — running it when already logged out succeeds silently.

### Token storage backends

| Backend | When used | Location |
|---------|-----------|----------|
| **Keychain** | Default on macOS, Windows, and Linux with a secret service | OS keyring (service `PatchFlow`, account `api-token`) |
| **File** | Fallback when keychain is unavailable | `~/.patchflow/` with `0600` permissions |
| **Config** (legacy) | Migration fallback for older installs | Read from `config.yaml` but never written there |

If you previously stored a token in the config file, running `patchflow login` again will migrate it to secure storage and clear it from the config file automatically.

---

## Configuration

### Configuration Precedence

PatchFlow CLI resolves configuration from multiple sources. Higher precedence overrides lower:

1. **Command-line flags** (`--api-url`, `--config`)
2. **Environment variables** (`PATCHFLOW_*`)
3. **Active configuration profile** (from `profiles.yaml`)
4. **Config file** (`~/.patchflow/config.yaml`)
5. **Built-in defaults**

### Config File

Path: `~/.patchflow/config.yaml`

Example:

```yaml
apiurl: https://api.patchflow.dev
org: my-org
loglevel: info
```

> The token is **never** written to this file. Use `patchflow login` to store credentials.

You can override the config file path with the global `--config <path>` flag.

### Environment Variables

| Variable | Description | Maps to |
|----------|-------------|---------|
| `PATCHFLOW_API_URL` | PatchFlow API base URL | `apiurl` |
| `PATCHFLOW_TOKEN` | API authentication token | `token` (legacy/migration) |
| `PATCHFLOW_ORG` | Default organization slug | `org` |
| `PATCHFLOW_LOG_LEVEL` | Logging verbosity | `loglevel` |

Environment variables are useful for CI/CD pipelines where you want to avoid writing config files.

### Configurable Keys

The `patchflow config set` command accepts the following keys:

| Key | Description | Example |
|-----|-------------|---------|
| `api_url` | PatchFlow API base URL | `https://api.patchflow.dev` |
| `org` | Default organization slug | `my-org` |
| `log_level` | Logging verbosity (`debug`, `info`, `warn`) | `info` |

Setting `token` via `config set` is **rejected** for security. Use `patchflow login --token <token>` instead:

```bash
$ patchflow config set token abc123
✗ error: Use 'patchflow login --token' to set the token.
```

### Configuration Profiles

Profiles let you maintain multiple configurations for different organizations, workspaces, or environments (e.g. production vs. staging). Profiles are stored in `~/.patchflow/profiles.yaml` and do **not** contain tokens (tokens remain in the keychain).

#### Create a profile

```bash
patchflow config profile create work \
  --api-url https://api.patchflow.dev \
  --org my-company \
  --log-level info
```

When flags are omitted, the profile inherits values from the current active configuration.

#### Switch to a profile

```bash
patchflow config profile use work
```

The active profile's values are merged on top of the base config at load time.

#### List all profiles

```bash
patchflow config profile list
```

Output:

```
NAME     ACTIVE  API_URL                     ORG         LOG_LEVEL
default          https://api.patchflow.dev               
work     *       https://api.patchflow.dev   my-company  info
```

The `*` marks the active profile.

#### Show profile details

```bash
patchflow config profile show work
```

Output:

```
name:      work
api_url:   https://api.patchflow.dev
org:       my-company
log_level: info
```

#### Delete a profile

```bash
patchflow config profile delete work
```

You cannot delete the `default` profile or the currently active profile.

---

## Global Flags

These flags are available on every command:

| Flag | Shorthand | Type | Default | Description |
|------|-----------|------|---------|-------------|
| `--config` | | string | `~/.patchflow/config.yaml` | Path to a custom config file |
| `--api-url` | | string | `https://api.patchflow.dev` | PatchFlow API base URL |
| `--json` | | bool | `false` | Output results as JSON |
| `--verbose` | `-v` | bool | `false` | Enable verbose (development) logging |
| `--no-color` | | bool | `false` | Disable colored output |

Examples:

```bash
patchflow --json review context
patchflow --no-color scan local
patchflow --verbose --api-url https://staging.api.patchflow.dev review pr --submit
```

---

## Commands

### `patchflow version`

Print the CLI version, commit, and build date.

```bash
$ patchflow version
patchflow version 0.1.0 (commit: dev, built: unknown)
```

```bash
$ patchflow version --json
{
  "version": "0.1.0",
  "commit": "dev",
  "date": "unknown"
}
```

---

### `patchflow doctor`

Run environment diagnostics. Verifies that Git is installed, that the current directory is inside a Git repository, and that a remote is configured.

```bash
$ patchflow doctor
PatchFlow Doctor
================
[OK] Git installed: git version 2.51.2
[OK] Inside a git repository: /home/user/project
[OK] Remote configured: git@github.com:org/repo.git
```

```bash
$ patchflow doctor --json
{
  "is_git_repo": true,
  "git_version": "git version 2.51.2",
  "repo_root": "/home/user/project",
  "remote_url": "git@github.com:org/repo.git",
  "errors": []
}
```

Run `doctor` first whenever the CLI behaves unexpectedly — it quickly surfaces missing Git, missing remote, or non-repo issues.

---

### `patchflow login`

Authenticate with the PatchFlow platform.

#### Flags

| Flag | Type | Required | Description |
|------|------|----------|-------------|
| `--token` | string | One of `--token` / `--device` | API token |
| `--device` | bool | One of `--token` / `--device` | Use GitHub OAuth device flow |
| `--client-id` | string | Required with `--device` | GitHub OAuth app client ID |

#### Token login

```bash
$ patchflow login --token my-api-token
✓ Authenticated with PatchFlow.
```

#### Device flow login

```bash
$ patchflow login --device --client-id Iv1.abc123
Please visit https://github.com/login/device and enter code: ABCD-1234
✓ Authenticated with PatchFlow via GitHub device flow.
```

---

### `patchflow logout`

Remove stored credentials.

```bash
$ patchflow logout
✓ Logged out of PatchFlow.
```

---

### `patchflow auth status`

Show authentication status with a masked token and the storage backend in use.

```bash
$ patchflow auth status
Authentication: authenticated (token: ****t123, storage: keychain)
```

```bash
$ patchflow auth status --json
{
  "Authenticated": true,
  "MaskedToken": "****t123",
  "StorageType": "keychain"
}
```

---

### `patchflow config show`

Display the current effective configuration (after merging flags, env vars, profiles, config file, and defaults). The token is shown as `***` if present, never in plaintext.

```bash
$ patchflow config show
api_url:   https://api.patchflow.dev
token:     ***
org:       my-org
log_level: info
```

```bash
$ patchflow config show --json
{
  "api_url": "https://api.patchflow.dev",
  "token": "***",
  "org": "my-org",
  "log_level": "info"
}
```

---

### `patchflow config set`

Set and persist a configuration value.

```bash
$ patchflow config set org my-org
Set org = my-org

$ patchflow config set log_level debug
Set log_level = debug

$ patchflow config set api_url https://staging.api.patchflow.dev
Set api_url = https://staging.api.patchflow.dev
```

Attempting to set `token` is rejected — use `patchflow login` instead.

---

### `patchflow config profile`

Manage configuration profiles. See [Configuration Profiles](#configuration-profiles) for full details.

| Subcommand | Description |
|------------|-------------|
| `profile create <name>` | Create a new profile |
| `profile use <name>` | Switch the active profile |
| `profile list` | List all profiles |
| `profile show <name>` | Show a profile's details |
| `profile delete <name>` | Delete a profile |

---

### `patchflow scan local`

Scan the local repository for dependency manifests and changed files. Manifests are detected up to one subdirectory deep, skipping `.git`, `vendor`, and `node_modules`.

```bash
$ patchflow scan local
Repository: /home/user/project
Detected manifests:
Type          Path
go            go.mod
node          package.json
python        requirements.txt
Total manifests: 3
```

```bash
$ patchflow scan local --json
{
  "root": "/home/user/project",
  "manifests": [
    { "path": "go.mod", "type": "go" },
    { "path": "package.json", "type": "node" },
    { "path": "requirements.txt", "type": "python" }
  ],
  "changed_files": ["cmd/root.go", "internal/api/client.go", "go.mod"]
}
```

#### Supported manifest types

| File | Detected type |
|------|---------------|
| `requirements.txt` | `python` |
| `pyproject.toml` | `python` |
| `package.json` | `node` |
| `package-lock.json` | `node-lock` |
| `pnpm-lock.yaml` | `node-lock` |
| `yarn.lock` | `node-lock` |
| `go.mod` | `go` |
| `Cargo.toml` | `rust` |
| `composer.json` | `php` |
| `Gemfile.lock` | `ruby` |
| `pom.xml` | `java` |
| `build.gradle` | `java` |

---

### `patchflow scan changed`

Scan only changed files (diffed against the base branch) and return manifests that are either at the repo root or among the changed files.

```bash
$ patchflow scan changed
Repository: /home/user/project
Changed files: 2
Detected manifests:
Type          Path
go            go.mod
Total manifests: 1
```

```bash
$ patchflow scan changed --json
{
  "root": "/home/user/project",
  "manifests": [
    { "path": "go.mod", "type": "go" }
  ],
  "changed_files": ["internal/api/client.go", "go.mod"]
}
```

---

### `patchflow scan export`

Export scan results in **SARIF 2.1.0** or **JSON** format. Useful for ingesting into CI dashboards, GitHub code scanning, or SIEM tools.

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--format` | string | `json` | Export format: `json` or `sarif` |
| `--output` | string | (stdout) | Output file path; writes to stdout if omitted |

#### Export to stdout

```bash
patchflow scan export --format sarif
```

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "PatchFlow CLI",
          "version": "0.1.0"
        }
      },
      "results": [
        {
          "ruleId": "manifest-detection",
          "message": { "text": "Detected dependency manifest: go.mod" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "go.mod" }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

#### Export to a file

```bash
patchflow scan export --format sarif --output patchflow-report.sarif
✓ Report written to patchflow-report.sarif
```

```bash
patchflow scan export --format json --output patchflow-report.json
✓ Report written to patchflow-report.json
```

> **Note:** `scan export` now runs a full analysis pipeline (SCA via OSV.dev, SAST via local tools, reachability, risk scoring) and exports real vulnerability findings — not just manifest detection results.

---

### `patchflow init`

Initialize PatchFlow in the current repository. Creates a `.patchflow/` directory with configuration, cache, baselines, and reports subdirectories.

```bash
patchflow init
✓ PatchFlow initialized.
  Config:  /path/to/repo/.patchflow/config.yml
  Dir:     /path/to/repo/.patchflow

Next steps:
  patchflow scan local      # scan the repository
  patchflow pr-review       # review changes before opening a PR
```

The `.patchflow/` directory structure:

```
.patchflow/
├── config.yml      # Project configuration
├── state.json      # Last scan state
├── .gitignore      # Ignores cache/
├── cache/          # Cached analysis results (gitignored)
├── baselines/      # Baseline snapshots for comparison
└── reports/        # Generated reports
```

Running `patchflow init` on an already-initialized repository is a no-op — it will not overwrite existing configuration.

---

### `patchflow scan run`

Run a full local security analysis: SCA (OSV.dev), SAST (local tools), reachability analysis, and risk scoring. No backend connection required.

```bash
patchflow scan run
Running SCA analysis (OSV.dev)...
Running SAST analysis (local tools)...
Running reachability analysis...

PatchFlow Analysis Report
=========================
...
Risk Score: 28/100 (LOW)
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--profile` | string | `standard` | Scan profile: `quick` (depth 1), `standard` (depth 3), `deep` (depth 5) |
| `--no-sast` | bool | false | Skip SAST analysis |
| `--no-secrets` | bool | false | Skip secret detection (gitleaks) |
| `--no-reachability` | bool | false | Skip reachability analysis |
| `--format` | string | (terminal) | Report format: `markdown`, `json`, `sarif` |
| `--output` | string | (stdout) | Write report to file |
| `--changed-only` | bool | false | Only analyze changed files |

#### Examples

```bash
# Quick scan (shallow manifest search)
patchflow scan run --profile quick

# Deep scan with all analyzers
patchflow scan run --profile deep

# SCA only (skip SAST and secrets)
patchflow scan run --no-sast --no-secrets

# Generate SARIF report
patchflow scan run --format sarif --output findings.sarif
```

---

### `patchflow pr-review`

Simulate a PR risk review before opening a pull request. Analyzes your current branch changes and computes a risk score, vulnerability findings, reachability data, and recommendations — all locally.

```bash
patchflow pr-review

PatchFlow PR Risk Review

  Branch: main → feature/add-auth
  Commit: 8b2fa32
  Files:  23 changed (+1623 / -79)

Analyzing dependencies (SCA via OSV.dev)...
Running SAST (local tools)...
Analyzing reachability...
  Report saved: .patchflow/reports/patchflow-report-20260625-163907.md

Risk Score: 28/100 — LOW

Findings by severity:
  medium      1

Top findings:
  1. [MEDIUM] golang.org/x/sys@v0.29.0: GO-2026-5024
     ...

Status: Ready for review
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--base` | string | (auto) | Base branch to compare against |
| `--head` | string | (current) | Head branch |
| `--format` | string | (terminal) | Report format: `markdown`, `json`, `sarif` |
| `--output` | string | (stdout) | Write report to file |
| `--no-sast` | bool | false | Skip SAST analysis |
| `--no-secrets` | bool | false | Skip secret detection |
| `--no-reachability` | bool | false | Skip reachability analysis |

The risk score (0-100) is computed from:
- **Vulnerability points** (SCA findings weighted by severity and reachability) — up to 50 points
- **SAST points** (static analysis findings) — up to 25 points
- **Secret points** (detected secrets) — up to 20 points
- **Change size points** (lines changed, files changed) — up to 15 points
- **Sensitivity points** (auth files, CI workflows, dependency changes) — up to 15 points
- **Reachability bonus** (reachable vulnerabilities boost score) — up to 10 points

Risk levels: `minimal` (0-19), `low` (20-39), `medium` (40-59), `high` (60-79), `critical` (80-100).

---

### `patchflow deps`

Analyze project dependencies. Subcommands:

#### `patchflow deps list`

List all dependencies parsed from manifest files.

```bash
patchflow deps list
Total dependencies: 20

NAME                                  VERSION     ECOSYSTEM  DIRECT  MANIFEST
github.com/spf13/cobra                v1.10.2     Go         no      go.mod
...
```

#### `patchflow deps tree`

Show dependencies grouped by ecosystem and manifest file.

```bash
patchflow deps tree
Dependency Tree (20 total)

├─ Go (20)
│  ├─ go.mod (20)
│  │  ├─ github.com/spf13/cobra@v1.10.2 *
│  │  ...
```

#### `patchflow deps vulnerable`

Query the OSV.dev vulnerability database and list vulnerable dependencies.

```bash
patchflow deps vulnerable
Querying OSV.dev for 20 dependencies...
Vulnerable dependencies: 1

golang.org/x/sys@v0.29.0 (Go) — 1 vulnerability(ies)
  [MEDIUM] GO-2026-5024
```

#### `patchflow deps diff`

Show dependency manifest files that changed against the base branch.

```bash
patchflow deps diff
Changed dependency manifests:
  go.mod

Dependencies in changed manifests: 20
...
```

---

### `patchflow reachability`

Determine whether a vulnerable dependency is actually imported and used in the codebase. This helps prioritize which vulnerabilities to fix first.

```bash
patchflow reachability --package github.com/spf13/cobra --explain
Package:      github.com/spf13/cobra
Reachability: HIGH

Evidence:
  Directly imported in 18 file(s):
    - cmd/auth.go
    - cmd/config.go
    ...

This package is directly imported in the codebase.
Vulnerabilities in this package are likely exploitable.
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--package` | string | (required*) | Package name to check |
| `--cve` | string | (required*) | CVE ID to find the package for |
| `--explain` | bool | false | Show evidence for the assessment |

*Either `--package` or `--cve` must be specified. When `--cve` is used, the CLI runs SCA first to find which package has that CVE.

Reachability levels:
- **HIGH** — directly imported or invoked in source code
- **MEDIUM** — direct dependency, possible runtime usage but no direct imports found
- **LOW** — transitive dependency, no direct usage
- **NONE** — not present in the import graph (vulnerabilities likely not exploitable)

Supported languages for import parsing: Python, Go, JavaScript/TypeScript.

---

### `patchflow report`

Run a full analysis and generate a report in the specified format.

```bash
# Markdown report to stdout
patchflow report --format markdown

# SARIF report to file
patchflow report --format sarif --output report.sarif

# JSON report to file
patchflow report --format json --output report.json
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--format` | string | `markdown` | Report format: `markdown`, `json`, `sarif` |
| `--output` | string | (stdout) | Output file path |

Reports are also automatically saved to `.patchflow/reports/` if the project is initialized.

---

### `patchflow review context`

Collect and display review context for the current repository: remote URL, branch, commit, base branch, change statistics, detected manifests, and risk hints.

```bash
$ patchflow review context
PatchFlow Review Context

Repository:
  Remote: git@github.com:org/repo.git
  Branch: feature/new-scan
  Commit: a1b2c3d
  Base:   main

Changes:
  Files changed: 3
  Added lines: 120
  Deleted lines: 45

Detected manifests:
  go.mod
  package.json

Risk hints:
  Dependency files changed: yes
  CI workflow changed: no
  Auth-related files changed: no

Next:
  Run: patchflow review pr --submit
```

```bash
$ patchflow review context --json
{
  "repo_root": "/home/user/project",
  "remote_url": "git@github.com:org/repo.git",
  "branch": "feature/new-scan",
  "commit_sha": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
  "base_branch": "main",
  "files_changed": 3,
  "added_lines": 120,
  "deleted_lines": 45,
  "manifests": ["go.mod", "package.json"],
  "dependency_files_changed": true,
  "ci_workflow_changed": false,
  "auth_files_changed": false
}
```

#### Risk hints explained

| Hint | True when |
|------|-----------|
| `dependency_files_changed` | Any changed file is a known dependency manifest (e.g. `go.mod`, `package.json`) |
| `ci_workflow_changed` | Any changed file is inside `.github/workflows/`, or is `.gitlab-ci.yml`, `Jenkinsfile`, or under `.circleci/` |
| `auth_files_changed` | Any changed file path contains `auth`, `login`, `session`, `jwt`, `oauth`, `password`, or `credential` (case-insensitive) |

These hints help you gauge whether a change touches sensitive areas before submitting for review.

---

### `patchflow review pr`

Preview review data for a pull request. Without `--submit`, this behaves identically to `review context` — it shows the collected context locally without contacting the backend.

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--submit` | bool | `false` | Submit the review payload to the PatchFlow backend |

#### Preview (no network)

```bash
patchflow review pr
```

Output is identical to [`review context`](#patchflow-review-context).

#### Submit to backend

```bash
$ patchflow review pr --submit
✓ Review submitted. Job ID: job-abc123
```

```bash
$ patchflow review pr --submit --json
{
  "success": true,
  "message": "Review submitted. Job ID: job-abc123"
}
```

The submitted payload contains **metadata only**: repo root, remote URL, branch, commit SHA, base branch, added/deleted line counts, and detected manifests. Source code contents are **not** sent.

#### Unauthenticated

```bash
$ patchflow review pr --submit
✗ error: Not authenticated. Run 'patchflow login --token <token>' first.
```

---

### `patchflow review diff`

Review a diff for the current repository. Currently produces the same context output as `review context`.

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--full-diff` | bool | `false` | Include full diff content (not yet implemented) |

```bash
$ patchflow review diff
PatchFlow Review Context
...
```

When `--full-diff` is passed, the CLI prints a notice that full diff mode is not yet implemented and falls back to metadata-only output.

---

### `patchflow review status`

Check the status of a previously submitted review job. Requires authentication.

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--watch` | bool | `false` | Poll every 5 seconds until the job completes or fails (max 60 attempts / 5 minutes) |

#### One-shot status

```bash
$ patchflow review status job-abc123
Job ID:     job-abc123
Status:     running
Result URL: https://api.patchflow.dev/api/v1/cli/results/job-abc123
```

```bash
$ patchflow review status job-abc123 --json
{
  "id": "job-abc123",
  "status": "running",
  "result_url": "https://api.patchflow.dev/api/v1/cli/results/job-abc123"
}
```

#### Watch mode

```bash
$ patchflow review status job-abc123 --watch
Job ID:     job-abc123
Status:     running
Result URL: ...
Job ID:     job-abc123
Status:     completed
Result URL: ...
```

Watch mode polls every 5 seconds and stops when the status is `completed` or `failed`, or after 60 attempts. It respects context cancellation (e.g. `Ctrl+C`).

---

## JSON Output for CI/CD

Every command supports the global `--json` flag for machine-readable output. This makes the CLI easy to integrate into CI/CD pipelines, scripts, and automation.

```bash
# Version info as JSON
patchflow version --json

# Review context as JSON
patchflow review context --json

# Diff review as JSON
patchflow review diff --json

# Scan changed files as JSON
patchflow scan changed --json

# Doctor diagnostics as JSON
patchflow doctor --json
```

Errors are also returned as JSON when `--json` is set:

```json
{
  "error": "Not authenticated. Run 'patchflow login --token <token>' first."
}
```

---

## SARIF and JSON Export

The `scan export` command produces standalone report files independent of the `--json` global flag:

| Format | Use case |
|--------|----------|
| `json` | Custom scripts, piping to `jq`, archiving raw scan data |
| `sarif` | GitHub Code Scanning uploads, Azure DevOps, IDE integrations |

### Uploading SARIF to GitHub Code Scanning

```bash
patchflow scan export --format sarif --output patchflow.sarif
```

Then use the GitHub `github/codeql-action/upload-sarif` action in your workflow (see the [CI/CD examples](#cicd-integration-examples)).

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Error (invalid input, API failure, authentication error, or internal error) |

Use exit codes in CI scripts to gate pipelines:

```bash
patchflow review pr --submit || exit 1
```

---

## Security and Privacy Model

PatchFlow CLI is built with a privacy-first philosophy:

- **Metadata by default.** The CLI sends file paths, branch names, diff statistics, and manifest lists — not source code contents.
- **Tokens never logged.** The `internal/auth` package masks tokens (`****` + last 4 chars) for all display. Raw tokens are never written to logs.
- **Tokens never in config files.** `patchflow login` stores tokens in the OS keychain (or a `0600`-permission file fallback). The `config set token` command is explicitly rejected.
- **Token migration.** If a token was previously stored in `config.yaml`, running `login` again migrates it to secure storage and clears it from the file.
- **Restricted file permissions.** Config and profile files are written with `0700` (directory) and `0600` (file) permissions.
- **No source code retention.** The CLI does not persist source code locally or send it remotely unless a future opt-in feature is explicitly enabled.

---

## CI/CD Integration Examples

### GitHub Actions — submit review and gate on status

```yaml
name: PatchFlow Review

on:
  pull_request:
    branches: [main]

jobs:
  patchflow:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # required for diff against base branch

      - name: Install PatchFlow CLI
        run: |
          curl -sSL https://github.com/patchflow/patchflow-cli/releases/latest/download/patchflow-linux-amd64 -o patchflow
          chmod +x patchflow
          sudo mv patchflow /usr/local/bin/

      - name: Authenticate
        env:
          PATCHFLOW_TOKEN: ${{ secrets.PATCHFLOW_TOKEN }}
        run: patchflow login --token "$PATCHFLOW_TOKEN"

      - name: Verify environment
        run: patchflow doctor

      - name: Submit review
        run: |
          JOB_ID=$(patchflow review pr --submit --json | jq -r '.message' | sed 's/.*Job ID: //')
          echo "JOB_ID=$JOB_ID" >> $GITHUB_ENV

      - name: Wait for completion
        run: patchflow review status "$JOB_ID" --watch

      - name: Export SARIF report
        run: patchflow scan export --format sarif --output patchflow.sarif

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: patchflow.sarif
```

### GitLab CI — metadata-only scan

```yaml
patchflow:scan:
  image: golang:1.25
  variables:
    PATCHFLOW_API_URL: "https://api.patchflow.dev"
  before_script:
    - go install github.com/patchflow/patchflow-cli@latest
    - patchflow login --token "$PATCHFLOW_TOKEN"
  script:
    - patchflow doctor
    - patchflow scan changed --json
    - patchflow review context --json > review-context.json
    - patchflow review pr --submit
  artifacts:
    paths:
      - review-context.json
```

### Using environment variables only (no config file)

```bash
export PATCHFLOW_API_URL=https://api.patchflow.dev
export PATCHFLOW_TOKEN=$CI_TOKEN
export PATCHFLOW_ORG=my-org

patchflow review pr --submit --json
```

---

## Troubleshooting

### `not a git repository`

The CLI must be run from inside a Git working tree. Run `patchflow doctor` to confirm. If you are in a subdirectory, the CLI will resolve the repository root automatically via `git rev-parse --show-toplevel`.

### `Not authenticated. Run 'patchflow login --token <token>' first.`

You attempted `review pr --submit` or `review status` without a stored token. Run:

```bash
patchflow login --token <your-token>
```

If running in CI, set `PATCHFLOW_TOKEN` as an environment variable instead.

### `failed to detect changed files`

The CLI diffs against the base branch (`main` or `master`, auto-detected). Ensure your repository has a remote `origin` with a default branch, or that you have at least one commit so `HEAD` exists. In CI, use `fetch-depth: 0` (or at least `fetch-depth: 2`) so the diff target is available.

### Keychain errors on Linux

The OS keychain on Linux requires a D-Bus secret service (e.g. `gnome-keyring`, `kwallet`). On headless CI runners this is typically unavailable, so the CLI falls back to a file-based token store. If you see keychain errors, ensure `PATCHFLOW_TOKEN` is set as an environment variable instead.

### No manifests detected

Manifests are detected only up to **one subdirectory deep** from the repository root. If your manifests are nested deeper (e.g. `services/auth/requirements.txt` is at depth 2), they will not be detected by `scan local`. Run `scan changed` instead, which also includes manifests that appear in the changed-files list regardless of depth.

### Colors not rendering correctly

If your terminal does not support ANSI colors, use `--no-color`:

```bash
patchflow --no-color review context
```

---

## Roadmap

The following capabilities are planned but not yet implemented in the current version (0.1.0):

- **`patchflow init`** — create a local `.patchflow/` directory with project config, baselines, and report storage
- **`patchflow scan --staged` / `--path` / `--profile`** — staged-file scans, path-scoped scans, and fast/deep analysis profiles
- **`patchflow deps`** — dependency tree, diff, vulnerability, and license analysis
- **`patchflow reachability`** — determine whether vulnerable dependencies are actually used in the codebase
- **`patchflow fix suggest` / `fix apply`** — AI-generated fix proposals with preview, dry-run, and explicit apply
- **`patchflow report`** — Markdown, SARIF, and GitHub Checks report generation with full findings
- **`review diff --full-diff`** — include full diff content in the review payload (opt-in)
- **Local analysis modes** — `local`, `remote`, `hybrid`, and `offline` execution modes
- **Baseline mode** — suppress pre-existing findings so developers are not punished for inherited debt

See [`patchflow-cli-building-context.md`](../patchflow-cli-building-context.md) for the full product vision and [`PatchFlow_CLI_Engineering_Manifesto.md`](../PatchFlow_CLI_Engineering_Manifesto.md) for the engineering philosophy.
