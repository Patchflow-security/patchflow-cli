# PatchFlow CLI — Change Intelligence for Engineering Teams

PatchFlow CLI provides change intelligence for engineering teams. Use it to scan, review, and analyze code changes in your repositories.

## Installation

Download the latest binary for your platform from the [releases page](https://github.com/patchflow/patchflow-cli/releases), or build from source:

```bash
go build -o patchflow .
```

## Quick Start

```bash
# Authenticate
patchflow login --token <your-api-token>

# Verify your environment
patchflow doctor

# Review local changes
patchflow review context

# Submit a review to PatchFlow
patchflow review pr --submit
```

## Commands

| Command | Description |
|---------|-------------|
| `patchflow version` | Print the version number |
| `patchflow doctor` | Check the CLI environment |
| `patchflow login --token <token>` | Authenticate with PatchFlow |
| `patchflow logout` | Remove stored credentials |
| `patchflow auth status` | Show authentication status |
| `patchflow config show` | Show current configuration |
| `patchflow config set <key> <value>` | Set a configuration value |
| `patchflow scan local` | Scan the local repository |
| `patchflow scan changed` | Scan changed files only |
| `patchflow review context` | Show review context for the current repository |
| `patchflow review pr` | Preview review data for a pull request |
| `patchflow review pr --submit` | Submit a review to the PatchFlow backend |
| `patchflow review diff` | Review a diff |
| `patchflow review diff --json` | Review a diff and output JSON |

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
patchflow scan local
patchflow scan changed
```

## Development

Run tests:

```bash
make test
```

Build:

```bash
make build
```

See [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) for the full developer guide.
