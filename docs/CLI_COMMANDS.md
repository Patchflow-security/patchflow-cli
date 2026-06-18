# PatchFlow CLI Command Reference

## Global Flags

These flags are available on every command:

| Flag | Shorthand | Type | Default | Description |
|------|-----------|------|---------|-------------|
| `--config` | | string | `~/.patchflow/config.yaml` | Path to a custom config file |
| `--api-url` | | string | `https://api.patchflow.dev` | PatchFlow API base URL |
| `--json` | | bool | `false` | Output results as JSON |
| `--verbose` | `-v` | bool | `false` | Enable verbose (development) logging |
| `--no-color` | | bool | `false` | Disable colored output |

---

## `patchflow version`

Print the version number of PatchFlow CLI.

### Example (human)

```bash
$ patchflow version
patchflow version 0.1.0 (commit: dev, built: unknown)
```

### Example (JSON)

```bash
$ patchflow version --json
{
  "version": "0.1.0",
  "commit": "dev",
  "date": "unknown"
}
```

---

## `patchflow doctor`

Check the PatchFlow CLI environment. Verifies Git installation, repository status, and remote configuration.

### Example (human)

```bash
$ patchflow doctor
PatchFlow Doctor
================
[OK] Git installed: git version 2.43.0
[OK] Inside a git repository: /home/user/project
[OK] Remote configured: git@github.com:patchflow/patchflow-cli.git
```

### Example (JSON)

```bash
$ patchflow doctor --json
{
  "is_git_repo": true,
  "git_version": "git version 2.43.0",
  "repo_root": "/home/user/project",
  "remote_url": "git@github.com:patchflow/patchflow-cli.git",
  "errors": []
}
```

---

## `patchflow login --token <token>`

Authenticate with the PatchFlow platform using an API token. The token is persisted to `~/.patchflow/config.yaml`.

### Flags

| Flag | Type | Required | Description |
|------|------|----------|-------------|
| `--token` | string | Yes | API token |

### Example (human)

```bash
$ patchflow login --token my-api-token
Authenticated with PatchFlow.
```

### Example (JSON)

```bash
$ patchflow login --token my-api-token --json
{
  "success": true,
  "message": "Authenticated with PatchFlow."
}
```

---

## `patchflow logout`

Remove stored credentials and log out from the PatchFlow platform.

### Example (human)

```bash
$ patchflow logout
Logged out of PatchFlow.
```

### Example (JSON)

```bash
$ patchflow logout --json
{
  "success": true,
  "message": "Logged out of PatchFlow."
}
```

---

## `patchflow auth status`

Show authentication status and a masked view of the stored token.

### Example (human)

```bash
$ patchflow auth status
{Authenticated:true MaskedToken:****abcd}
```

### Example (JSON)

```bash
$ patchflow auth status --json
{
  "Authenticated": true,
  "MaskedToken": "****abcd"
}
```

---

## `patchflow config show`

Show the current effective configuration.

### Example (human)

```bash
$ patchflow config show
api_url:   https://api.patchflow.dev
token:     ***
org:       my-org
log_level: info
```

### Example (JSON)

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

## `patchflow config set <key> <value>`

Set a configuration value and persist it to the config file.

### Supported keys

| Key | Description |
|-----|-------------|
| `api_url` | PatchFlow API base URL |
| `org` | Default organization slug |
| `log_level` | Logging level (e.g., `debug`, `info`, `warn`) |

The `token` key is rejected. Use `patchflow login --token <token>` instead.

### Example (human)

```bash
$ patchflow config set org my-org
Set org = my-org
```

### Example (JSON)

```bash
$ patchflow config set org my-org --json
{
  "success": true,
  "message": "Set org = my-org"
}
```

### Rejected key

```bash
$ patchflow config set token abc123
error: Use 'patchflow login --token' to set the token.
```

---

## `patchflow scan local`

Scan the local repository for dependency manifests and change metadata.

### Example (human)

```bash
$ patchflow scan local
Repository: /home/user/project
Changed files: 3
Detected manifests:
  go.mod         go
  package.json   node
  requirements.txt  python
Total manifests: 3
```

### Example (JSON)

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

---

## `patchflow scan changed`

Scan only changed files for relevant manifests.

### Example (human)

```bash
$ patchflow scan changed
Repository: /home/user/project
Changed files: 2
Detected manifests:
  go.mod         go
Total manifests: 1
```

### Example (JSON)

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

## `patchflow review context`

Show review context for the current repository: remote, branch, commit, changes, detected manifests, and risk hints.

### Example (human)

```bash
$ patchflow review context
PatchFlow Review Context

Repository:
  Remote: git@github.com:patchflow/patchflow-cli.git
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

### Example (JSON)

```bash
$ patchflow review context --json
{
  "repo_root": "/home/user/project",
  "remote_url": "git@github.com:patchflow/patchflow-cli.git",
  "branch": "feature/new-scan",
  "commit_sha": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0",
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

---

## `patchflow review pr`

Preview review data for a pull request without submitting it.

### Example (human)

```bash
$ patchflow review pr
PatchFlow Review Context
Repository:
  Remote: git@github.com:patchflow/patchflow-cli.git
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

### Example (JSON)

```bash
$ patchflow review pr --json
{
  "repo_root": "/home/user/project",
  "remote_url": "git@github.com:patchflow/patchflow-cli.git",
  "branch": "feature/new-scan",
  "commit_sha": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0",
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

---

## `patchflow review pr --submit`

Submit the review payload to the PatchFlow backend. Requires authentication.

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--submit` | bool | `false` | Submit review payload to PatchFlow backend |

### Example (human)

```bash
$ patchflow review pr --submit
Review submitted. Job ID: job-abc123
```

### Example (JSON)

```bash
$ patchflow review pr --submit --json
{
  "success": true,
  "message": "Review submitted. Job ID: job-abc123"
}
```

### Unauthenticated

```bash
$ patchflow review pr --submit
error: Not authenticated. Run 'patchflow login --token <token>' first.
```

---

## `patchflow review diff`

Review a diff for the current repository.

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--full-diff` | bool | `false` | Include full diff content (not yet implemented) |

### Example (human)

```bash
$ patchflow review diff
PatchFlow Review Context
Repository:
  Remote: git@github.com:patchflow/patchflow-cli.git
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

### Example (JSON)

```bash
$ patchflow review diff --json
{
  "repo_root": "/home/user/project",
  "remote_url": "git@github.com:patchflow/patchflow-cli.git",
  "branch": "feature/new-scan",
  "commit_sha": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0",
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

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Error (invalid input, API failure, or internal error) |
