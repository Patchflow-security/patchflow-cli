# Development Guide

## Project Structure

```
.
├── cmd/                    # Cobra CLI commands (one file per command group)
│   ├── root.go             # Root command, global flags, context wiring
│   ├── version.go
│   ├── doctor.go
│   ├── login.go
│   ├── logout.go
│   ├── auth.go
│   ├── config.go
│   ├── scan.go
│   └── review.go
├── internal/               # Internal implementation packages
│   ├── api/                # HTTP client and PatchFlow API endpoints
│   ├── auth/               # Token lifecycle and authentication state
│   ├── config/             # Config file and environment variable loading
│   ├── doctor/             # Environment diagnostic checks
│   ├── git/                # Git repository introspection
│   ├── output/             # Human and JSON formatters
│   ├── review/             # Review context collection and risk detection
│   └── scan/               # Manifest scanning
├── pkg/                    # Public packages (importable by other projects)
│   └── version/            # Version metadata variables
├── docs/                   # Documentation
├── main.go                 # Entry point
└── go.mod
```

## Build

```bash
go build ./...
```

To build the binary:

```bash
go build -o patchflow .
```

## Test

```bash
go test ./...
```

Run with verbose output:

```bash
go test -v ./...
```

## Run

```bash
go run main.go <command>
```

Examples:

```bash
go run main.go version
go run main.go doctor
go run main.go review context --json
```

## Architecture

### `cmd/`

Each file in `cmd/` defines one or more Cobra commands. The `root.go` file wires global flags (`--config`, `--api-url`, `--json`, `--verbose`, `--no-color`), initializes the logger and formatter, and injects them into the command context via `context.WithValue`.

All command handlers retrieve dependencies from context:

- `FormatterFromContext(ctx)` — output formatting
- `ConfigFromContext(ctx)` — loaded configuration
- `LoggerFromContext(ctx)` — structured logging

### `internal/`

Packages under `internal/` are isolated by concern:

- **`internal/api`** — HTTP client for the PatchFlow API. Defines `Client`, request/response types, and error parsing.
- **`internal/auth`** — Token validation, persistence, and masking. Never logs raw tokens.
- **`internal/config`** — Viper-backed configuration loader. Supports `~/.patchflow/config.yaml`, environment variables (`PATCHFLOW_*`), and defaults.
- **`internal/doctor`** — Environment checks: Git version, repository status, remote URL.
- **`internal/git`** — Git abstraction with a `ShellExecutor` and `MockExecutor` for testing.
- **`internal/output`** — `Formatter` interface with `HumanFormatter` and `JSONFormatter` implementations.
- **`internal/review`** — Collects review context from a git repository and detects risk hints (dependency, CI, auth file changes).
- **`internal/scan`** — Scans the filesystem for dependency manifest files up to depth 1.

### `pkg/`

Packages under `pkg/` are public and may be imported by other projects.

- **`pkg/version`** — Holds `Version`, `Commit`, and `Date` variables populated at build time.

## Adding a New Command

1. Create a new file in `cmd/` (e.g., `cmd/status.go`).
2. Define the command using `cobra.Command`.
3. Register it in `init()` with `rootCmd.AddCommand(...)`.
4. Use `FormatterFromContext`, `ConfigFromContext`, and `LoggerFromContext` for dependencies.
5. Return errors via `formatter.PrintError(err)`.
6. Add tests in the relevant `internal/` package.
7. Document the command in `docs/CLI_COMMANDS.md` and `README.md`.

Example skeleton:

```go
package cmd

import "github.com/spf13/cobra"

var myCmd = &cobra.Command{
    Use:   "mycommand",
    Short: "Short description",
    RunE: func(cmd *cobra.Command, _ []string) error {
        formatter := FormatterFromContext(cmd.Context())
        return formatter.Print("Hello from mycommand")
    },
}

func init() {
    rootCmd.AddCommand(myCmd)
}
```

## Coding Standards

- **No global mutable state.** All shared state is passed through the command context.
- **All output via `internal/output`.** Commands never call `fmt.Println` directly (except `doctor`, which prints a fixed header before delegating to the formatter).
- **All config via `internal/config`.** Commands do not parse environment variables or files directly.
- **All API calls via `internal/api`.** No `http.Client` outside this package.
- **Never log or expose raw tokens.** The `internal/auth` package masks tokens for display.

## Testing Guidelines

- Prefer table-driven tests.
- Use the `internal/git.MockExecutor` to test git-dependent code without a real repository.
- Use `httptest.Server` to test API clients.
- Use `output.NewWriter(buf, jsonMode, noColor)` to capture and assert formatter output.
- Tests should not depend on the user's actual `~/.patchflow/config.yaml` or environment.

## Lint and Format

```bash
go vet ./...
gofmt -w .
```

Or use the Makefile:

```bash
make lint
make fmt
```
