# PatchFlow CLI — Developer Guide

This guide is for engineers contributing to the PatchFlow CLI codebase. It covers architecture, conventions, the internal package layering, how to add commands, testing, and release practices.

For end-user documentation, see [`USER_GUIDE.md`](USER_GUIDE.md). For a command reference, see [`CLI_COMMANDS.md`](CLI_COMMANDS.md).

---

## Table of Contents

- [Technology Stack](#technology-stack)
- [Repository Structure](#repository-structure)
- [Build, Test, and Lint](#build-test-and-lint)
- [Architecture Overview](#architecture-overview)
- [Context Injection Pattern](#context-injection-pattern)
- [Package Reference](#package-reference)
  - [`cmd/` — Cobra Commands](#cmd--cobra-commands)
  - [`internal/config/` — Configuration](#internalconfig--configuration)
  - [`internal/auth/` — Authentication and Token Storage](#internalauth--authentication-and-token-storage)
  - [`internal/api/` — HTTP Client](#internalapi--http-client)
  - [`internal/git/` — Git Abstraction](#internalgit--git-abstraction)
  - [`internal/scan/` — Manifest Scanning](#internalscan--manifest-scanning)
  - [`internal/analysis/` — Core Analysis Types](#internalanalysis--core-analysis-types)
  - [`internal/manifest/` — Dependency Manifest Parser](#internalmanifest--dependency-manifest-parser)
  - [`internal/osv/` — OSV.dev Vulnerability Client](#internalosv--osvdev-vulnerability-client)
  - [`internal/sca/` — Software Composition Analysis](#internalsca--software-composition-analysis)
  - [`internal/sast/` — Static Analysis Security Testing](#internalsast--static-analysis-security-testing)
  - [`internal/reachability/` — Reachability Analysis](#internalreachability--reachability-analysis)
  - [`internal/risk/` — Risk Scoring Engine](#internalrisk--risk-scoring-engine)
  - [`internal/project/` — Project Initialization](#internalproject--project-initialization)
  - [`internal/report/` — Report Generator](#internalreport--report-generator)
  - [`internal/review/` — Review Context and Risk Hints](#internalreview--review-context-and-risk-hints)
  - [`internal/output/` — Output Formatting](#internaloutput--output-formatting)
  - [`internal/doctor/` — Environment Diagnostics](#internaldoctor--environment-diagnostics)
  - [`pkg/version/` — Version Metadata](#pkgversion--version-metadata)
- [Adding a New Command](#adding-a-new-command)
- [Configuration System Deep Dive](#configuration-system-deep-dive)
- [Authentication and Storage Deep Dive](#authentication-and-storage-deep-dive)
- [API Client Deep Dive](#api-client-deep-dive)
- [Export System (SARIF / JSON)](#export-system-sarif--json)
- [Testing Guidelines](#testing-guidelines)
- [Coding Standards](#coding-standards)
- [Security Considerations for Contributors](#security-considerations-for-contributors)
- [Release Process](#release-process)
- [Engineering Standards Reference](#engineering-standards-reference)

---

## Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| CLI framework | [Cobra](https://github.com/spf13/cobra) v1.10 | Command structure, flags, help generation |
| Configuration | [Viper](https://github.com/spf13/viper) v1.21 | Config files, env vars, defaults |
| Logging | [Zap](https://go.uber.org/zap) v1.28 | Structured, leveled logging |
| Keychain | [go-keyring](https://github.com/zalando/go-keyring) v0.2 | OS-native credential storage |
| YAML | `go.yaml.in/yaml/v3` | Profile serialization |
| Go version | 1.25 | Module requires `go 1.25.6` |

---

## Repository Structure

```
.
├── main.go                     # Entry point — calls cmd.Execute()
├── go.mod / go.sum             # Module definition and checksums
├── Makefile                    # build, test, vet, fmt, lint, clean, all
├── cmd/                        # Cobra commands (one file per command/group)
│   ├── root.go                 # Root command, global flags, context wiring
│   ├── version.go
│   ├── doctor.go
│   ├── login.go                # Token + GitHub device flow
│   ├── logout.go
│   ├── auth.go                 # auth status subcommand
│   ├── config.go               # config show / set
│   ├── config_profile.go       # config profile create/use/list/delete/show
│   ├── scan.go                 # scan local / changed
│   ├── scan_export.go          # scan export (sarif / json)
│   ├── review.go               # review context / pr / diff
│   └── review_status.go        # review status (--watch)
├── internal/                   # Internal implementation packages
│   ├── api/                    # HTTP client, endpoints, polling
│   ├── auth/                   # Token lifecycle, keychain/file storage, OAuth device flow
│   ├── config/                 # Config loading (Viper) + profiles (YAML)
│   ├── doctor/                 # Environment diagnostic checks
│   ├── git/                    # Git abstraction (Shell + Mock executors)
│   ├── output/                 # Human + JSON formatters
│   ├── review/                 # Review context collection + risk hint detection
│   └── scan/                   # Manifest detection + SARIF/JSON export
├── pkg/                        # Public packages (importable externally)
│   └── version/                # Version, Commit, Date (populated at build time)
├── docs/                       # Documentation
│   ├── USER_GUIDE.md           # End-user guide
│   ├── DEVELOPER_GUIDE.md      # This file
│   └── CLI_COMMANDS.md         # Command reference
├── PatchFlow_CLI_Engineering_Manifesto.md
├── PATCHFLOW_PRODUCT_PRINCIPLES.md
├── ENGINEERING_STANDARDS.md
├── ARCHITECTURE_DECISION_RECORDS.md
└── patchflow-cli-building-context.md   # Full product vision / spec
```

### Layering rules

- `cmd/` depends on `internal/*` and `pkg/*`. It contains **no business logic** — only command wiring and output delegation.
- `internal/*` packages depend on each other only when necessary (e.g. `scan` uses `git`, `review` uses `git`). No circular dependencies.
- `pkg/*` is public and dependency-free (only stdlib). Other projects may import it.
- `main.go` is a one-liner that calls `cmd.Execute()`.

---

## Build, Test, and Lint

### Build

```bash
go build ./...              # compile all packages
go build -o patchflow .     # produce the binary
make build                  # same, via Makefile
```

### Run

```bash
go run main.go <command>
go run main.go version
go run main.go review context --json
```

### Test

```bash
go test ./...               # all packages
go test -v ./...            # verbose
make test                   # via Makefile
```

### Lint and format

```bash
go vet ./...                # static analysis
gofmt -w .                  # format all files
make lint                   # vet + test
make fmt                    # gofmt
make all                    # fmt + vet + test + build
```

### Clean

```bash
make clean                  # remove the built binary
```

---

## Architecture Overview

The CLI follows a layered architecture with strict dependency injection through Go's `context.Context`.

```
main.go
  └─ cmd.Execute()
       └─ rootCmd (Cobra)
            ├─ PersistentPreRunE → loads config, logger, formatter → injects into context
            └─ Subcommands retrieve deps from context via FromContext helpers
                 ├─ cmd handlers call internal/* packages
                 └─ cmd handlers delegate output to internal/output Formatter
```

Request flow for a typical command (e.g. `review context`):

```
patchflow review context
  → cmd/review.go: runReviewContext
      → collectReviewContext()
          → git.Detect()                    (internal/git)
          → repo.DetectChangedFiles()
          → repo.DetectDiffStats()
          → review.CollectContext(repo)     (internal/review)
          → review.DetectManifests(root)
      → printContext(formatter, ctx)        (internal/output)
```

Key design properties:

- **No global mutable state.** All shared state (config, logger, formatter) is created once in `PersistentPreRunE` and passed via `context.Context`.
- **Single output channel.** Commands never call `fmt.Println` directly (the sole exception is `doctor`, which prints a fixed header before delegating to the formatter). All output goes through `internal/output.Formatter`.
- **Single config source.** Commands never read env vars or files directly — they use `ConfigFromContext`.
- **Single HTTP boundary.** No `http.Client` is constructed outside `internal/api`.
- **Token safety.** The `internal/auth` package is the only place that touches raw tokens; it masks them for all display.

---

## Context Injection Pattern

The root command's `PersistentPreRunE` (`cmd/root.go`) is the single wiring point. It:

1. Reads global flags (`--config`, `--api-url`, `--json`, `--verbose`, `--no-color`).
2. Loads configuration via `config.Load(configPath)`, applying the `--api-url` override.
3. Creates a Zap logger (development mode if `--verbose`, production otherwise).
4. Creates a formatter via `output.NewFormatter(jsonMode, noColor)`.
5. Injects all three into the command's `context.Context` using typed keys.

```go
// cmd/root.go
const (
    formatterKey contextKey = "formatter"
    configKey    contextKey = "config"
    loggerKey    contextKey = "logger"
)

ctx = context.WithValue(ctx, formatterKey, formatter)
ctx = context.WithValue(ctx, configKey, cfg)
ctx = context.WithValue(ctx, loggerKey, logger)
cmd.SetContext(ctx)
```

Commands retrieve dependencies via three helper functions:

| Helper | Returns |
|--------|---------|
| `FormatterFromContext(ctx)` | `output.Formatter` |
| `ConfigFromContext(ctx)` | `*config.Config` |
| `LoggerFromContext(ctx)` | `*zap.Logger` |

Each helper returns a safe default if the value is missing (e.g. a new production logger, an empty config), so commands never panic on a nil dependency.

---

## Package Reference

### `cmd/` — Cobra Commands

Each file in `cmd/` defines one or more Cobra commands. Commands are registered in `init()` via `rootCmd.AddCommand(...)`.

Conventions:

- Command handlers receive `cmd *cobra.Command` and retrieve dependencies from `cmd.Context()`.
- Errors are returned via `formatter.PrintError(err)` (which prints and returns nil to Cobra, preventing Cobra from printing a duplicate error).
- Subcommands are grouped under parent commands (e.g. `scan local`, `scan changed`, `scan export` under `scan`).

File-to-command mapping:

| File | Commands |
|------|----------|
| `root.go` | Root command + global flags + context wiring |
| `version.go` | `version` |
| `doctor.go` | `doctor` |
| `login.go` | `login` (`--token`, `--device`, `--client-id`) |
| `logout.go` | `logout` |
| `auth.go` | `auth status` |
| `config.go` | `config show`, `config set` |
| `config_profile.go` | `config profile create/use/list/delete/show` |
| `scan.go` | `scan local`, `scan changed` |
| `scan_export.go` | `scan export` |
| `review.go` | `review context`, `review pr`, `review diff` |
| `review_status.go` | `review status` |

### `internal/config/` — Configuration

#### `config.go`

- **`Config` struct** — holds `APIURL`, `Token`, `Org`, `LogLevel` (mapstructure tags: `apiurl`, `token`, `org`, `loglevel`).
- **`GetConfigDir()`** — returns `~/.patchflow`.
- **`Load(path)`** — uses Viper to merge: config file (`~/.patchflow/config.yaml` or custom path) → env vars (`PATCHFLOW_*`) → defaults. Then merges the active profile on top. Returns `*Config`.
- **`Save(cfg)`** — writes `apiurl`, `org`, `loglevel` to `~/.patchflow/config.yaml` with `0700` directory permissions. **Intentionally omits `token`** so credentials are never persisted to the config file.

#### `profiles.go`

- **`Profile` struct** — `Name`, `APIURL`, `Org`, `LogLevel`. No token (stored in keychain).
- **`Profiles` struct** — holds `Active` (string) and `Items` (map of name → Profile).
- **`LoadProfiles()` / `SaveProfiles(p)`** — read/write `~/.patchflow/profiles.yaml` with `0600` file permissions.
- **`Get/Set/Delete/List`** — map operations with sorted list output.
- **`DefaultProfileName`** — constant `"default"`; cannot be deleted.

The config loader merges the active profile on top of the base config: if the active profile has a non-empty `APIURL`, `Org`, or `LogLevel`, those override the base values.

### `internal/auth/` — Authentication and Token Storage

#### `auth.go`

- **`Manager`** — wraps a `*config.Config` and a `TokenStorage` backend.
- **`NewManager(cfg)`** — creates a manager with the default keychain storage.
- **`NewManagerWithStorage(cfg, storage)`** — for testing with a custom storage backend.
- **`Login(token)`** — validates non-empty, saves to storage, and clears any token from the config file (migration safety).
- **`Logout()`** — deletes from storage (idempotent), clears config token.
- **`Status()`** — returns `AuthStatus{Authenticated, MaskedToken, StorageType}`. Checks storage first, falls back to `config.Token` for legacy migration.
- **`maskToken(token)`** — returns `****` + last 4 chars for tokens ≥ 4 chars; fully masks shorter tokens; returns `"none"` for empty.

#### `storage.go`

- **`TokenStorage` interface** — `Save(token)`, `Load()`, `Delete()`.
- **`KeychainStorage`** — uses `go-keyring` with service `"PatchFlow"` and account `"api-token"`.
- **`FileStorage`** — fallback: writes to a file with `0600` permissions in a `0700` directory.
- **`NewTokenStorage()`** — returns `KeychainStorage` by default.

#### `oauth_device.go`

- **`DeviceFlow`** — implements the GitHub OAuth device authorization grant.
- **`Start()`** — POSTs to `https://github.com/login/device/code` with `scope: read:user repo`, returns `DeviceCodeResponse` (device code, user code, verification URI, interval).
- **`Poll(deviceCode, interval)`** — polls `https://github.com/login/oauth/access_token` every `interval` seconds. Handles `authorization_pending` (continue) and `slow_down` (increase interval by 5s). Returns `OAuthTokenResponse` on success.
- **`HTTPClient` interface** — stubbable for testing.

### `internal/api/` — HTTP Client

#### `client.go`

- **`Client` struct** — `baseURL`, `httpClient` (30s default timeout), `token`.
- **`NewClient(baseURL, token)`** / **`NewClientWithHTTP(...)`** — constructors.
- **`SetAuthHeader(req)`** — sets `Authorization: Bearer <token>`.
- **`Error` struct** — `StatusCode`, `Message`, `Code`; implements `error`.

#### `endpoints.go`

- **`APIClient` interface** — `PostContext`, `PostReview`, `GetStatus`. `Client` implements it (`var _ APIClient = (*Client)(nil)`).
- **`ContextPayload` / `ReviewPayload` / `StatusResponse`** — request/response types.
- **`PostContext`** — POST `/api/v1/cli/context`.
- **`PostReview`** — POST `/api/v1/cli/review`.
- **`GetStatus`** — GET `/api/v1/cli/status/{id}`.
- **`postJSON`** — internal helper: marshals payload, sets headers + auth, sends, parses `{id}` from response.
- **`parseError`** — decodes structured `{message, code}` error bodies, falls back to raw body or status text.

#### `polling.go`

- **`Poller` struct** — `Client`, `Interval` (default 5s), `MaxAttempts` (default 60).
- **`Poll(ctx, id)`** — loops `GetStatus` until `completed`/`failed` or max attempts. Respects context cancellation.

### `internal/git/` — Git Abstraction

#### `git.go`

- **`Executor` interface** — `Run(dir, args...) (string, error)`.
- **`ShellExecutor`** — runs `git` via `exec.Command`, returns combined output.
- **`Repository` struct** — `Root`, `RemoteURL`, `CurrentBranch`, `CommitSHA`, `BaseBranch`, `ChangedFiles`, `AddedLines`, `DeletedLines`, plus private `executor`.
- **`NewRepository(executor)`** — detects root (`rev-parse --show-toplevel`), branch, SHA, remote, and base branch. Falls back to `ShellExecutor` if executor is nil.
- **`Detect()`** — convenience: `NewRepository(nil)`.
- **`detectBaseBranch()`** — tries `symbolic-ref refs/remotes/origin/HEAD`, then `origin/main`, then `origin/master`.
- **`DetectChangedFiles()`** — `git diff --name-only <base>...HEAD` (falls back to `HEAD` if no base).
- **`DetectDiffStats()`** — `git diff --stat <base>...HEAD`, parsed via regex for insertion/deletion counts.
- **`MockExecutor`** — test double with `Responses` and `Errors` maps keyed by joined args; records `Calls`.

### `internal/scan/` — Manifest Scanning

#### `scan.go`

- **`manifestTypes` map** — filename → type (e.g. `go.mod` → `go`, `package.json` → `node`).
- **`skipDirs` map** — `.git`, `vendor`, `node_modules`.
- **`Result` struct** — `Root`, `Manifests []Manifest`, `ChangedFiles`.
- **`Manifest` struct** — `Path`, `Type`.
- **`DetectManifests(root)`** — walks root (depth 0) and one subdirectory deep (depth 1), skipping `skipDirs`. Returns sorted manifests.
- **`ScanLocal()`** — detects repo, scans manifests, includes changed files.
- **`ScanChanged()`** — detects repo + changed files, returns manifests at root or in the changed set.

#### `export.go`

- **SARIF 2.1.0 types** — `Report`, `Run`, `Tool`, `Driver`, `SARIFResult`, `Message`, `Location`, `PhysicalLocation`, `ArtifactLocation`.
- **`ExportSARIF(result)`** — converts each manifest to a `manifest-detection` SARIF result with the tool name `PatchFlow CLI` and version from `pkg/version`.
- **`ExportJSON(result)`** — `json.MarshalIndent` of the `Result`.

### `internal/analysis/` — Core Analysis Types

The `analysis` package defines the shared types used across all analyzers:

- **`Finding`** — normalized output of any analyzer (SCA, SAST, secret detection). Contains severity, confidence, package info, CVE ID, advisory URL, reachability status, evidence, and recommendation.
- **`Severity`** — `critical`, `high`, `medium`, `low`, `info` with `SeverityWeight()` and `SeverityOrder()` helpers.
- **`Confidence`** — `high`, `medium`, `low`.
- **`ReachabilityStatus`** — `high`, `medium`, `low`, `none`, `unknown` with `ReachabilityWeight()` for risk scoring.
- **`Dependency`** — a parsed package dependency (name, version, ecosystem, manifest path, direct/dev flags).
- **`AnalysisResult`** — the complete output of an analysis run (findings, dependencies, risk score, change stats).
- **`Ecosystem`** — `Go`, `npm`, `PyPI`, `crates.io`, `RubyGems`, `Packagist`, `Maven`.

### `internal/manifest/` — Dependency Manifest Parser

Parses dependency manifests across 8 ecosystems:

- **`Detect(root, maxDepth)`** — walks the filesystem and finds known manifest files, skipping `node_modules`, `vendor`, `.git`, etc.
- **`Parse(path)`** — dispatches to the appropriate parser based on filename.
- **`ParseAll(root, maxDepth)`** — detects and parses all manifests, returns dependencies + manifest info.

Supported formats: `go.mod`, `package.json`, `requirements.txt`, `pyproject.toml`, `Cargo.toml`, `Gemfile`, `Gemfile.lock`, `composer.json`, `pom.xml`, `build.gradle`, `build.gradle.kts`.

### `internal/osv/` — OSV.dev Vulnerability Client

Queries the [OSV.dev](https://osv.dev) public vulnerability database (free, no auth):

- **`Client.QueryBatch(ctx, deps)`** — batch query up to 1000 packages per request, returns vulnerabilities parallel to the input slice.
- **`Client.Query(ctx, name, version, ecosystem)`** — single package query.
- **`ExtractSeverity(vuln)`** — derives severity from CVSS scores, database_specific, or summary text.
- **`ExtractFixedVersion(vuln, pkgName, version)`** — finds the fixed version from affected ranges.
- **`ExtractCVEID(vuln)`** — extracts the CVE alias from a vulnerability.
- **`ExtractAdvisoryURL(vuln)`** — finds the best advisory URL from references.

### `internal/sca/` — Software Composition Analysis

The SCA analyzer ties manifest parsing and OSV.dev querying together:

- **`Analyzer.Analyze(ctx, root)`** — parses manifests, queries OSV.dev, produces normalized findings.
- **`Analyzer.ChangedOnly`** / **`Analyzer.ChangedFiles`** — filter to changed manifests only.
- **`Analyzer.MaxDepth`** — controls manifest search depth.

### `internal/sast/` — Static Analysis Security Testing

Runs embedded scanners first (always available, zero installation), then external tools as supplements:

- **`Runner.Analyze(ctx, root)`** — runs all embedded scanners and available external tools, collects findings, and applies suppression directives.
- **`Runner.AvailableTools()`** — lists installed external tools.
- **`Runner.EmbeddedTools()`** — lists embedded scanners (always available).

**Embedded scanners** (in `internal/sast/`):
- **`gosast/`** — Go SAST scanner with 32 AST-based rules ported from gosec v2.27.1. Uses `golang.org/x/tools/go/packages` for type-aware AST analysis. Rules: `analyzer.go` (orchestration), `helpers.go` (CallList, GetCallInfo, TryResolve), `rules.go` (22 rules), `rules_extra.go` (10 rules).
- **`secrets/`** — Regex-based secret scanner with 35 curated patterns plus Shannon entropy detection. Skips `.venv/`, `node_modules/`, `.env.example`, binary files. Redacts evidence in output.
- **`patterns/`** — Multi-language regex pattern scanner for Python, JavaScript/TypeScript, Ruby, PHP. 40 rules covering OWASP Top 10. Language detection by file extension. Comment skipping per language.
- **`suppression/`** — Comment-based suppression directive parser. Supports `//patchflow:ignore <RULE_ID>` and `# patchflow:ignore` (blanket). Caches per-file directives.

**External tools** (optional, supplement embedded scanners):
- `gosec` (Go), `bandit` (Python), `semgrep` (multi-language), `gitleaks` (secrets).
- Each tool has an `IsAvailable()` check and a `Run()` function that parses JSON output.

**Rule ID conventions**:
- Go SAST: `G1xx` (injection/crypto), `G2xx` (SQL), `G3xx` (filesystem), `G4xx` (crypto/TLS), `G5xx` (blocklist), `G6xx` (memory)
- Secrets: `SECRET-<NAME>` (e.g., `SECRET-AWS-Access-Key-ID`)
- Patterns: `PY0xx` (Python), `JS0xx` (JS/TS), `RB0xx` (Ruby), `PHP0xx` (PHP), `XLANG0xx` (cross-language)

**Adding a new Go SAST rule**:
1. Implement the `Rule` interface (`ID()`, `Match()`, `Nodes()`) in `rules.go` or `rules_extra.go`
2. Use `callListRule` for simple call-pattern rules, or custom struct for complex logic
3. Register in `registerDefaultRules()` in `analyzer.go`
4. Add a test in `analyzer_test.go` or `rules_extra_test.go`

**Adding a new pattern rule**:
1. Add a `PatternRule` to `registerRules()` in `patterns/scanner.go`
2. Specify `ID`, `Title`, `Description`, `Severity`, `Confidence`, `Languages`, `Pattern` (compiled regex)
3. Add a test in `patterns/scanner_test.go`

### `internal/reachability/` — Reachability Analysis

Determines whether vulnerable dependencies are actually used in the codebase:

- **`Analyzer.Analyze(ctx, root, findings, deps)`** — builds an import graph and updates SCA findings with reachability metadata.
- **`Analyzer.AssessPackage(root, pkgName)`** — directly assesses a single package's reachability.
- Parses imports for Python (`import`/`from`), Go (`import` blocks and single-line), JavaScript/TypeScript (`import`/`require`/dynamic `import()`).
- Builds an `ImportGraph` mapping files to imported packages and packages to importing files.
- Reachability levels: `HIGH` (directly imported), `MEDIUM` (direct dep, no imports), `LOW` (transitive), `NONE` (not in graph).

### `internal/risk/` — Risk Scoring Engine

Computes a 0-100 risk score from findings and change metadata:

- **`Engine.Compute(input)`** — returns a `ScoreOutput` with the total score, level, breakdown by component, and top findings.
- Score components: vulnerability points (up to 50), SAST points (up to 25), secret points (up to 20), change size points (up to 15), sensitivity points (up to 15), reachability bonus (up to 10).
- Risk levels: `minimal` (0-19), `low` (20-39), `medium` (40-59), `high` (60-79), `critical` (80-100).

### `internal/project/` — Project Initialization

Manages the `.patchflow/` directory structure:

- **`Init(root)`** — creates `.patchflow/` with `config.yml`, `state.json`, `.gitignore`, and `cache/`, `baselines/`, `reports/` subdirectories.
- **`LoadConfig(root)`** — reads and parses `config.yml`.
- **`IsInitialized(root)`** — checks if `.patchflow/` exists.
- **`DefaultConfig()`** — returns the default configuration (local mode, standard profile, reachability + SAST + secrets enabled, secrets redacted).

### `internal/report/` — Report Generator

Generates reports in multiple formats from analysis results:

- **`Generator.TerminalSummary()`** — human-readable terminal output.
- **`Generator.Markdown()`** — full Markdown report with summary, risk score, findings, dependencies, and recommendations.
- **`Generator.JSON()`** — structured JSON report.
- **`Generator.SARIF(toolVersion)`** — SARIF 2.1.0 report for CI integration.
- **`Generator.WriteFile(format, path)`** — writes a report to a file.
- **`Generator.WriteToReportsDir(root, format)`** — writes to `.patchflow/reports/` with a timestamped filename.

### `internal/review/` — Review Context and Risk Hints

#### `review.go`

- **`Context` struct** — `RepoRoot`, `RemoteURL`, `Branch`, `CommitSHA`, `BaseBranch`, `FilesChanged`, `AddedLines`, `DeletedLines`, `Manifests`, `DependencyFilesChanged`, `CIWorkflowChanged`, `AuthFilesChanged`.
- **`CollectContext(repo)`** — maps `git.Repository` fields to `review.Context` and computes risk hints by scanning changed file paths.
- **`DetectManifests(root)`** — glob-based manifest detection (depth 0 + 1), returns unique relative paths.
- **`isDependencyFile(path)`** — checks basename against the manifest list.
- **`isCIWorkflow(path)`** — checks for `.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`, `.circleci/`.
- **`isAuthFile(path)`** — case-insensitive check for `auth`, `login`, `session`, `jwt`, `oauth`, `password`, `credential`.

### `internal/output/` — Output Formatting

#### `output.go`

- **`Formatter` interface** — `Print(any)`, `PrintError(error)`, `PrintSuccess(string)`, `PrintTable(headers, rows)`.
- **`HumanFormatter`** — writes to an `io.Writer`; supports `noColor` mode (`[ERR]`/`[OK]` prefixes vs `✗`/`✓`). `Print` handles `string`, `fmt.Stringer`, and default `%+v`. `PrintTable` does column-aligned padding.
- **`JSONFormatter`** — `json.MarshalIndent` for `Print`; structured `{error: ...}` for `PrintError`; structured `{success, message}` for `PrintSuccess`; array of objects for `PrintTable`.
- **`NewFormatter(jsonMode, noColor)`** — returns a formatter writing to `os.Stdout`.
- **`NewWriter(w, jsonMode, noColor)`** — returns a formatter writing to a custom writer (for tests).
- **`IsJSON(f)`** — type assertion helper used by commands that need branching logic.

### `internal/doctor/` — Environment Diagnostics

#### `doctor.go`

- **`Report` struct** — `IsGitRepo`, `GitVersion`, `RepoRoot`, `RemoteURL`, `Errors`.
- **`Run()`** — checks `git --version`, then `git.Detect()`. Returns a report; never returns an error (failures are captured in `report.Errors`).

### `pkg/version/` — Version Metadata

#### `version.go`

- **`Version`** (`"0.1.0"`), **`Commit`** (`"dev"`), **`Date`** (`"unknown"`) — package-level vars, overridable at build time via `-ldflags`.
- **`BuildInfo()`** — returns `"patchflow version <v> (commit: <c>, built: <d>)"`.

---

## Adding a New Command

Follow this step-by-step process to add a command. The example adds a `patchflow status` command.

### 1. Create the command file

Create `cmd/status.go`:

```go
package cmd

import (
    "github.com/patchflow/patchflow-cli/internal/output"
    "github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
    Use:   "status",
    Short: "Show the status of the current workspace",
    RunE: func(cmd *cobra.Command, _ []string) error {
        formatter := FormatterFromContext(cmd.Context())
        return formatter.Print("Workspace OK")
    },
}

func init() {
    rootCmd.AddCommand(statusCmd)
}
```

### 2. Add flags (if needed)

```go
func init() {
    statusCmd.Flags().BoolVar(&verboseFlag, "verbose", false, "Show extended status")
    rootCmd.AddCommand(statusCmd)
}
```

### 3. Implement business logic in `internal/`

Do **not** put business logic in `cmd/`. Create or extend an `internal/` package:

```go
// internal/workspace/workspace.go
package workspace

type Status struct {
    Healthy bool   `json:"healthy"`
    Message string `json:"message"`
}

func Check() (*Status, error) {
    // ... implementation ...
    return &Status{Healthy: true, Message: "OK"}, nil
}
```

### 4. Wire the command to the internal package

```go
RunE: func(cmd *cobra.Command, _ []string) error {
    formatter := FormatterFromContext(cmd.Context())
    status, err := workspace.Check()
    if err != nil {
        return formatter.PrintError(err)
    }
    return formatter.Print(status)
},
```

### 5. Handle JSON vs human output

If your output needs different rendering for JSON and human modes, branch on `output.IsJSON(formatter)`:

```go
if output.IsJSON(formatter) {
    return formatter.Print(status)
}
return formatter.Print(fmt.Sprintf("Healthy: %s — %s", status.Healthy, status.Message))
```

Alternatively, make your output struct implement `fmt.Stringer` so `HumanFormatter.Print` calls `.String()` automatically:

```go
func (s Status) String() string {
    return fmt.Sprintf("Healthy: %v — %s", s.Healthy, s.Message)
}
```

### 6. Add tests

Add tests in the relevant `internal/` package using table-driven tests and mocks. See [Testing Guidelines](#testing-guidelines).

### 7. Document the command

- Add an entry to [`docs/CLI_COMMANDS.md`](CLI_COMMANDS.md) with flags, human output, and JSON output examples.
- Add a section to [`docs/USER_GUIDE.md`](USER_GUIDE.md) under the Commands section.
- Add a row to the commands table in [`README.md`](../README.md).

---

## Configuration System Deep Dive

### Load order (inside `config.Load`)

```
1. Viper reads config file:
     - explicit path from --config, OR
     - ~/.patchflow/config.yaml, OR
     - ./config.yaml (cwd)
2. Viper binds env vars (PATCHFLOW_API_URL, PATCHFLOW_TOKEN, PATCHFLOW_ORG, PATCHFLOW_LOG_LEVEL)
3. Viper applies defaults (apiurl = https://api.patchflow.dev)
4. Viper unmarshals into Config
5. Active profile is loaded from profiles.yaml and merged on top (non-empty fields override)
```

### Save behavior

`config.Save(cfg)` writes only `apiurl`, `org`, `loglevel` — **never `token`**. The config directory is created with `0700` permissions. This is a deliberate security boundary: even if `config.yaml` is leaked or committed by accident, no credentials are exposed.

### Profile merge semantics

Profiles store non-secret configuration for different contexts. When `profiles.Active` is set and the named profile exists, its non-empty fields override the base config:

```go
if prof.APIURL != "" { cfg.APIURL = prof.APIURL }
if prof.Org != ""    { cfg.Org = prof.Org }
if prof.LogLevel != "" { cfg.LogLevel = prof.LogLevel }
```

This means a profile can selectively override only some fields while inheriting the rest from the base config.

### Adding a new config key

1. Add the field to the `Config` struct in `internal/config/config.go` with a `mapstructure` tag.
2. Add a `v.SetDefault(...)` and `v.BindEnv(...)` in `Load()`.
3. Add the key to the `switch` in `cmd/config.go` (`configSetCmd`).
4. Add the field to `Profile` in `internal/config/profiles.go` if it should be profile-scoped, and to the merge logic in `Load()`.
5. Add the field to `configShowOutput` in `cmd/config.go`.
6. Update tests in `internal/config/config_test.go` and `profiles_test.go`.
7. Document the key in `USER_GUIDE.md` and `CLI_COMMANDS.md`.

---

## Authentication and Storage Deep Dive

### Storage backend selection

`NewTokenStorage()` returns `KeychainStorage` unconditionally. The `go-keyring` library handles platform dispatch:

| Platform | Backend |
|----------|---------|
| macOS | Keychain |
| Windows | Credential Manager |
| Linux | Secret Service (D-Bus) — requires `gnome-keyring` or similar |

If keychain operations fail at runtime (e.g. headless Linux without a secret service), callers receive an error. For CI environments, prefer setting `PATCHFLOW_TOKEN` as an environment variable, which Viper binds into `config.Token` and the auth manager reads as a migration fallback.

### Token masking rules

`maskToken(token)`:

| Token length | Output |
|--------------|--------|
| Empty | `"none"` |
| 1–3 chars | all `*` (e.g. `***`) |
| 4+ chars | `****` + last 4 chars (e.g. `****t123`) |

### Migration flow

If a user upgrades from an older CLI version that stored tokens in `config.yaml`:

1. `Status()` checks keychain first; if not found, falls back to `config.Token` and reports `StorageType: "config"`.
2. `Login(token)` saves to keychain and then clears `config.Token` by calling `config.Save` (which omits the token).
3. Subsequent `Status()` calls report `StorageType: "keychain"`.

This makes the migration transparent — users do not need to re-authenticate.

### Adding a new storage backend

1. Implement the `TokenStorage` interface (`Save`, `Load`, `Delete`).
2. Add a case to `storageTypeName()` in `auth.go` for human-readable status output.
3. Update `NewTokenStorage()` if it should be a default, or provide a separate constructor.
4. Add tests using `NewManagerWithStorage(cfg, yourBackend)`.

---

## API Client Deep Dive

### Endpoint contract

The CLI expects three backend endpoints:

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/v1/cli/context` | Submit context payload, returns `{id}` |
| POST | `/api/v1/cli/review` | Submit review payload, returns `{id}` |
| GET | `/api/v1/cli/status/{id}` | Get job status, returns `{id, status, result_url}` |

All requests include `Authorization: Bearer <token>` and `Content-Type: application/json`.

### Error handling

`parseError(resp)` decodes the response body as `{message, code}` if possible. If JSON parsing fails, it uses the raw body as the message. If the body is empty, it uses `http.StatusText(statusCode)`. The resulting `*api.Error` includes `StatusCode`, `Message`, and `Code`.

### Polling

Two polling mechanisms exist:

- **`api.Poller`** (`internal/api/polling.go`) — reusable poller with configurable interval and max attempts. Used programmatically.
- **`watchStatus`** (`cmd/review_status.go`) — command-level polling for `review status --watch`. Polls every 5s, max 60 attempts (5 minutes), respects context cancellation.

When adding new async operations, prefer reusing `api.Poller` rather than reimplementing the loop.

### Adding a new endpoint

1. Add request/response types to `internal/api/endpoints.go`.
2. Add the method to the `APIClient` interface.
3. Implement it on `Client` (use `postJSON` for POSTs or build a request directly for GETs).
4. Add a test in `internal/api/client_test.go` using `httptest.Server`.
5. Wire a command in `cmd/` that calls the new method.
6. Document the endpoint contract in this guide and in `CLI_COMMANDS.md`.

---

## Export System (SARIF / JSON)

The `scan export` command (`cmd/scan_export.go`) delegates to `internal/scan/export.go`:

- **`ExportJSON(result)`** — straightforward `json.MarshalIndent` of `scan.Result`.
- **`ExportSARIF(result)`** — builds a SARIF 2.1.0 report with one run. Each manifest becomes a `manifest-detection` result with a location pointing to the manifest path. The tool driver is `PatchFlow CLI` with the version from `pkg/version`.

The export command bypasses the formatter for file output (it writes raw bytes to the file), but uses the formatter for the success message. When no `--output` is given, it writes directly to stdout via `fmt.Fprintln` (this is an acceptable exception since the export output is the report itself, not CLI messaging).

### Extending SARIF output

To add real findings (vulnerabilities, SAST results) to the SARIF report:

1. Extend `scan.Result` to include findings (or create a separate findings struct).
2. Map each finding to a `SARIFResult` with an appropriate `ruleId`, `message`, and `location` (file path + line range).
3. Add SARIF rule definitions to the `Run.Tool.Driver` if needed.
4. Update `ExportSARIF` to include both manifest detections and findings.

---

## Testing Guidelines

### Principles

- **Table-driven tests** are the preferred pattern across the codebase.
- **No external dependencies.** Tests must not depend on the user's actual `~/.patchflow/config.yaml`, environment variables, or a real Git repository.
- **Use mocks and test servers** to isolate the code under test.

### Tools and patterns

| What to test | Tool / pattern |
|--------------|----------------|
| Git-dependent code | `git.MockExecutor` with pre-configured `Responses` and `Errors` maps |
| API client | `httptest.Server` returning canned JSON |
| Formatter output | `output.NewWriter(&buf, jsonMode, noColor)` then assert on `buf.String()` |
| Auth/storage | `auth.NewManagerWithStorage(cfg, fakeStorage)` with a custom `TokenStorage` |
| Config loading | Temp directory + explicit config path via `--config` or `config.Load(path)` |
| OAuth device flow | Custom `HTTPClient` returning canned `DeviceCodeResponse` / `OAuthTokenResponse` |

### Example: testing a git-dependent function

```go
func TestCollectContext(t *testing.T) {
    exec := &git.MockExecutor{
        Responses: map[string]string{
            "rev-parse --show-toplevel":          "/fake/repo",
            "rev-parse --abbrev-ref HEAD":        "feature/x",
            "rev-parse HEAD":                     "abc123",
            "remote get-url origin":              "git@github.com:org/repo.git",
            "symbolic-ref refs/remotes/origin/HEAD": "refs/remotes/origin/main",
            "diff --name-only main...HEAD":       "auth/login.go\nauth/session.go",
            "diff --stat main...HEAD":            "2 files changed, 10 insertions(+), 5 deletions(-)",
        },
    }
    repo, err := git.NewRepository(exec)
    // ... assert on repo fields ...
}
```

### Example: testing formatter output

```go
func TestHumanFormatter(t *testing.T) {
    var buf bytes.Buffer
    f := output.NewWriter(&buf, false, true) // human, no color
    _ = f.PrintError(errors.New("boom"))
    assert.Contains(t, buf.String(), "[ERR] error: boom")
}
```

### Example: testing the API client

```go
func TestPostReview(t *testing.T) {
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        assert.Equal(t, "/api/v1/cli/review", r.URL.Path)
        assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
        _ = json.NewEncoder(w).Encode(map[string]string{"id": "job-123"})
    }))
    defer srv.Close()

    client := api.NewClientWithHTTP(srv.URL, "test-token", srv.Client())
    id, err := client.PostReview(context.Background(), api.ReviewPayload{Submit: true})
    require.NoError(t, err)
    assert.Equal(t, "job-123", id)
}
```

### Running tests

```bash
go test ./...                    # all
go test -v ./internal/scan/...   # one package, verbose
go test -run TestScanLocal ./internal/scan/  # one test
go test -race ./...              # with race detector
go test -cover ./...             # with coverage
```

---

## Coding Standards

These standards are enforced by convention and review. See [`ENGINEERING_STANDARDS.md`](../ENGINEERING_STANDARDS.md) for the full list.

### Go conventions

- **Cobra** for CLI commands; **Viper** for config; **Zap** for logging.
- **Context propagation** is mandatory — pass `context.Context` to all functions that can be cancelled or carry deadlines.
- **Error wrapping** with `%w` is required: `fmt.Errorf("failed to X: %w", err)`.
- **No global mutable state.** Shared state flows through `context.Context`.
- **No `fmt.Println` in commands** (exception: `doctor`'s fixed header). All output via `internal/output`.
- **No direct env var reads in commands.** All config via `internal/config`.
- **No `http.Client` outside `internal/api`.**

### Formatting

```bash
gofmt -w .
go vet ./...
```

### Commit conventions

Follow the existing commit prefix style:

| Prefix | Use |
|--------|-----|
| `feat:` | New feature |
| `fix:` | Bug fix |
| `refactor:` | Code restructuring without behavior change |
| `docs:` | Documentation |
| `test:` | Test additions or fixes |
| `chore:` | Tooling, deps, CI |

Branch naming: `feat/*`, `fix/*`, `chore/*`, `refactor/*`, `docs/*`.

---

## Security Considerations for Contributors

These rules are non-negotiable. Violations must be caught in review.

### Never

- **Log raw tokens.** The `internal/auth` package is the only place that handles raw tokens, and it masks them immediately for display.
- **Write tokens to config files.** `config.Save` intentionally omits the token field. Do not add it.
- **Print credentials in error messages.** Wrap errors without including sensitive values.
- **Store repository source code permanently.** The CLI is metadata-only by default.
- **Trust AI output without validation.** (Applies to future AI features — deterministic systems verify facts.)

### Always

- **Validate inputs.** Check for empty tokens, invalid paths, unknown config keys.
- **Use restricted file permissions.** `0700` for config directories, `0600` for token/profile files.
- **Mask tokens for display.** Use `maskToken()` from `internal/auth`.
- **Wrap errors with context.** Help users understand what failed and why.
- **Respect context cancellation.** Long-running operations (polling, HTTP) must check `ctx.Done()`.

### Adding security-sensitive code

If your change touches authentication, token storage, or the API client:

1. Review the [Security and Privacy Model](USER_GUIDE.md#security-and-privacy-model) in the user guide.
2. Ensure no new code path can leak a raw token.
3. Add tests that verify masking behavior.
4. Consider the CI/headless case where the keychain is unavailable.

---

## Release Process

### Versioning

The CLI uses semantic versioning. The current version (`0.1.0`) is set in `pkg/version/version.go` and can be overridden at build time:

```bash
go build -ldflags "-X github.com/patchflow/patchflow-cli/pkg/version.Version=0.2.0 -X github.com/patchflow/patchflow-cli/pkg/version.Commit=$(git rev-parse --short HEAD) -X github.com/patchflow/patchflow-cli/pkg/version.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o patchflow .
```

### Release checklist

1. Update `pkg/version/version.go` `Version` to the new semver.
2. Ensure all tests pass: `make all`.
3. Build cross-platform binaries (linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64) with ldflags injecting `Version`, `Commit`, and `Date`.
4. Tag the release: `git tag v0.2.0 && git push origin v0.2.0`.
5. Create a GitHub Release with the binaries attached.
6. Update `README.md` and `USER_GUIDE.md` if the installation instructions or command set changed.

### Makefile targets

| Target | Action |
|--------|--------|
| `make build` | Compile to `./patchflow` |
| `make test` | `go test ./...` |
| `make vet` | `go vet ./...` |
| `make fmt` | `gofmt -w .` |
| `make lint` | `go vet ./... && go test ./...` |
| `make clean` | Remove `./patchflow` |
| `make all` | `fmt` + `vet` + `test` + `build` |

---

## Engineering Standards Reference

The following project documents define the broader engineering philosophy and standards. Contributors should read them:

- [`PatchFlow_CLI_Engineering_Manifesto.md`](../PatchFlow_CLI_Engineering_Manifesto.md) — vision, core principles, technology stack, AI principles
- [`PATCHFLOW_PRODUCT_PRINCIPLES.md`](../PATCHFLOW_PRODUCT_PRINCIPLES.md) — 10 product principles (context > diff, signal > noise, explain > block, etc.)
- [`ENGINEERING_STANDARDS.md`](../ENGINEERING_STANDARDS.md) — general principles, Git standards, Go/Python standards, testing, observability, security
- [`ARCHITECTURE_DECISION_RECORDS.md`](../ARCHITECTURE_DECISION_RECORDS.md) — ADR template and initial ADRs (ADR-0001: Go for CLI, ADR-0005: AI Explain / Deterministic Verify, etc.)
- [`patchflow-cli-building-context.md`](../patchflow-cli-building-context.md) — full product vision, planned commands, data models, analyzer plugin interface, backend integration plan
