# PatchFlow CLI Development Guide

## Project Structure

`patchflow-cli` is a Go-based SAST/SCA security scanner. Key packages:

- **`internal/frameworks/`** — framework detection layer (types, signatures, detector)
- **`internal/sast/frameworks/`** — framework rule model, registry, loader, matcher
  - **`rails/`** — reference framework pack (sources, sinks, sanitizers, rules)
  - **`packs/`** — pack registration + governance maturity bridge
- **`internal/sast/`** — SAST runner orchestrating all embedded + external scanners
  - `patterns/` — multi-language regex scanner
  - `taintpatterns/` — tree-sitter source→sink taint engine
  - `treesitter/` — AST rules
  - `filecollector.go` — single-pass parallel file dispatch
- **`internal/rules/`** — governance registry (maturity, profiles, CWE/OWASP)
- **`cmd/`** — cobra CLI commands (`scan run`, `rules`, `explain`)

## Build & Test Commands

```bash
# Build
go build ./...

# Vet
go vet ./...

# Run framework foundation tests
go test ./internal/frameworks/ ./internal/sast/frameworks/ ./internal/sast/frameworks/rails/ ./internal/sast/frameworks/packs/ -v

# Run all SAST + rules tests
go test ./internal/sast/... ./internal/rules/...

# Build the CLI binary
go build -o patchflow .
```

## Framework Pack Architecture

Framework-specific rules are **official embedded packs**, not user YAML. The flow:

```
1. Detect frameworks (internal/frameworks.Detector) via filesystem signals
2. Select packs (frameworks.Loader) based on detection + CLI config
3. Pattern/template rules → frameworks.Matcher (line-oriented, sanitizer-aware)
4. Taint rules → registered into taintpatterns.Analyzer (source→sink tracking)
5. Findings deduplicated by the SAST runner
```

### Adding a new framework pack

1. Create `internal/sast/frameworks/<name>/` with:
   - `pack.go` — implements `frameworks.Pack` (Name, Language, FileExtensions, TemplateExtensions, Rules, Sources, Sinks, Sanitizers)
   - `sources.go`, `sinks.go`, `sanitizers.go`, `templates.go`, `rules.go`
2. Register the pack in `internal/sast/frameworks/packs/default_registry.go`.
3. Add detection signals in `internal/frameworks/signatures.go`.
4. Add vulnerable/safe/normal fixtures under `tests/`.
5. Set `Maturity: MaturityExperimental` until fixtures pass; promote to `Beta`/`Stable` as tests and regression corpora grow.

### Rule model

A `FrameworkRule` declares a `MatchMode`:
- `MatchPattern` — regex against source lines (simple dangerous APIs)
- `MatchAST` — framework-specific call structures (tree-sitter, reserved)
- `MatchTaint` — source→sink taint (feeds the taintpatterns engine)
- `MatchTemplate` — ERB/Jinja/Razor/Blade/JSX output issues

Each rule carries `Sources`, `Sinks`, `Sanitizers`, `SafePatterns`, `Exclusions`, and `Maturity` for governance.

### Import cycle notes

- `internal/sast/frameworks` defines its own `Maturity` type (not `rules.Maturity`) to avoid an import cycle with `internal/rules` (which imports `internal/sast`).
- The `packs` subpackage bridges `frameworks.Maturity` → `rules.Maturity` via `ToRulesMaturity`.
- `rules.BuildRegistryFromRunner` was removed (it was unused and created a cycle). Use `packs.RegisterFrameworkRules(reg)` to add framework rules to a governance registry.

## CLI Surface

```bash
# Scan with auto-detected framework packs (default)
patchflow scan run

# Scan with unified config flag (B11.5.4)
patchflow scan run --config .patchflow/rules.yaml

# Force-enable a specific pack
patchflow scan run --framework rails

# Disable a pack even if detected
patchflow scan run --disable-framework spring

# List all official packs and detection status
patchflow rules list-frameworks

# List rules in a specific pack
patchflow rules list --framework rails

# Explain a framework rule (shows sources/sinks/sanitizers)
patchflow explain --rule PF-RAILS-XSS-001

# Validate rules config (B11.5.5 + B12.6)
patchflow rules validate .patchflow/rules.yaml

# Config management (B12.5)
patchflow config validate
patchflow config migrate

# CI templates (B12.7)
patchflow ci init github
patchflow ci init gitlab --profile ci-blocking

# Version with full metadata (B12.1)
patchflow version --json

# Doctor diagnostic (B12.8)
patchflow doctor --json
```

## Release Hardening (B12)

- **Version**: `patchflow version --json` outputs version, commit, go_version, ruleset_version, schema_version, sarif_version
- **Doctor**: `patchflow doctor` checks version, git, config, cache, SARIF output, embedded scanners, external tools
- **Config migration**: `patchflow config migrate` adds schema_version and suggests framework_extensions
- **CI templates**: `patchflow ci init {github,gitlab,circleci,azure,pre-commit}` with audit/starter/ci-blocking profiles
- **Smoke fixtures**: `internal/testdata/release-smoke/` with 5 fixtures (spring, graphql, express, clean-go, clean-python)
- **GoReleaser**: 6 targets (linux/darwin/windows × amd64/arm64), checksums, SBOMs, cosign signing, Homebrew, Scoop, Docker
- **Release process**: See `RELEASE.md` and `PATCHFLOW_CLI_RC1_BASELINE.md`

## Governance

Framework rules register under `EngineFrameworks` in the governance registry. Default maturity is `experimental` (audit profile only, non-blocking). Promote rules to `beta`/`stable` as they gain test fixtures and regression coverage, which activates them in PR/CI profiles and makes high/critical findings blocking-eligible.

## Dedup and Grouping (B10)

The SAST runner has a multi-phase dedup pipeline:

1. **Cross-scanner dedup** (`dedupFindings`) — same file+line+rule, prefer AST/taint over regex.
2. **Semantic dedup** (`semanticDedupFindings`) — same rule+file+evidence across different lines.
3. **Base/IP dedup** (`dedupBaseVsInterprocedural`) — merge `TP-JS001` base with `TP-JS001-IP` interprocedural variant on same line. IP variant kept (longer taint path).
4. **Issue grouping** (`groupIssues`) — group related findings in same function. Uses function boundary detection (reads source files for `def`/`class`/`function`/`func` patterns) as primary strategy. Proximity (10-line window) is fallback only. Methods with same name in different classes are separated using `name@startLine` keys. Findings are NOT dropped — primary carries `OccurrenceCount` and `RelatedLocations`.

Finding fingerprints:
- `SemanticFingerprint` — line-number independent (rule+analyzer+file+evidence).
- `LocationFingerprint` — includes line number (SARIF partialFingerprints).
- `DedupFingerprint` — groups base/IP variants (strips -IP suffix, includes line).
- `IssueGroupID` — groups same-function findings (rule+file+function+line).

## Performance

- All regex patterns are precompiled at scanner initialization (`regexp.MustCompile` in `NewScanner()`/`registerRules()`). No recompilation on each scan.
- Framework registry is a package-level singleton (`sync.Once`), shared across all Runner instances.
- Framework detection is ~12ms, called once per scan.
- Dedup/grouping overhead is ~0.4ms.
- Engine timings are collected in `engine_timings` JSON field.

## Custom Framework Extensions (B11 + B11.5)

Users can extend official framework packs with organization-specific sources, sinks, sanitizers, and safe patterns via `framework_extensions` in `.patchflow/rules.yaml`.

Key points:
- Extensions are merged into the same `PackOverride` pipeline as `framework_overrides`.
- Extensions add `safe_patterns` and CWE metadata on sinks (not available in overrides).
- Both sections are combined if they define entries for the same framework.
- Extensions only **add** — they never remove official sources/sinks/sanitizers.
- **B11.5.1**: Custom sinks are scoped by CWE/category — a sink with `cwe: "CWE-89"` only attaches to SQLi rules, not SSRF/redirect/deser. Unscoped sinks attach to all rules (backward compatible).
- **B11.5.2**: Custom sources can be scoped by `categories` — a source with `categories: [sql_injection]` only attaches to SQLi rules.
- **B11.5.3**: Safe patterns suppress taint-mode findings when the pattern matches in the same function (uses function boundary detection from B10.9).
- **B11.5.4**: `--config` flag is the unified config entry point; `--rules` and `--rules-config` are legacy aliases.
- **B11.5.5**: `rules validate` catches noisy extension mistakes (unscoped sinks, duplicates, unknown frameworks, bad regex).
- YAML accepts both `func` and `function` as field names for user-friendliness.
- `patchflow explain --rule <id>` shows project extensions.
- See `docs/CUSTOM_FRAMEWORK_EXTENSIONS.md` for the full schema reference.
