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
```

## Governance

Framework rules register under `EngineFrameworks` in the governance registry. Default maturity is `experimental` (audit profile only, non-blocking). Promote rules to `beta`/`stable` as they gain test fixtures and regression coverage, which activates them in PR/CI profiles and makes high/critical findings blocking-eligible.
