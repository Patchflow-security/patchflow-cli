# Framework Pack Progress

## Goal

Close the remaining gaps in PatchFlow's framework-pack system so official packs,
user YAML extensions, template-aware detection, CLI commands, and regression
tests work as one coherent feature set.

## Current Snapshot

- Detection exists in `internal/frameworks/` for many frameworks, but only
  `rails` and `spring` have official embedded packs wired into
  `internal/sast/frameworks/packs/default_registry.go`.
- Framework enable/disable is exposed only through CLI flags:
  `patchflow scan run --framework ...` and `--disable-framework ...`.
- User YAML currently supports only generic regex rules via
  `.patchflow/rules.yaml`; it does not extend official framework packs.
- Template files are mostly handled by extension fallback in the collector and
  matcher; there is no explicit template-language classification layer for
  `.haml`, `.slim`, `.blade.php`, `.razor`, `.jinja2`.
- Framework-pack governance maturity exists, but promotions still depend on
  larger fixture/regression corpora landing per pack.

## Requested Scope

### P0 packs

- Express
- Next.js
- React
- Spring Boot
- Spring Security
- ASP.NET Core
- Razor
- Django
- Laravel
- FastAPI
- Gin
- Rails as reference baseline

### P1/P2 work

- Additional packs from the priority table after P0 lands
- Rule maturity promotions from `experimental` to `beta` and `stable`
- Regression corpus growth and fixture-based validation

### Product requirements

- User YAML extension layer for official packs:
  - custom sources
  - custom sinks
  - custom sanitizers
  - severity overrides
- Easier commands for framework packs and rule inspection
- Multi-pack selection similar to ESLint-style rule configuration
- Explicit template-engine coverage in collector classification
- Full testing for the pack contract, matcher behavior, config loading, CLI
  behavior, and regression paths

## Gaps To Close

### 1. Config and YAML model

- Add persisted `frameworks:` config support, not only ad hoc CLI flags.
- Extend `.patchflow/rules.yaml` into a broader policy file or companion YAML
  model that can describe:
  - enabled packs
  - disabled packs
  - per-pack severity overrides
  - custom framework sources/sinks/sanitizers
  - optional custom framework rules
- Validate unknown pack names and malformed override definitions clearly.

### 2. Pack registration and rule surfaces

- Add official pack directories following the standard structure:
  `pack.go`, `sources.go`, `sinks.go`, `sanitizers.go`, `rules.go`, `tests`.
- Register all shipped packs in the default registry.
- Ensure `patchflow rules list`, `rules list-frameworks`, and `explain --rule`
  expose framework-pack metadata consistently.

### 3. Template-aware classification

- Add explicit template-engine detection to the collector instead of relying on
  plain text fallback.
- Preserve compound extensions such as `.blade.php`.
- Allow rules to target template families precisely:
  - Haml
  - Slim
  - Blade
  - Razor
  - Jinja2

### 4. Governance and maturity

- Stop assigning framework packs a flat audit-only shape once tests exist.
- Register pack-rule profiles from actual maturity instead of always using the
  framework engine defaults.
- Add a promotion checklist tied to fixtures and regression corpus coverage.

### 5. Testing and regression safety

- Add pack contract tests for every official pack.
- Add vulnerable/safe/normal fixture tests for every rule family.
- Add CLI/config tests for:
  - auto-detect
  - explicit pack enablement
  - explicit pack disablement
  - YAML extension merge behavior
  - rule explanation output
  - list-frameworks output
- Add collector tests for explicit template-engine classification.

## Delivery Phases

### Phase 1: Framework policy and YAML extension plumbing

Deliverables:

- Config model for persisted framework selection
- YAML extension schema for official pack customization
- Merge layer that overlays user-defined sources/sinks/sanitizers/severity on
  top of embedded packs
- Validation and tests for the new YAML model

Acceptance:

- A user can enable multiple packs from YAML without CLI flags
- A user can override severity for an official framework rule
- A user can add custom framework source/sink/sanitizer semantics
- Invalid YAML reports actionable errors

### Phase 2: Template-engine classification

Deliverables:

- Collector support for explicit template-language detection
- Matcher support for compound template extensions without ambiguity
- Tests covering `.haml`, `.slim`, `.blade.php`, `.razor`, `.jinja2`

Acceptance:

- Template rules can target only the intended template family
- Blade and Razor files no longer depend on text-file fallback behavior

### Phase 3: P0 official pack completion

Deliverables:

- Implement and register packs for:
  - express
  - nextjs
  - react
  - spring-security
  - aspnet
  - razor
  - django
  - laravel
  - fastapi
  - gin
- Keep `rails` and `spring` as reference implementations and harden their test
  corpus as needed

Acceptance:

- `patchflow rules list-frameworks` shows every shipped P0 pack
- `patchflow scan run --framework <name>` activates each pack deterministically
- Each P0 pack has contract tests plus vulnerable/safe fixtures

### Phase 4: Governance, commands, and docs

Deliverables:

- Maturity-aware registration using per-rule maturity for profiles
- Cleaner CLI commands for pack discovery and rule inspection
- User docs for framework configuration and YAML extensions

Acceptance:

- Users can inspect framework packs and explain their rules easily
- Governance output reflects real maturity rather than a flat framework default

### Phase 5: P1/P2 rollout

Deliverables:

- Implement next-priority packs from the framework priority table
- Promote mature rules to `beta` and `stable`
- Expand regression corpora

Acceptance:

- P1/P2 packs follow the same structure and test bar as P0
- Rule promotions are backed by fixtures and regression data

## CLI Shape To Support

### Existing commands to preserve

```bash
patchflow scan run --framework rails
patchflow scan run --framework express --framework react
patchflow scan run --disable-framework spring
patchflow rules list-frameworks
patchflow rules list --framework rails
patchflow explain --rule PF-RAILS-XSS-003
```

### Target easy-to-use commands

```bash
patchflow scan run --framework auto
patchflow scan run --framework express,nextjs,react
patchflow rules list --framework express
patchflow rules list --framework express --framework react
patchflow rules pack show express
patchflow rules pack test express
patchflow rules pack scaffold django
```

Note:

- The first pass should prioritize robust selection and inspection.
- `rules pack test` and `rules pack scaffold` are optional follow-ons after the
  core pack/runtime plumbing is stable.

## YAML Shape To Support

Proposed direction:

```yaml
frameworks:
  auto_detect: true
  enabled:
    - express
    - nextjs
    - react
  disabled:
    - spring-security

framework_overrides:
  express:
    custom_sources:
      - func: req.headers["x-forwarded-host"]
    custom_sinks:
      - func: res.redirect
        arg_index: 0
    custom_sanitizers:
      - func: isSafeRedirect
    severity_overrides:
      PF-EXPRESS-REDIRECT-001: high
```

Requirements:

- Official packs remain the source of truth.
- User YAML extends official packs; it does not replace them.
- Multiple packs can be configured at once, ESLint-style.

## Testing Matrix

### Unit

- `internal/frameworks`
- `internal/sast/frameworks`
- `internal/sast/customrules` or replacement extension loader
- `internal/config`
- CLI command handlers where practical

### Pack tests

- One contract test per pack
- Vulnerable fixture tests
- Safe fixture tests
- Normal/no-noise fixture tests

### Integration

- Scan runs with detected packs
- Scan runs with explicit pack enable/disable
- YAML extension merges applied to findings
- Governance profile filtering with pack rules

### Baseline commands

```bash
go build ./...
go test ./internal/frameworks/... ./internal/sast/frameworks/... ./internal/rules/... -count=1
go test ./internal/sast/... ./internal/config/... ./cmd/... -count=1
```

## Execution Order

1. Land framework YAML/config plumbing.
2. Land explicit template-engine classification.
3. Add and register the remaining P0 packs.
4. Fix governance profile registration for framework-rule maturity.
5. Expand tests and promote mature packs/rules.
6. Continue with P1/P2 packs.

## Progress Log

- [x] Baseline repo inspection completed
- [x] Current pack architecture reviewed
- [x] Current framework CLI wiring reviewed
- [x] Current test baseline verified
- [x] Framework YAML/config extension layer implemented
- [x] Explicit template-engine classification implemented
- [x] P0 pack registry completed
- [x] Governance maturity registration corrected
- [x] P0 pack tests and regressions completed
- [x] P1/P2 rollout started

## Latest Implementation Pass

- Added a tracked project roadmap in this file
- Added project-level framework selection in `.patchflow/config.yml`
- Extended `.patchflow/rules.yaml` to support:
  - `frameworks.auto_detect`
  - `frameworks.enabled`
  - `frameworks.disabled`
  - `framework_overrides.<pack>.custom_sources`
  - `framework_overrides.<pack>.custom_sinks`
  - `framework_overrides.<pack>.custom_sanitizers`
  - `framework_overrides.<pack>.severity_overrides`
- Merged YAML framework overrides onto official packs at scan time
- Added explicit template extension detection for `.blade.php` and
  `.thymeleaf.html`, while preserving precise matching for `.haml`, `.slim`,
  `.razor`, and `.jinja2`
- Extended `patchflow rules list --framework` to accept multiple packs
- Added `patchflow rules list-frameworks --json`
- Added and registered the first new P0 official pack: `fastapi`
- Added and registered the remaining P0 starter packs:
  - `express`
  - `nextjs`
  - `react`
  - `spring-security`
  - `aspnet`
  - `razor`
  - `django`
  - `laravel`
  - `gin`
- Updated framework governance registration so rule profiles are derived from
  per-rule maturity instead of the framework engine default:
  - experimental: audit
  - beta: ci, audit
  - stable/enterprise: dev, pr, ci, audit
- Added focused tests for:
  - framework policy parsing
  - framework override severity validation
  - framework-policy-driven scan behavior
  - template extension detection
  - compound template matching
  - FastAPI pack contract and vulnerable/safe fixtures
  - P0 pack contracts and representative vulnerable/safe fixtures

## P1/P2 Rollout Pass

- Started P1/P2 rollout with detected framework packs not included in P0:
  - `flask`
  - `symfony`
  - `angular`
  - `nestjs`
  - `echo`
- Registered these packs in the default framework registry
- Added pack contract tests plus representative vulnerable/safe fixtures for
  the first P1 batch

## Real Benchmark Validation

- Added a dedicated suite at `benchmarks/framework-pack-validation.yaml`.
- The suite runs against local benchmark repos under
  `/Users/digitalcenter/patchflow-benchmarks/.bench-work`.
- Added framework-specific recall/accounting:
  - per-repo `framework_findings`
  - per-repo `expected_framework_detected`
  - per-repo `expected_framework_missed`
  - per-repo `framework_recall`
  - summary `total_framework_findings`
  - summary `avg_framework_recall`
- Fixed benchmark artifact handling so missing `.patchflow/reports/` no longer
  turns a successful JSON/SARIF scan into a failed repo result.

### 2026-07-01 Run

Command:

```bash
./patchflow benchmark run benchmarks/framework-pack-validation.yaml --no-tools
```

Results:

- Results directory:
  `/Users/digitalcenter/patchflow-benchmarks/results/2026-07-framework-pack-validation`
- 7 repos scanned
- 657,286 LOC
- 1,473 total findings
- 7 framework findings
- 100% average framework recall across repos with
  `expected_framework_findings`
- 7/7 SARIF artifacts valid

Framework-pack signal:

- `nodegoat`: 1 framework finding, `PF-EXPRESS-REDIRECT-001`
- `aspgoat`: 3 framework findings, `PF-RAZOR-XSS-001`
- `vuln-springboot-app`: 1 framework finding, `PF-SPRINGSEC-CSRF-001`
- `vulnerable-flask-app`: 2 framework findings, `PF-FLASK-SSTI-001`
- `gin`: 0 framework findings on clean repo
- `laravel-v5.5.40`: 0 framework findings on clean repo
- `django`: 0 framework findings on clean repo

Noise/overlap fixes validated:

- Django clean-repo framework findings reduced from 44 to 0 by excluding
  framework source/docs/tests paths for Django and Flask pack rules.
- Express/Next.js overlap fixed: `res.redirect(req.query.url)` no longer
  triggers `PF-NEXTJS-REDIRECT-001`.
- Flask benchmark coverage fixed with `PF-FLASK-SSTI-001` for dynamic
  `render_template_string(...)`.
