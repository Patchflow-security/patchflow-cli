# PatchFlow CLI — Technical Assessment

**Date:** 2026-06-27
**Version:** Current main branch
**Assessor:** Automated audit + manual review

---

## 1. Executive Summary

PatchFlow CLI is a **production-grade security analysis tool** written in Go, providing local-first SCA, SAST, secret detection, reachability analysis, SBOM generation, and PR intelligence. The codebase is well-architected with clean package boundaries, consistent error handling, and zero external runtime dependencies (embedded scanners).

| Dimension | Grade | Score |
|-----------|-------|-------|
| Architecture | A- | 90/100 |
| Code Quality | B+ | 85/100 |
| Security | A | 95/100 |
| Feature Completeness | B | 75/100 |
| Test Coverage | B- | 70/100 |
| CLI UX | B+ | 85/100 |
| **Overall** | **B+** | **83/100** |

---

## 2. Code Metrics

| Metric | Value |
|--------|-------|
| Go files | 143 |
| Total lines | 44,707 |
| Test files | 48 |
| Test functions | 516 |
| Benchmark functions | 6 |
| Internal packages | 29 |
| Command files | 26 |
| Direct dependencies | 8 |
| Total dependencies | 25 |
| TODO/FIXME in production code | 1 (a SAST rule pattern, not actual TODO) |
| panic() calls | 0 |

---

## 3. Architecture Assessment

### Strengths

1. **Clean package structure** — 29 well-organized internal packages with clear separation of concerns
2. **Interface-based design** — `git.Executor` interface enables testability without shell access
3. **Embedded scanners** — Zero-dependency SAST approach (no external tools required for basic scanning)
4. **No circular imports** — Package dependencies are clean and acyclic
5. **Proper context propagation** — `context.Context` used throughout command chain
6. **Consistent error wrapping** — 205 instances of `fmt.Errorf` with `%w`, zero panics
7. **Excellent resource cleanup** — 47 defer statements, 29 `.Close()` calls with proper defer
8. **Well-controlled concurrency** — 9 goroutines, proper sync.WaitGroup/Mutex usage, no race conditions detected

### Areas for Improvement

1. **Duplicate YAML dependency** — Both `go.yaml.in/yaml/v3` and `gopkg.in/yaml.v3` are included; remove the latter
2. **Logging inconsistency** — Mixed use of `zap` (9), `log` (16), and `fmt.Print` (56); standardize on `zap` for structured logging
3. **Large files** — `internal/sast/runner.go` (1153 lines) should be split by concern
4. **Global state in git package** — `ignoredDirSet` and `binaryExts` maps could use dependency injection for testability

---

## 4. Command Coverage

**24 top-level commands, 56 total subcommands — 100% implemented, 0 stubs.**

```
patchflow
├── auth (status)
├── login
├── logout
├── config (show, set, profile: create/use/list/delete/show)
├── scan (local, changed, export, run, baseline)
├── baseline (create, list, diff, delete)
├── review (context, pr, diff, status)
├── pr-review
├── init (github-actions, gitlab-ci, pre-commit, jenkins, azure-devops)
├── deps (list, vulnerable, diff, tree, licenses)
├── benchmark (run, compare, report)
├── rules (list, maturity, docs, validate)
├── cache (status, clean)
├── doctor
├── explain
├── suppress
├── report
├── reachability
└── version
```

### Missing CLI Features
- **Shell completion** — No bash/zsh/fish/powershell completion support
- **`--quiet` global flag** — No way to suppress non-error output for CI scripting
- **`--staged` scan flag** — Only `--changed` is implemented
- **`--path` scan flag** — Can only scan current directory

---

## 5. Feature Completeness

### Fully Implemented (P1-P4)

| Feature | Status | Key Files |
|---------|--------|-----------|
| SCA (OSV.dev) — 7 ecosystems | ✅ | `internal/sca/`, `internal/osv/`, `internal/manifest/` |
| SAST — 6 embedded + 4 external | ✅ | `internal/sast/` (10 subpackages) |
| Secret detection — 35+ patterns | ✅ | `internal/sast/secrets/` |
| Reachability analysis | ✅ | `internal/reachability/` |
| Risk scoring (0-100) | ✅ | `internal/risk/` |
| Baseline/diff with semantic fingerprinting | ✅ | `internal/baseline/` |
| SBOM (CycloneDX + SPDX) | ✅ | `internal/sbom/` |
| VEX generation | ✅ | `internal/sbom/vex.go` |
| License scanning | ✅ | `internal/sbom/licenses.go` |
| Dependency graph (tree + DOT) | ✅ | `internal/sbom/depgraph.go` |
| PR summary generation | ✅ | `internal/pr/summary.go` |
| Inline annotations (GitHub + GitLab) | ✅ | `internal/pr/annotations.go` |
| Reviewer suggestions (CODEOWNERS + blame) | ✅ | `internal/reviewers/suggest.go` |
| Report generation (markdown, JSON, SARIF) | ✅ | `internal/report/` |
| Monorepo detection (9 build systems) | ✅ | `internal/monorepo/` |
| CI/CD templates (GitHub Actions, GitLab, pre-commit, Jenkins, Azure) | ✅ | `cmd/init_templates.go` |
| Custom rules YAML | ✅ | `internal/sast/customrules/` |
| Suppression directives | ✅ | `internal/sast/suppression/` |
| Incremental scanning | ✅ | `internal/sast/incremental/` |
| OSV response caching | ✅ | `internal/osv/cache.go` |
| Benchmark suite | ✅ | `internal/benchmark/` |

### Missing Features (P5+)

| Feature | Priority | Notes |
|---------|----------|-------|
| **Fix proposal system** | P5 (High) | Entire `patchflow fix` command not implemented |
| **AI summary/explanation** | P6 (High) | No AI-powered findings explanation or fix suggestions |
| **IaC scanning** | P7 (Medium) | Checkov/Terraform scanning not implemented |
| **GitLab Code Quality format** | P8 (Medium) | Only SARIF for GitHub is supported |
| **NVD enrichment** | P9 (Low) | OSV.dev is the only vulnerability source |
| **Java/C++ SAST** | P10 (Low) | Embedded scanners don't cover Java or C++ |
| **Backend API alignment** | P11 (Medium) | Implementation uses `/api/v1/cli/*` vs documented `/api/v1/analysis-runs/*` |

### SCA Ecosystem Coverage

| Ecosystem | Manifest Files | Status |
|-----------|----------------|--------|
| Go | go.mod, go.work | ✅ |
| npm | package.json, pnpm-workspace.yaml | ✅ |
| PyPI | requirements.txt, pyproject.toml, setup.py, Pipfile, poetry.lock, uv.lock | ✅ |
| Cargo | Cargo.toml | ✅ |
| RubyGems | Gemfile, Gemfile.lock | ✅ |
| Packagist | composer.json | ✅ |
| Maven | pom.xml, build.gradle, build.gradle.kts | ✅ |

### SAST Language Coverage

| Language | Embedded | External | Reachability |
|----------|----------|----------|-------------|
| Go | ✅ (gosast + taint + patterns) | gosec | ✅ |
| Python | ✅ (patterns) | bandit | ✅ |
| JavaScript/TS | ✅ (patterns + tree-sitter) | semgrep | ✅ |
| Ruby | ✅ (patterns) | — | ❌ |
| PHP | ✅ (patterns) | — | ❌ |
| Java | ❌ | semgrep | ❌ |
| C/C++ | ❌ | — | ❌ |

---

## 6. Test Coverage

### Coverage by Package (short mode)

| Package | Coverage | Assessment |
|---------|----------|------------|
| `internal/review` | 97.5% | Excellent |
| `internal/rules` | 90.8% | Excellent |
| `internal/analysis` | 89.1% | Excellent |
| `internal/baseline` | 88.7% | Excellent |
| `internal/git` | 87.8% | Excellent |
| `internal/ignore` | 87.6% | Excellent |
| `internal/monorepo` | 87.3% | Excellent |
| `internal/sast/customrules` | 89.3% | Excellent |
| `internal/sast/patterns` | 87.5% | Excellent |
| `internal/config` | 84.9% | Good |
| `internal/risk` | 84.9% | Good |
| `internal/output` | 85.7% | Good |
| `internal/sbom` | 81.6% | Good |
| `internal/pr` | 83.9% | Good |
| `internal/project` | 83.8% | Good |
| `internal/sast/treesitter` | 82.9% | Good |
| `internal/api` | 83.1% | Good |
| `internal/templates` | 80.6% | Good |
| `internal/report` | 73.9% | Fair |
| `internal/reviewers` | 72.3% | Fair |
| `internal/sast/suppression` | 71.9% | Fair |
| `internal/sast/taint` | 74.7% | Fair |
| `internal/sast/secrets` | 74.8% | Fair |
| `internal/sast/taintpatterns` | 76.7% | Fair |
| `internal/reachability` | 69.1% | Fair |
| `internal/sast/incremental` | 68.4% | Fair |
| `internal/manifest` | 65.6% | Fair |
| `internal/sast/gosast` | 53.0% | Poor |
| `internal/benchmark` | 40.5% | Poor |
| `internal/osv` | 31.2% | Poor |
| `internal/auth` | 35.7% | Poor |
| `internal/scan` | 22.7% | Poor |
| `internal/sast` (runner) | 12.7% | Poor |
| `cmd/` | 0.0% | Critical gap |
| `internal/doctor` | 0.0% | Critical gap |
| `internal/sca` | 0.0% | Critical gap |
| `internal/exitcode` | 0.0% | Critical gap |

### Test Infrastructure
- **516 test functions** across 48 test files
- **6 benchmark functions**
- **Real-repo integration tests** — Clone and test against NodeGoat, dvna, django-DefectDojo, WebGoat
- **Mock infrastructure** — `git.Executor` interface, mock HTTP servers
- **Test helpers** — `cloneRepo()`, `runPatchflowExport()`, `runPRReview()`

### Critical Test Gaps
1. **`cmd/` package — 0% coverage** — All 26 command handlers are untested
2. **`internal/sca/` — 0% coverage** — Core SCA analyzer untested
3. **`internal/doctor/` — 0% coverage** — Health check untested
4. **`internal/sast/` runner — 12.7%** — Main SAST orchestration poorly tested
5. **`internal/osv/` — 31.2%** — OSV API client poorly tested

---

## 7. Security Assessment

### Secure Practices ✅

| Practice | Status | Details |
|----------|--------|---------|
| No hardcoded secrets | ✅ | All test secrets are clearly fake |
| Token storage | ✅ | OS keyring with 0600 fallback |
| Token masking | ✅ | `****` + last 4 chars in output |
| No SQL injection | ✅ | No SQL database code |
| No InsecureSkipVerify | ✅ | All HTTP clients use proper TLS |
| HTTP timeouts | ✅ | 30s API, 60s GitHub upload |
| Typed JSON deserialization | ✅ | No `json.Unmarshal` into `interface{}` |
| Proper concurrency | ✅ | WaitGroups, Mutexes, no race conditions |

### Security Concerns ⚠️

| Issue | Severity | File | Recommendation |
|-------|----------|------|----------------|
| Path traversal in Maven parent POM | MEDIUM | `internal/manifest/parser.go:1868` | Validate resolved path stays within project root |
| 87× `os.WriteFile(..., 0644)` | MEDIUM | Multiple files | Use 0600 for sensitive files (baselines, scan state, SARIF) |
| No file size limits on manifests | LOW | `internal/manifest/parser.go` | Add max file size check to prevent DoS |
| No input validation on `--output` path | LOW | `cmd/scan_run.go` | Validate paths stay within expected bounds |
| No URL validation in benchmark config | LOW | `internal/benchmark/runner.go:299` | Validate git URLs to prevent SSRF |
| No schema validation for custom rules | LOW | `internal/sast/customrules/loader.go` | Validate rule structure before loading |
| No depth limit for recursive POM loading | LOW | `internal/manifest/parser.go` | Add max depth to prevent infinite recursion |

---

## 8. Dependency Assessment

### Direct Dependencies (8)

| Dependency | Version | Status | Notes |
|------------|---------|--------|-------|
| `spf13/cobra` | v1.10.2 | ✅ Current | CLI framework |
| `spf13/viper` | v1.21.0 | ✅ Current | Config management |
| `zalando/go-keyring` | v0.2.8 | ✅ Current | OS keyring access |
| `go.uber.org/zap` | v1.28.0 | ✅ Current | Structured logging |
| `go.yaml.in/yaml/v3` | v3.0.4 | ✅ Current | YAML parsing (maintained fork) |
| `golang.org/x/tools` | v0.35.0 | ✅ Current | Go AST analysis |
| `gopkg.in/yaml.v3` | v3.0.1 | ⚠️ Duplicate | Remove — replaced by `go.yaml.in/yaml/v3` |
| `odvcencio/gotreesitter` | v0.20.5 | ✅ Current | Tree-sitter bindings |

**No known vulnerabilities in any dependency.**

---

## 9. Build & Release

| Target | Status | Notes |
|--------|--------|-------|
| `make build` | ✅ | Version info embedded |
| `make test` | ✅ | All packages |
| `make vet` | ✅ | go vet |
| `make fmt` | ✅ | go fmt |
| `make lint` | ✅ | vet + test |
| `make release` | ✅ | goreleaser |
| `make release-snapshot` | ✅ | Snapshot build |
| `make docker-build` | ✅ | Docker image |
| `.goreleaser.yml` | ✅ | Cross-platform builds |
| `Dockerfile` | ✅ | Multi-stage build |
| GitHub Actions release | ✅ | Automated releases |

---

## 10. Recommended Next Steps

### Phase 5: Safe Fixes (P5) — High Priority

1. **Implement `patchflow fix` command**
   - `patchflow fix suggest --finding <id>` — Generate fix proposal
   - `patchflow fix apply --finding <id> --dry-run` — Preview patch
   - `patchflow fix apply --finding <id>` — Apply with confirmation
   - Patch generation, validation, test running before apply
   - Create `internal/fix/` package

### Phase 6: AI Integration (P6) — High Priority

2. **AI-powered findings explanation**
   - Integrate with LLM API for natural language explanations
   - Enhance `patchflow explain` with AI summaries
   - Add `--ai` flag to `scan run` for AI-powered triage

3. **AI fix suggestions**
   - LLM-powered code fixes for common vulnerability patterns
   - Integrate with fix proposal system (P5)

### Phase 7: Hardening (P7) — Medium Priority

4. **Security hardening**
   - Fix path traversal in Maven POM parser
   - Change file permissions from 0644 to 0600 for sensitive files
   - Add file size limits for manifest parsing
   - Add input validation for all user-provided paths
   - Add URL validation for benchmark configs

5. **Test coverage improvement**
   - Add tests for `cmd/` package (currently 0%)
   - Add tests for `internal/sca/` (currently 0%)
   - Add tests for `internal/doctor/` (currently 0%)
   - Improve `internal/sast/` runner coverage (currently 12.7%)
   - Improve `internal/osv/` coverage (currently 31.2%)

6. **Code quality**
   - Remove duplicate YAML dependency
   - Standardize logging on `zap`
   - Split `internal/sast/runner.go` (1153 lines)
   - Add `golangci-lint` to CI pipeline
   - Add race detector to CI (`go test -race`)

### Phase 8: Platform Expansion (P8) — Medium Priority

7. **IaC scanning**
   - Add Terraform/HCL scanning (Checkov integration or embedded rules)
   - Add CloudFormation scanning
   - Add Kubernetes manifest scanning

8. **GitLab integration**
   - Add GitLab Code Quality report format
   - Add GitLab MR annotation support
   - Add GitLab CI template to `init`

9. **Additional language support**
   - Java SAST (embedded patterns)
   - C/C++ SAST (embedded patterns)
   - Java reachability analysis

### Phase 9: Polish (P9) — Low Priority

10. **CLI UX improvements**
    - Add shell completion (bash/zsh/fish/powershell)
    - Add `--quiet` global flag
    - Add `--staged` scan flag
    - Add `--path` scan flag
    - Add global `--format` flag

11. **Backend alignment**
    - Align API endpoints with documented structure
    - Add NVD enrichment for vulnerability data
    - Add dependency owner/maintainer metadata

12. **Documentation**
    - Add architecture decision records (ADRs)
    - Add code coverage reporting to CI
    - Add CONTRIBUTING.md
    - Add CHANGELOG.md

---

## 11. Priority Matrix

| Priority | Phase | Effort | Impact |
|----------|-------|--------|--------|
| 🔴 Critical | P5: Fix proposal system | Large | High — Core product gap |
| 🔴 Critical | P7: Security hardening | Medium | High — Security debt |
| 🔴 Critical | P7: Test coverage (cmd, sca, doctor) | Medium | High — Quality risk |
| 🟡 High | P6: AI integration | Large | High — Product differentiation |
| 🟡 High | P8: IaC scanning | Medium | Medium — Market expansion |
| 🟡 High | P8: GitLab integration | Small | Medium — Platform coverage |
| 🟢 Medium | P7: Code quality cleanup | Small | Low — Technical debt |
| 🟢 Medium | P8: Java/C++ SAST | Medium | Medium — Language coverage |
| 🟢 Medium | P9: CLI UX (completion, quiet) | Small | Low — Developer experience |
| ⚪ Low | P9: Backend alignment | Medium | Low — Documentation sync |
| ⚪ Low | P9: NVD enrichment | Small | Low — Data completeness |

---

## 12. Conclusion

PatchFlow CLI is a **well-engineered, production-ready security tool** with strong architecture, excellent error handling, and comprehensive feature coverage for SCA, SAST, secrets, reachability, SBOM, and PR intelligence. The codebase demonstrates mature Go practices with zero panics, proper resource cleanup, and clean package boundaries.

The **three most impactful next steps** are:

1. **Implement the fix proposal system (P5)** — This is the largest feature gap and directly addresses the "safe fix flow" philosophy from the product vision
2. **Security hardening (P7)** — Fix path traversal, file permissions, and input validation issues
3. **Test coverage for cmd/ and sca/ packages (P7)** — These are critical paths with 0% coverage

The CLI is ready for production use today, with the understanding that the fix proposal system and AI features will be added in subsequent phases.
