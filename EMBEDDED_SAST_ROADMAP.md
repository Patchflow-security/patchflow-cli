# Embedded SAST Roadmap

Track progress of the embedded SAST scanner development for `patchflow-cli`.

**Last updated**: 2026-06-25

---

## Completed Work

### Tier 1: Embedded Go SAST Scanner (`internal/sast/gosast/`)
- [x] `analyzer.go` — Analyzer struct, package loading via `golang.org/x/tools/go/packages`
- [x] `helpers.go` — CallList, GetCallInfo, TryResolve, GetString, MatchCallByPackage (ported from gosec v2.27.1)
- [x] `rules.go` — 22 AST-based rules ported from gosec:
  - G101: Hardcoded credentials
  - G102: Bind to all network interfaces
  - G103: Use of unsafe block
  - G106: SSH InsecureIgnoreHostKey
  - G107: SSRF (URL as taint input)
  - G108: Profiling endpoint exposed (pprof)
  - G114: HTTP serve without timeouts
  - G116: Trojan Source (bidirectional Unicode)
  - G201: SQL query via format string
  - G202: SQL query via string concatenation
  - G203: Unescaped data in HTML templates
  - G204: Subprocess launched with variable
  - G301: Poor directory permissions (Mkdir)
  - G302: Poor file permissions (OpenFile/Chmod)
  - G303: Predictable tempfile path
  - G304: File path as taint input
  - G305: Path traversal in zip/tar extraction
  - G306: Poor WriteFile permissions
  - G401: Weak crypto hash (MD5/SHA1)
  - G404: Weak random number generator (math/rand)
  - G405: Weak crypto encryption (DES/RC4)
  - G501: Blocklisted imports (crypto/md5, crypto/des, etc.)
- [x] `analyzer_test.go` — 8 tests, all passing

### Tier 1: Embedded Secret Scanner (`internal/sast/secrets/`)
- [x] `scanner.go` — 35 curated regex patterns:
  - Cloud: AWS Access Key, AWS Secret, Google API Key, Google OAuth, Google Cloud SA, Azure Storage
  - VCS: GitHub PAT/Fine-grained/Action/OAuth/Refresh, GitLab PAT
  - SaaS: Slack Token/Webhook, Stripe Live/Restricted, Twilio, Square, Heroku, Mailgun, MailChimp, Telegram
  - Private keys: RSA, EC, DSA, OpenSSH, PGP
  - Database URLs: postgres, mysql, mongodb, redis, amqp
  - JWT tokens
  - Generic: API key, secret, password, token assignments
  - Shannon entropy detection for high-entropy strings
  - Evidence redaction in output
  - False positive filtering (example/placeholder values)
- [x] `scanner_test.go` — 9 tests, all passing

### Tier 1: Multi-Language Pattern Scanner (`internal/sast/patterns/`)
- [x] `scanner.go` — 40 regex rules across 5 languages:
  - Python (17 rules): eval, exec, os.system, shell=True, pickle, yaml.load, SQL injection, MD5, SHA1, random, hardcoded password, verify=False, debug=True, Flask debug, Django ALLOWED_HOSTS, hardcoded IP, TODO security
  - JavaScript/TypeScript (12 rules): eval, Function constructor, child_process.exec/execSync, SQL interpolation, MD5, SHA1, Math.random, CORS wildcard, Helmet disabled, Node debug, dangerouslySetInnerHTML
  - Ruby (5 rules): eval, system, backtick execution, SQL injection, OpenSSL weak cipher
  - PHP (5 rules): eval, exec/system, SQL injection, md5/sha1, file inclusion
  - Cross-language (2 rules): hardcoded IP, TODO/FIXME security comments
- [x] Language detection by file extension
- [x] Comment skipping per language
- [x] `scanner_test.go` — 14 tests, all passing

### Integration
- [x] `runner.go` — Embedded scanners run first (always available), external tools supplement
- [x] New flags: `NoEmbeddedGo`, `NoEmbeddedSecrets`, `NoEmbeddedPatterns`
- [x] `EmbeddedTools()` method on Runner
- [x] All 22 test packages pass
- [x] Verified on patchflow-cli (35 Go findings) and Vexy (TypeScript, tuned false positives)

---

## P0: Immediate (Correctness + Validation)

### P0.1: Fix `--no-sast` / `--no-secrets` flag wiring
- **Status**: DONE
- **Problem**: `cmd/scan_run.go` filtered external tools but did NOT set `NoEmbeddedGo`, `NoEmbeddedSecrets`, `NoEmbeddedPatterns` on the runner. So `--no-sast` didn't skip the embedded Go SAST scanner.
- **Fix**: Set the embedded scanner flags based on `scanNoSAST` and `scanNoSecrets`:
  ```go
  if scanNoSAST {
      sastRunner.NoEmbeddedGo = true
      sastRunner.NoEmbeddedPatterns = true
  }
  if scanNoSecrets {
      sastRunner.NoEmbeddedSecrets = true
  }
  ```
- **Verified**:
  - `--no-sast` → `Analyzers: osv, secrets-embedded` (gosast + patterns skipped)
  - `--no-secrets` → `Analyzers: osv, gosast-embedded, patterns-embedded, gosec` (secrets skipped)
  - `--no-sast --no-secrets` → `Analyzers: osv` (all SAST skipped)

### P0.2: Test on Safe-pip-backend (Python/FastAPI)
- **Status**: DONE
- **Repo**: `/Users/digitalcenter/Safe-pip-backend`
- **Results**:
  - Total findings: 155 (67 high, 74 medium, 16 low)
  - SAST findings in app code: 36 (real security issues)
  - Key real findings:
    - `app/services/adapter_argocd_service.py:252` — SSL verify=False (HIGH, real)
    - `app/services/cloud/policy_engine_service.py` — 5x SSL verify=False (HIGH, default insecure)
    - `app/services/fix_proposal_generator.py:350` — subprocess shell=True (HIGH, real)
    - `app/services/vulnerability_detector.py:665` — MD5 + SHA1 usage (MEDIUM, real)
    - `app/services/auth_service.py:262` — random module for security (MEDIUM, real)
    - `app/core/config.py:80` — Database connection URL in config (HIGH, real)
  - Known false positives (regex limitation):
    - eval/exec/os.system in string literals (e.g. `pr_review_evidence_aggregator.py` checks for these in strings)
    - eval() mentioned in LLM prompt text (`pr_review_llm_enricher.py:371`)
  - Fixed: `.venv/` directory was being scanned (added to ignored dirs)
  - Fixed: `.env.example` files were flagged (added isExampleFile check)

### P0.3: Test on Sandbox-Orch (Go microservice)
- **Status**: DONE
- **Repo**: `/Users/digitalcenter/Sandbox-Orch`
- **Results**:
  - Total findings: 25 (1 high, 22 medium, 2 low)
  - gosast-embedded found 1 finding:
    - `internal/app/app.go:342` — G304: File path provided as taint input (os.ReadFile with config value) — REAL
  - External gosec found 1 finding:
    - `internal/orchestrator/runner.go:264` — G118: Goroutine uses context.Background/TODO — REAL
  - SCA found golang.org/x/crypto and golang.org/x/net advisories
  - No false positives — clean results on Go codebase

### P0.4: Tune false positives from real-world testing
- **Status**: DONE
- **Changes made**:
  - Added `.venv`, `venv`, `env`, `.env`, `.tox`, `.pytest_cache`, `.mypy_cache`, `site-packages`, `__pycache__`, `.eggs`, `.ruff_cache` to ignored dirs (both scanners)
  - Added `.pyc`, `.pyo`, `.so`, `.dll`, `.dylib`, `.wasm`, `.o`, `.a`, `.class`, `.jar` to ignored extensions (secret scanner)
  - Added `isExampleFile()` function to skip `.env.example`, `*.example`, `*.sample`, `*.template`, `*.dist` files (secret scanner)
  - Tuned PY013 (SSL verify=False) regex to use word boundary: `verify\s*=\s*False\b`
  - Result: Safe-pip-backend went from 389 findings → 155 findings (60% reduction in false positives)
- **Remaining known false positives** (require tree-sitter / AST analysis to fix):
  - eval/exec/os.system mentioned in string literals (not actual calls)
  - Security-related keywords in LLM prompt text
  - These are documented limitations of regex-based scanning (Phase 2: tree-sitter will address)

---

## P1: High Priority (Coverage + Usability)

### P1.1: Port remaining gosec AST rules
- **Status**: TODO
- **Rules to port** (17 remaining):
  - [ ] G104: Audit errors not checked (medium — needs type info)
  - [ ] G109: strconv.Atoi → int32/int16 overflow (low)
  - [ ] G110: io.Copy instead of io.CopyN during decompression (low)
  - [ ] G111: http.Dir("/") directory traversal (low)
  - [ ] G112: ReadHeaderTimeout not configured / slowloris (medium — high priority)
  - [ ] G117: Secrets exposed via JSON/YAML marshaling (medium)
  - [ ] G307: os.Create file permissions (low — pattern already exists)
  - [ ] G402: Bad TLS connection settings (high complexity — high priority)
  - [ ] G403: Minimum RSA key length 2048 (low)
  - [ ] G406: Deprecated MD4/RIPEMD160 (low)
  - [ ] G601: Implicit memory aliasing in rangeStmt (medium)
- **Skip for now**: G602 (slice bounds — SSA-based), G115 (type conversion overflow — SSA-based)
- **Effort**: ~2-3 hours

### P1.2: Suppression directives (`//patchflow:ignore`)
- **Status**: TODO
- **Syntax**:
  ```go
  //patchflow:ignore G404 -- using math/rand for non-security purpose
  n := rand.Intn(100)
  ```
  ```python
  # patchflow:ignore PY001 -- eval is safe here, input is sanitized
  result = eval(user_input)
  ```
- **Implementation**:
  - [ ] Parse `//patchflow:ignore` / `# patchflow:ignore` comments during scanning
  - [ ] Support rule-specific suppression (`//patchflow:ignore G404`)
  - [ ] Support blanket suppression (`//patchflow:ignore`)
  - [ ] Support inline (same line) and above-line comment styles
  - [ ] Add `--show-suppressed` flag to display suppressed findings
  - [ ] Track suppressions in report output
- **Effort**: ~3-4 hours

### P1.3: Update documentation
- **Status**: TODO
- [ ] README.md: Add embedded scanners to feature list, note zero-install requirement
- [ ] docs/USER_GUIDE.md: Document `--no-sast` / `--no-secrets` with embedded scanners, suppression directives
- [ ] docs/DEVELOPER_GUIDE.md: Document the three embedded scanner packages, how to add new rules, rule ID conventions
- **Effort**: ~2-3 hours

---

## P2: Medium Priority (Extensibility + UX)

### P2.1: Custom YAML rules (`.patchflow/rules.yaml`)
- **Status**: TODO
- **Syntax**:
  ```yaml
  rules:
    - id: CUSTOM-001
      title: No console.log in production
      languages: [javascript, typescript]
      pattern: "console\\.log\\("
      severity: low
      confidence: high
  ```
- **Implementation**:
  - [ ] Load `.patchflow/rules.yaml` during scan initialization
  - [ ] Parse rules into `PatternRule` structs
  - [ ] Merge with built-in rules
  - [ ] Support `--rules <path>` flag
  - [ ] Validate rule syntax on load
- **Effort**: ~4-5 hours

### P2.2: `patchflow rules list` command
- **Status**: TODO
- **Output**:
  ```
  Go SAST Rules (gosast-embedded):
    G101  HIGH  Hardcoded credentials
    G102  MED   Binds to all network interfaces
    ...

  Secret Patterns (secrets-embedded):
    AWS Access Key ID          HIGH   AKIA[0-9A-Z]{16}
    ...

  Pattern Rules (patterns-embedded):
    PY001  HIGH  Python: Use of eval()
    ...
  ```
- **Effort**: ~2-3 hours

### P2.3: `patchflow doctor` enhancement
- **Status**: TODO
- **Output**:
  ```
  Embedded Scanners:
    gosast-embedded:     ✓ (22 rules)
    secrets-embedded:    ✓ (35 patterns)
    patterns-embedded:   ✓ (40 rules, 5 languages)

  External Tools:
    gosec:               ✓ installed
    bandit:              ✗ not installed
    ...
  ```
- **Effort**: ~1-2 hours

### P2.4: Performance optimization
- **Status**: TODO
- [ ] Go SAST: Cache package loading (file hash-based)
- [ ] Go SAST: Skip vendor/ and test files by default
- [ ] Go SAST: Support `--changed-only` properly (only analyze packages with changed files)
- [ ] Secret scanner: Parallelize file walking with worker pool
- [ ] Pattern scanner: Use `.gitignore` patterns to skip irrelevant files
- **Effort**: ~1 day

---

## P3: Long-term (Deep Analysis + Adoption)

### P3.1: SSA-based taint analysis (G701-G710)
- **Status**: TODO
- **Rules**: SQL injection, command injection, path traversal, SSRF, XSS, log injection, SMTP injection, SSTI, unsafe deserialization, open redirect
- **Approach**: Port gosec's taint engine using `golang.org/x/tools/go/analysis/passes/buildssa`
- **Effort**: ~2-3 days
- **Note**: External gosec already provides these when installed; this is for zero-install taint analysis

### P3.2: Tree-sitter integration
- **Status**: TODO
- **Goal**: Replace regex-based pattern matching with AST analysis for Python, JS/TS, Ruby, PHP
- **Library**: `github.com/tree-sitter/go-tree-sitter` (requires cgo)
- **Benefits**: 80%+ false positive reduction, metavariable support, scope-aware analysis
- **Trade-off**: cgo complicates cross-compilation
- **Effort**: ~1-2 weeks
- **Recommendation**: Defer until regex scanner validated on real projects

### P3.3: CI/CD integrations
- **Status**: TODO
- [ ] GitHub Action: `uses: patchflow/patchflow-cli@v1`
- [ ] SARIF upload to GitHub Code Scanning (`scan export --upload-github`)
- [ ] Pre-commit hook (`.pre-commit-hooks.yaml`)
- **Effort**: ~1 day

---

## Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-06-25 | Embed gosec rules as Go library instead of requiring gosec install | Zero user installation, avoids 40+ transitive deps (AI SDKs, gRPC, OTel) |
| 2026-06-25 | Use regex for multi-language patterns (Phase 1) | Fast to implement, covers OWASP Top 10, no cgo requirement |
| 2026-06-25 | Keep external tools as supplements (Tier 3) | Power users get deeper analysis; embedded scanners provide baseline |
| 2026-06-25 | Defer tree-sitter to P3 | cgo complicates builds; validate regex approach first |
