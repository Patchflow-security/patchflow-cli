# B1 Rules Baseline — Frozen Reference

**Date:** 2026-07-02  
**Phase:** Post-B2 (after Spring + ASP.NET + Rails batch)  
**Purpose:** Regression anchor for all future rule additions. Any change that
shifts these numbers must be documented and justified.

## How to Reproduce

```bash
go build -o /tmp/patchflow-baseline .
cd /Users/digitalcenter/patchflow-benchmarks/.bench-work/<repo>
/tmp/patchflow-baseline scan run --json --quiet --offline
```

## Clean Repos (FP Baseline)

These repos are NOT deliberately vulnerable. Findings here are noise/FPs.
The baseline tracks exact counts so any increase is caught.

### cobra (clean Go CLI library)

| Metric | Value |
|--------|-------|
| Total findings | 18 |
| Blocking findings | 0 |
| SAST findings (gosast-embedded) | 14 |
| SCA/license findings | 4 |
| Max SAST threshold | 30 (current: 14) |

Rule breakdown:
- G104 (unhandled errors): 7
- G201 (SQL format string): 5
- G302 (file permissions): 1
- G304 (file path taint): 1
- none (license/SCA): 4

### flask (clean Python web framework)

| Metric | Value |
|--------|-------|
| Total findings | 43 |
| Blocking findings | 0 |
| SAST findings (patterns + treesitter) | 6 |
| SCA/license/secrets findings | 37 |
| Max SAST threshold | 15 (current: 6) |

Rule breakdown:
- PY019: 2
- TS-PY019: 2
- TS-PY002: 1
- TS-PY001: 1
- generic-api-key (secrets): 5
- none (license/SCA/checkov): 30

### django (clean Python web framework, ~250k LOC)

| Metric | Value |
|--------|-------|
| Total findings | 143 |
| Blocking findings | 0 |
| SAST findings (patterns + treesitter + taint) | 132 |
| SCA/license/secrets findings | 11 |
| Max SAST threshold | 200 (current: 132) |

Top rules:
- PY050 (subprocess): 48
- TS-PY018: 12
- HTML002: 11
- TS-PY005: 7
- PY051: 6
- PY001: 6
- PY043: 4
- TS-PY008: 3
- TS-PY017: 3
- TS-PY002: 3
- TP-PY001-IP (taint): 2

## Vulnerable Benchmark Repos

These repos ARE deliberately vulnerable. Findings here are expected.
The baseline tracks which rule families fire so we can detect regressions
(rules that stop firing) and improvements (new rules that start firing).

### webgoat (Java, deliberately vulnerable)

| Metric | Value |
|--------|-------|
| Total findings | 635 |
| Blocking findings | 7 |
| High/Critical | 351 |

Analyzers: osv(107), registry-license(170), patterns-embedded(286), treesitter-ast(29), secrets-embedded(11), framework-spring-security(2), checkov(7), gitleaks(15), taint-patterns(8)

Key rule families:
- JAVA*: 20+ rules firing (JAVA005, JAVA006, JAVA008, JAVA012, etc.)
- TS-JAVA*: 4 rules (TS-JAVA001, TS-JAVA002, TS-JAVA004, TS-JAVA006)
- PF-SPRINGSEC-CSRF-001: 2 (new Spring Security rule)
- TP-JAVA*: 8 findings (TP-JAVA001: 4, TP-JAVA006: 1, TP-JAVA009: 3) — **B6.5: now firing via Spring annotation source model**
- SECRET*: 4 rules firing

**B6.5 update:** TP-JAVA* taint rules now fire on WebGoat. The taint engine
models Spring annotations (@RequestParam, @PathVariable, @RequestBody, etc.)
as taint sources via `seedAnnotatedParams()`. The strict test
`TestWebGoat_SpringAnnotationSources_TaintRulesFire` is now enabled.

### dvga (Python, Damn Vulnerable GraphQL App)

| Metric | Value |
|--------|-------|
| Total findings | 99 |
| Blocking findings | 0 |
| High/Critical | 36 |

Key rule families:
- PY*: 7 rules (PY011, PY031, PY042b, PY042c, PY044, PY046, PY047)
- TS-PY*: 1 rule (TS-PY013)
- TP-PY001: 1 (taint: resolver arg `filter` → SQLAlchemy `text()` SQLi)
- PF-GRAPHQL-AUTH-001: 6 (IDOR: filter_by(id=id) without ownership check)
- PF-GRAPHQL-SQLI-001: 1 (taint: resolver args → raw SQL)

**B7 update:** DVGA is now closed. The GraphQL framework pack (5 rules) fires
on resolver-based vulnerabilities. The taint engine detects resolver args
flowing to SQLAlchemy `text()` (TP-PY001) and the AUTH rule catches IDOR
patterns (filter_by(id=id) without ownership checks).

Test status:
- `TestDVGA_GraphQLSources_AreSeeded` — enabled
- `TestDVGA_GraphQLSources_TaintRulesFire` — enabled (B7.1: text() sink closes the gap)

### juice-shop (JS/TS, OWASP Juice Shop)

| Metric | Value |
|--------|-------|
| Total findings | 347 |
| Blocking findings | 0 |
| High/Critical | 183 |

Key rule families:
- JS*: 18 rules firing
- TS-JS*: 5 rules (TS-JS001, TS-JS006, TS-JS009, TS-JS018, TS-JS020)
- PF-EXPRESS-SQLI-001: firing (framework rule)
- TP-JS*: 66 findings (TP-JS001, TP-JS004, TP-JS005, TP-JS006, TP-JS008 + inter-procedural variants) — **B6.5: now firing via TS normalization + direct source-to-sink detection**

**B6.5 update:** TP-JS* taint rules now fire on Juice Shop. Two changes enabled
this:
1. TypeScript files are now normalized to "javascript" for taint rule matching
   (previously .ts files were skipped entirely).
2. Direct source-to-sink detection via `argContainsSource()` catches inline
   source usage in sink arguments (e.g., `query(`SELECT ... ${req.body.email}`)`).
The strict test `TestJuiceShop_ExpressSources_TaintRulesFire` is now enabled.

### nodegoat (JS, OWASP NodeGoat)

| Metric | Value |
|--------|-------|
| Total findings | 371 |
| Blocking findings | 2 |
| High/Critical | 252 |

Key rule families:
- TP-JS005: firing (taint rule — NodeGoat uses simple req.body patterns)
- TP-JS005-IP: firing (interprocedural variant)
- PF-EXPRESS-REDIRECT-001: firing
- TS-JS*: 2 rules

### dvna (JS, Damn Vulnerable Node App)

| Metric | Value |
|--------|-------|
| Total findings | 66 |
| Blocking findings | 0 |
| High/Critical | 40 |

Key rule families:
- TP-JS001: firing
- TP-JS001-IP: firing
- PF-EXPRESS-REDIRECT-001: firing

### laravel-v5.5.40 (PHP, historical vulnerable)

| Metric | Value |
|--------|-------|
| Total findings | 228 |
| Blocking findings | 0 |
| High/Critical | 215 |

Key rule families:
- PHP*: 11 rules (PHP001, PHP002, PHP004, PHP007, PHP011, PHP016, PHP019, PHP023, PHP027, PHP029, PHP033)
- TS-PHP*: 3 rules (TS-PHP002, TS-PHP004, TS-PHP006)
- PF-LARAVEL-*: 0 (no Laravel framework rules yet — Phase B3 target)

### railsgoat (Ruby, deliberately vulnerable Rails)

| Metric | Value |
|--------|-------|
| Total findings | 75 |
| Blocking findings | 0 |
| High/Critical | 44 |

Key rule families:
- TP-RB006, TP-RB006-IP: firing (taint)
- TP-RB008, TP-RB008-IP: firing (taint)
- PF-RAILS-REDIRECT-002-IP: firing (framework taint)
- RB*: 14 rules firing (pattern)
- TS-RB*: 2 rules

### dvwa (PHP, Damn Vulnerable Web Application)

| Metric | Value |
|--------|-------|
| Total findings | 128 |
| Blocking findings | 0 |
| High/Critical | 91 |

Key rule families:
- TP-PHP*: 5 rules firing (TP-PHP001, TP-PHP002, TP-PHP004, TP-PHP005, TP-PHP008)
- PHP*: 11 rules firing
- TS-PHP*: 3 rules firing

## SCA / CVE Baseline

| Repo | Expected CVEs | Status |
|------|--------------|--------|
| log4j 2.14.0 | CVE-2021-44228, CVE-2021-45046, CVE-2021-45105 | PASS |
| lodash 4.17.10 | CVE-2019-10744, CVE-2020-8203, CVE-2021-23337 | PASS |
| express 4.16.0 | CVE-2024-29041 | PASS |
| requests 2.19.0 | CVE-2023-32681 | PASS |
| urllib3 1.24.x | CVE-2019-11324 | PASS (relaxed) |
| golang-jwt old | CVE-2020-26160 | PASS (relaxed, offline DB gap) |

## Test Counts

| Suite | Count | Status |
|-------|-------|--------|
| rulesconfig unit tests | 28 | PASS |
| framework pack tests (all 19 packs) | 35+ new + existing | PASS |
| real-repo integration tests | 33 | PASS |
| go vet | clean | PASS |

## Known Gaps (Strict-Pending Tests)

These are tracked as explicit gaps, not silent relaxations:

1. **TP-JAVA* on WebGoat** — Spring annotation sources not modeled in taint engine
2. **TP-PY* on DVGA** — GraphQL resolver args not modeled as taint sources
3. **TP-JS* on Juice Shop** — Express req.* sources not modeled in taint engine
4. **PF-LARAVEL-* on Laravel** — No Laravel framework rules yet (B3 target)
5. **CWE extraction from OSV** — ExtractCWEID implemented but may not find CWEs
   for all advisories (depends on OSV database_specific field availability)
