# PatchFlow framework-rules-v1 Benchmark Report

**Date:** 2026-07-03  
**Version:** framework-rules-v1  
**Commit:** `e3716fc`

## Executive Summary

PatchFlow framework-rules-v1 adds policy-aware, framework-aware scanning:
source-to-sink taint modeling for Spring, Express, GraphQL, Angular, Flask,
FastAPI and more, with block/inform/off governance and clean-repo regression
gates.

This release combines:
- **777 rules** across 7 scanner engines
- **18 framework packs** with 132 framework-specific rules
- **47 taint rules** with source-to-sink tracking
- **6 configuration profiles** (starter, strict, audit, framework-heavy, ci-blocking, enterprise)
- **SARIF/JSON output** with mode metadata for CI auditability
- **Clean-repo regression baselines** to prevent false-positive creep

## What Changed Since v7.1

### Taint Engine Improvements

| Improvement | Impact |
|-------------|--------|
| Spring annotation source model | `@RequestParam`, `@PathVariable`, `@RequestBody` → pre-tainted |
| GraphQL resolver source model | `resolve_*` and `mutate` args → pre-tainted |
| Angular route/form source model | 25 source patterns for route, form, @Input, ElementRef |
| SQLAlchemy `text()` sink | Closes DVGA SQLi detection gap |
| TypeScript normalization | TS files treated as JS for taint matching |
| Direct source-to-sink | `argContainsSource()` for Express/JS |
| Conservative resolver detection | `info` parameter required — avoids Django ORM FPs |

### Framework Pack Expansion

| Pack | Rules | Key Addition |
|------|-------|--------------|
| GraphQL (new) | 5 | SQLI, SSRF, PATH, AUTH, DOS |
| Flask (enhanced) | 9 | +2 MatchTaint, +PATH, +CONFIG |
| FastAPI (enhanced) | 9 | +AUTH, +text() sink |
| Angular (enhanced) | 5 | +2 MatchTaint, 25 source patterns |

### Governance and Explainability

| Feature | Description |
|---------|-------------|
| Rule modes | block / inform / off with maturity-based defaults |
| Configuration profiles | 6 presets for different team needs |
| `patchflow explain --rule` | OWASP category, default mode, safe patterns, override hint |
| JSON/SARIF metadata | `mode`, `blocking`, `mode_source`, `maturity` fields |
| Framework pack docs | 7 per-pack docs with sources/sinks/sanitizers/examples |

## Methodology

### Tools

- **PatchFlow:** `patchflow scan run --json --quiet --offline` (commit `e3716fc`)
- **Semgrep:** `semgrep scan --config auto --json --quiet` (v1.168.0)
- **Trivy:** `trivy fs --format json --quiet .` (v0.71.2)

### Benchmark Repos

| Category | Repos |
|----------|-------|
| Vulnerable (Spring) | WebGoat |
| Vulnerable (Express) | Juice Shop, NodeGoat, DVNA |
| Vulnerable (GraphQL) | DVGA |
| Vulnerable (Rails) | RailsGoat |
| Vulnerable (Flask) | DVFA |
| Clean (Go CLI) | cobra |
| Clean (Flask framework) | flask |
| Clean (Django framework) | django |

### Environment

- Go 1.26.4, Darwin 25.4.0, arm64
- Offline mode (local OSV DB)
- Semgrep online (Registry auto ruleset)

## Rule Governance and Modes

Every finding includes policy metadata:

```json
{
  "mode": "inform",
  "blocking": false,
  "mode_source": "default",
  "maturity": "beta"
}
```

| Mode | Behavior | CI Impact |
|------|----------|-----------|
| block | Reported + fails CI | Non-zero exit |
| inform | Reported only | Zero exit |
| off | Suppressed | N/A |

Maturity-based defaults ensure experimental rules never block without
explicit user opt-in.

## Framework Pack Coverage

18 framework packs covering 132 rules across 8 languages:

| Language | Packs | Rules |
|----------|-------|-------|
| Java | spring, spring-security | 35 |
| JavaScript | express, nextjs, react | 17 |
| Python | django, flask, fastapi, graphql | 30 |
| TypeScript | angular, nestjs | 9 |
| Ruby | rails | 15 |
| C# | aspnet, razor | 10 |
| PHP | laravel, symfony | 9 |
| Go | gin, echo | 7 |

## Semgrep Comparison

### Vulnerable Repos

| Repo | PatchFlow | Semgrep | PatchFlow Taint | Semgrep ERROR |
|------|-----------|---------|-----------------|---------------|
| WebGoat | 635 | 219 | 8 | 30 |
| Juice Shop | 347 | 74 | 66 | 10 |
| DVGA | 99 | 29 | 1 | 4 |
| NodeGoat | 375 | 35 | 6 | 7 |
| RailsGoat | 81 | 44 | 14 | 9 |
| DVNA | 84 | 23 | 20 | 3 |
| DVFA | 15 | 5 | 6 | 3 |

### Clean Repos

| Repo | PatchFlow | Semgrep | PatchFlow Blocking | Semgrep ERROR |
|------|-----------|---------|---------------------|---------------|
| cobra | 18 | 14 | 0 | 0 |
| flask | 43 | 16 | 0 | 1 |
| django | 143 | 612 | 0 | 81 |

### Key Takeaway

PatchFlow's taint-confirmed findings (source-to-sink) are a unique strength
vs Semgrep OSS. On Juice Shop, PatchFlow finds 66 taint-confirmed findings
vs Semgrep's 10 ERROR-level. On clean repos, PatchFlow's framework pack
exclusions prevent 81 ERROR-level FPs that Semgrep reports on Django
framework source.

## Clean Precision Baseline

| Repo | B1 Total | v1 Total | Delta | Blocking Delta |
|------|----------|----------|-------|----------------|
| cobra | 18 | 18 | 0 | 0 |
| flask | 43 | 43 | 0 | 0 |
| django | 143 | 143 | 0 | 0 |

**Claim:** Framework rule expansion did not introduce clean-repo blocking
regressions in the tracked baseline.

## Framework Source-Model Wins

| Repo | B1 | v1 | Delta | Source Model |
|------|----|----|-------|-------------|
| WebGoat | 627 | 635 | +8 | Spring annotations → SQL/XSS/XXE sinks |
| Juice Shop | 273 | 347 | +74 | TS normalization + req.* → eval/query/render |
| DVGA | 91 | 99 | +8 | GraphQL resolver args → SQLAlchemy text() |

## Output Quality: SARIF/JSON

PatchFlow includes policy metadata in both JSON and SARIF outputs:

- `mode` — effective rule behavior (block/inform/off)
- `blocking` — whether this finding can fail CI
- `mode_source` — where the mode came from (default/project_config/cli)
- `maturity` — rule maturity (experimental/beta/stable/enterprise)
- `owasp` — OWASP Top 10 category

This enables CI dashboards, audit trails, and enterprise compliance reporting.

## Trivy Comparison (SCA Lane)

| Repo | PatchFlow SCA | Trivy SCA |
|------|---------------|-----------|
| WebGoat | 107 | 100 |
| Juice Shop | 68 | 0 |
| DVGA | 65 | 44 |
| Flask | 17 | 13 |
| Django | 0 | 0 |

PatchFlow's OSV integration finds more vulnerabilities on Juice Shop (68 vs 0)
and WebGoat (107 vs 100). Trivy remains stronger for container/infra scanning.

## Known Limitations

1. **Interprocedural duplicate pairs:** Juice Shop shows paired base/IP
   findings (e.g., TP-JS001 x11 + TP-JS001-IP x11). These are not duplicates
   — base detects direct flow, -IP detects interprocedural flow. Dedup is
   planned for B10.

2. **Auth/IDOR heuristics:** PF-GRAPHQL-AUTH-001 and PF-FASTAPI-AUTH-001 are
   heuristic rules. They fire as `inform` by default and should not block
   CI without manual review. Missing ownership validation is not always
   provable statically. The 6 PF-GRAPHQL-AUTH-001 findings in DVGA were
   manually reviewed — all 6 are true positives (see
   `MANUAL_REVIEW_DVGA_AUTH_findings.md`).

3. **Java coverage:** Spring annotation source modeling is newer than
   Semgrep's Java rules. PatchFlow finds 8 taint-confirmed findings on
   WebGoat vs Semgrep's 30 ERROR-level. Java coverage will improve in
   future releases.

4. **Scan time:** Not fully benchmarked in this report. Planned for B10.

5. **Semgrep comparison:** Semgrep `--config auto` uses the free OSS
   ruleset. Semgrep Pro (paid) includes taint tracking that may find
   additional findings not captured in this comparison.

## Roadmap

| Phase | Focus |
|-------|-------|
| B10 | Performance pass, duplicate reduction, scan time optimization |
| B11 | User custom framework extensions, org-specific sources/sinks |
| Future | Interprocedural dedup, Java coverage expansion, dashboard integration |

## Claims

### What we can say

- PatchFlow supports framework-aware rule packs across 18 frameworks.
- PatchFlow supports ESLint-style rule governance with block, inform, and off modes.
- PatchFlow includes rule mode metadata in JSON and SARIF outputs for CI auditability.
- PatchFlow improved taint-confirmed findings in WebGoat, Juice Shop, and DVGA without clean-repo blocking regressions in the tracked baseline.
- PatchFlow's taint engine is built-in and free (no paid tier required).

### What we cannot say

- PatchFlow has no false positives.
- PatchFlow is better than Semgrep everywhere.
- PatchFlow replaces Trivy.

## Reproducibility

All benchmark data was generated on:
- Go 1.26.4, Darwin 25.4.0, arm64
- PatchFlow commit `e3716fc`
- Semgrep 1.168.0
- Trivy 0.71.2
- Offline mode (local OSV DB)

To reproduce:
```bash
# PatchFlow
patchflow scan run --json --quiet --offline

# Semgrep
semgrep scan --config auto --json --quiet

# Trivy (SCA only)
trivy fs --format json --quiet .
```

See `FRAMEWORK_RULES_V1_BASELINE.md` for the full frozen baseline.
