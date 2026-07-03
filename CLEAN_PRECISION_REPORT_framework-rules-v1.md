# Clean Precision Report — framework-rules-v1

**Date:** 2026-07-03  
**Baseline:** B1 (2026-07-02)  
**Candidate:** framework-rules-v1 (post-B8)

## Executive Summary

Framework rule expansion from B1 to framework-rules-v1 added 132 framework
rules, 18 framework packs, enhanced taint source modeling (Spring annotations,
GraphQL resolvers, Angular route data, direct source-to-sink), and SQLAlchemy
`text()` sink support. Despite this expansion, **clean repos show zero
blocking regressions and zero taint FP regressions** in the tracked baseline.

## Methodology

Each clean repo was scanned with:
```bash
patchflow scan run --json --quiet --offline
```

Findings are categorized by analyzer and rule family. The key metric is
**delta from B1 baseline** — any increase indicates a regression.

## Clean Repo Results

### cobra (Go CLI library)

| Metric | B1 | v1 | Delta |
|--------|----|----|-------|
| Total findings | 18 | 18 | 0 |
| SAST findings | 14 | 14 | 0 |
| SCA/license findings | 4 | 4 | 0 |
| Taint findings | 0 | 0 | 0 |
| Blocking findings | 0 | 0 | 0 |
| Framework rule findings | 0 | 0 | 0 |

**Verdict:** No regression. Cobra is a Go CLI library with no web framework,
so framework rules do not activate.

### flask (Python web framework source)

| Metric | B1 | v1 | Delta |
|--------|----|----|-------|
| Total findings | 43 | 43 | 0 |
| SAST findings | 6 | 6 | 0 |
| SCA/license/secrets | 37 | 37 | 0 |
| Taint findings | 0 | 0 | 0 |
| Blocking findings | 0 | 0 | 0 |
| Framework rule findings | 0 | 0 | 0 |

**Verdict:** No regression. The Flask framework source itself does not trigger
Flask pack rules because the `djangoSourceExclusions` pattern excludes
framework library source code.

### django (Python web framework source, ~250k LOC)

| Metric | B1 | v1 | Delta |
|--------|----|----|-------|
| Total findings | 143 | 143 | 0 |
| SAST findings | 132 | 132 | 0 |
| SCA/license/secrets | 11 | 11 | 0 |
| Taint findings | 3 | 3 | 0 |
| Blocking findings | 0 | 0 | 0 |
| Framework rule findings | 0 | 0 | 0 |
| PF-GRAPHQL* findings | 0 | 0 | 0 |

**Verdict:** No regression. The conservative GraphQL resolver detection
(requires both `resolve_*` name AND `info` parameter) correctly avoids
triggering on Django ORM methods like `resolve_expression_parameter`.

## Key Claims

1. **Zero blocking regressions** in clean repos from B1 to framework-rules-v1.
2. **Zero taint FP regressions** — Django stays at 3 taint findings (pre-existing
   TP-PY001 findings from non-framework code), Flask stays at 0.
3. **Zero framework rule FPs** — no PF-* rules fire on clean framework source code.
4. **GraphQL resolver detection is conservative** — Django ORM methods with
   `resolve_` prefix are not flagged because they lack the `info` parameter.

## Analyzer Breakdown (Django)

| Analyzer | Findings |
|----------|----------|
| patterns-embedded | 93 |
| treesitter-ast | 36 |
| taint-patterns | 3 |
| registry-license | 9 |
| gitleaks | 2 |

The 3 taint findings in Django are pre-existing TP-PY001 findings from
non-framework Python code (cursor.execute with string concatenation). These
are not related to framework rule expansion.

## Conclusion

Framework rule expansion did not introduce clean-repo blocking regressions
in the tracked baseline. The combination of:
- Framework pack exclusions (django/**, flask/**, tests/**, docs/**)
- Conservative GraphQL resolver detection (requires `info` parameter)
- Maturity-based mode defaults (experimental/beta = inform, never block)

...effectively prevents framework rule FPs from affecting CI gates.
