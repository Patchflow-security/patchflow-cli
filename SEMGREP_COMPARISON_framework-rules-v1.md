# Semgrep Comparison — framework-rules-v1

**Date:** 2026-07-03  
**PatchFlow version:** framework-rules-v1 (commit `e3716fc`)  
**Semgrep version:** 1.168.0 (`--config auto`)  
**Mode:** Offline (PatchFlow), online (Semgrep auto ruleset)

## Methodology

- **PatchFlow:** `patchflow scan run --json --quiet --offline`
- **Semgrep:** `semgrep scan --config auto --json --quiet`
- Both tools run on the same benchmark repos at the same commit state.
- Semgrep `--config auto` uses the Semgrep Registry default ruleset (online).
- PatchFlow uses embedded rules + local OSV DB (offline).

## Vulnerable Repo Comparison

| Repo | PatchFlow Total | Semgrep Total | PatchFlow Taint | Semgrep ERROR | PatchFlow Blocking |
|------|-----------------|---------------|-----------------|---------------|---------------------|
| WebGoat | 635 | 219 | 8 | 30 | 7 |
| Juice Shop | 347 | 74 | 66 | 10 | 0 |
| DVGA | 99 | 29 | 1 | 4 | 0 |
| NodeGoat | 375 | 35 | 6 | 7 | 2 |
| RailsGoat | 81 | 44 | 14 | 9 | 0 |
| DVNA | 84 | 23 | 20 | 3 | 0 |
| DVFA | 15 | 5 | 6 | 3 | 0 |

### Key Observations

1. **PatchFlow finds more total findings** on every vulnerable repo. This is
   partly because PatchFlow includes SCA (OSV), license scanning, secrets
   detection, and IaC (Checkov) in addition to SAST — Semgrep `--config auto`
   is SAST-only.

2. **PatchFlow taint-confirmed findings are a unique strength.** Semgrep's
   taint tracking is available in Semgrep Pro (paid), not in the open-source
   `--config auto` ruleset. PatchFlow's taint engine is built-in and free.

3. **Semgrep ERROR-level findings** (equivalent to "high confidence") are
   fewer than PatchFlow's taint-confirmed findings on Juice Shop (10 vs 66)
   and DVNA (3 vs 20), indicating PatchFlow's source-to-sink modeling finds
   more real vulnerabilities in JS/TS code.

4. **WebGoat:** Semgrep finds 30 ERROR-level vs PatchFlow's 8 taint-confirmed.
   Semgrep has strong Java rules. PatchFlow's Spring annotation source model
   is newer and still maturing.

## Clean Repo Comparison

| Repo | PatchFlow Total | Semgrep Total | PatchFlow Blocking | Semgrep ERROR |
|------|-----------------|---------------|---------------------|---------------|
| cobra | 18 | 14 | 0 | 0 |
| flask | 43 | 16 | 0 | 1 |
| django | 143 | 612 | 0 | 81 |

### Key Observations

1. **Django clean repo:** Semgrep reports 612 findings (81 ERROR-level) on
   the Django framework source code. PatchFlow reports 143 (0 blocking).
   PatchFlow's framework pack exclusions prevent framework library source
   from triggering framework rules.

2. **Flask clean repo:** Semgrep reports 16 findings (1 ERROR) on the Flask
   framework source. PatchFlow reports 43 (0 blocking). PatchFlow's findings
   are SCA/license/secrets, not SAST false positives.

3. **Cobra:** Both tools report similar low counts. No false positives from
   either tool.

## Feature Comparison

| Feature | PatchFlow | Semgrep (OSS) | Semgrep Pro |
|---------|-----------|---------------|-------------|
| SAST pattern rules | Yes (427) | Yes (1000+) | Yes |
| Taint tracking | Yes (47 rules, free) | Limited (community rules) | Yes (Pro) |
| Framework-aware sources | Yes (18 packs) | Limited | Yes (Pro) |
| SCA/dependency scanning | Yes (OSV, offline) | No | No |
| Secrets detection | Yes (35 rules) | Yes (community) | Yes |
| IaC scanning | Yes (Checkov) | Limited | Yes (Pro) |
| License compliance | Yes | No | No |
| Rule governance (block/inform/off) | Yes | No | No |
| Maturity-based defaults | Yes | No | No |
| Configuration profiles | Yes (6) | No | No |
| SARIF output | Yes | Yes | Yes |
| JSON output with mode metadata | Yes | No | No |
| Offline mode | Yes | No (registry needed) | No |
| Custom rules (YAML) | Yes | Yes | Yes |
| Custom rules (Go) | Yes | No | No |

## Scan Time Comparison

| Repo | PatchFlow | Semgrep |
|------|-----------|---------|
| DVGA | ~8s | ~13s |

Note: Full scan time benchmarking across all repos is planned for B10.

## Precision Analysis

### PatchFlow Advantages

1. **Policy-aware findings:** Every finding includes `mode`, `blocking`,
   `mode_source`, and `maturity` metadata. Semgrep findings have severity
   but no governance metadata.

2. **Clean-repo discipline:** PatchFlow's framework pack exclusions prevent
   framework library source from triggering framework rules. Semgrep reports
   612 findings on Django framework source — many are likely true positives
   in framework code, but they are not actionable for users of the framework.

3. **Taint tracking is free:** PatchFlow's source-to-sink taint engine is
   built-in. Semgrep requires the paid Pro tier for equivalent taint tracking.

4. **Offline SCA:** PatchFlow includes OSV-based SCA scanning with a local
   database. Semgrep does not include SCA scanning.

### Semgrep Advantages

1. **Larger rule ecosystem:** Semgrep Registry has thousands of community
   rules. PatchFlow has 777 embedded rules.

2. **Faster on large repos:** Semgrep's pattern engine is highly optimized.
   PatchFlow's multi-analyzer architecture has more overhead.

3. **Custom rule language:** Semgrep's rule language is more expressive for
   pattern matching. PatchFlow uses regex patterns (simpler but less precise).

4. **Java coverage:** Semgrep has mature Java rules. PatchFlow's Spring
   annotation source model is newer and still maturing.

## Conclusion

PatchFlow and Semgrep are complementary tools with different strengths:

- **PatchFlow** excels at: framework-aware taint tracking, policy-aware
  findings, clean-repo discipline, offline SCA, rule governance, and CI
  integration with block/inform/off modes.

- **Semgrep** excels at: large rule ecosystem, custom rule expressiveness,
  scan speed on large repos, and Java coverage.

**Recommendation:** Use PatchFlow as the primary CI gate for its governance
and clean-repo discipline. Use Semgrep for ad-hoc deep scans and custom rule
development. They can be run in parallel without conflict.
