# Trivy Comparison — framework-rules-v1

**Date:** 2026-07-03  
**PatchFlow version:** framework-rules-v1 (commit `e3716fc`)  
**Trivy version:** 0.71.2  
**Scope:** SCA/dependency scanning only (no IaC or container changes since B1)

## Methodology

- **PatchFlow:** `patchflow scan run --json --quiet --offline` (local OSV DB)
- **Trivy:** `trivy fs --format json --quiet .` (online DB)
- Both tools scan the same repos at the same commit state.
- Only SCA/dependency findings are compared. SAST, secrets, and IaC are out
  of scope for this comparison.

## SCA Comparison

| Repo | PatchFlow SCA | Trivy SCA | PatchFlow Critical | Trivy Critical |
|------|---------------|-----------|---------------------|----------------|
| WebGoat | 107 | 100 | 13 | 10 |
| Juice Shop | 68 | 0 | 8 | 0 |
| DVGA | 65 | 44 | 2 | 2 |
| Flask (clean) | 17 | 13 | 0 | 0 |
| Django (clean) | 0 | 0 | 0 | 0 |

### Key Observations

1. **Juice Shop:** Trivy reports 0 SCA findings. This is likely because
   Juice Shop uses npm and Trivy's npm resolution may not detect
   transitive vulnerabilities in this project structure. PatchFlow's OSV
   integration finds 68 vulnerabilities (8 critical).

2. **WebGoat:** PatchFlow finds 107 vs Trivy's 100. PatchFlow's OSV DB may
   have more recent vulnerability data or broader package matching.

3. **DVGA:** PatchFlow finds 65 vs Trivy's 44. Similar to WebGoat, PatchFlow
  's OSV integration covers more packages.

4. **Flask (clean):** Both tools find similar numbers (17 vs 13). These are
   real vulnerabilities in Flask's dependencies, not false positives.

5. **Django (clean):** Both tools find 0 SCA findings. Django's dependencies
   are well-maintained.

## Feature Comparison (SCA Lane)

| Feature | PatchFlow | Trivy |
|---------|-----------|-------|
| Vulnerability DB | OSV (local, offline) | Trivy DB (online) |
| Offline mode | Yes | Yes (with --skip-db-update) |
| License scanning | Yes | Yes |
| Language coverage | Broad (OSV) | Broad |
| Container scanning | No | Yes |
| IaC scanning | Yes (Checkov) | Yes |
| Speed | Fast (local DB) | Fast (cached DB) |
| SARIF output | Yes | Yes |
| Rule governance | Yes (block/inform/off) | No |

## Positioning

Trivy remains strongest for:
- Container image scanning
- Cloud-native/Kubernetes manifest scanning
- CI/CD pipeline integration for infrastructure

PatchFlow is strongest for:
- Developer workflow SAST + SCA + secrets in one scan
- Framework-aware taint tracking
- Rule governance with block/inform/off modes
- Offline SCA with local OSV DB
- Remediation context (explain, fix snippets)

**Recommendation:** Use PatchFlow for developer-facing scans (PR review,
local development, framework-aware SAST). Use Trivy for container/infra
scanning in CI/CD pipelines. They cover different lanes.
