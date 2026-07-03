# Framework Rules v1 — Frozen Baseline

**Date:** 2026-07-03  
**Phase:** Post-B8 (framework-rules-v1 candidate)  
**Purpose:** Reproducible benchmark anchor for the framework-rules-v1 release.

## Environment

| Field | Value |
|-------|-------|
| PatchFlow commit | `e3716fc371170155014c1392627a89624cf0dbb6` |
| Go version | go1.26.4 darwin/arm64 |
| OS | Darwin 25.4.0 (macOS) |
| Architecture | arm64 (Apple Silicon) |
| Trivy version | 0.71.2 |
| Semgrep | Not installed (comparison based on documented capabilities) |
| Offline mode | Yes (local OSV DB) |

## Rule Counts

| Metric | Value |
|--------|-------|
| Total rules (all engines) | 777 |
| Framework pack rules | 132 |
| Framework packs | 18 |
| Stable maturity | 79 |
| Beta maturity | 636 |
| Experimental maturity | 62 |
| Blocking-eligible by default | 37 |
| CWE-mapped rules | 217 |
| OWASP-mapped rules | 191 |

## Engine Breakdown

| Engine | Rule Count |
|--------|------------|
| patterns-embedded | 427 |
| framework-packs | 132 |
| taint-patterns | 47 |
| gosast-embedded | 35 |
| secrets-embedded | 35 |
| taint-ssa | 9 |

## Framework Packs

| Pack | Language | Rules |
|------|----------|-------|
| spring | java | 31 |
| rails | ruby | 15 |
| express | javascript | 9 |
| fastapi | python | 9 |
| flask | python | 9 |
| aspnet | csharp | 8 |
| django | python | 7 |
| laravel | php | 6 |
| angular | typescript | 5 |
| graphql | python | 5 |
| gin | go | 4 |
| nestjs | typescript | 4 |
| nextjs | javascript | 4 |
| react | javascript | 4 |
| spring-security | java | 4 |
| echo | go | 3 |
| symfony | php | 3 |
| razor | csharp | 2 |

## Profiles Available

| Profile | Description |
|---------|-------------|
| starter | Stable high/critical block, rest inform |
| strict | Stable + beta injection/auth-critical block |
| audit | Everything inform, nothing blocks |
| framework-heavy | Enable framework packs, stable block |
| ci-blocking | Block high/critical (stable+beta), experimental off |
| enterprise | Stable block, beta inform, experimental off |

## Benchmark Repos

### Vulnerable Repos

| Repo | Framework | Total | Taint | Framework Rules | Blocking | High/Crit |
|------|-----------|-------|-------|-----------------|----------|-----------|
| webgoat | Spring | 635 | 8 | 2 | 7 | 358 |
| juice-shop | Express | 347 | 66 | 20 | 0 | 255 |
| dvga | GraphQL | 99 | 1 | 7 | 0 | 38 |
| nodegoat | Express | 375 | 6 | 1 | 2 | 254 |
| railsgoat | Rails | 81 | 14 | 1 | 0 | 50 |
| dvna | Express | 84 | 20 | 1 | 0 | 56 |
| dvfa | Flask | 15 | 6 | 0 | 0 | 8 |

### Clean Repos (FP Baseline)

| Repo | Framework | Total | Taint | Framework Rules | Blocking | High/Crit |
|------|-----------|-------|-------|-----------------|----------|-----------|
| cobra | Go CLI | 18 | 0 | 0 | 0 | 4 |
| flask | Flask framework | 43 | 0 | 0 | 0 | 21 |
| django | Django framework | 143 | 3 | 0 | 0 | 78 |

## Key Improvements Since B1 Baseline

| Repo | B1 Total | v1 Total | Delta | Key Change |
|------|----------|----------|-------|------------|
| webgoat | 627 | 635 | +8 | Spring annotation source model (TP-JAVA*) |
| juice-shop | 273 | 347 | +74 | TS normalization + direct source-to-sink (TP-JS*) |
| dvga | 91 | 99 | +8 | GraphQL source model + SQLAlchemy text() sink |
| django (clean) | 143 | 143 | 0 | No FP regression |
| flask (clean) | 43 | 43 | 0 | No FP regression |

## Test Suite

| Metric | Value |
|--------|-------|
| Test packages | 61 |
| Failing packages | 0 |
| `go vet` | clean |
| `go build` | clean |
