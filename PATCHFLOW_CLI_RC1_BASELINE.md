# PatchFlow CLI RC1 Baseline

**Frozen at:** commit `e3716fc` — "feat(scan): register --rules-config CLI flag"
**Date:** 2026-07-03
**Version:** 0.1.2

## Capability Summary

| Capability | Status |
|-----------|--------|
| SAST (Go AST) | 35 rules |
| SAST (patterns, multi-language) | 283 rules |
| SAST (tree-sitter AST) | 18 rules |
| SAST (taint patterns, source→sink) | 486 rules |
| Secrets detection | 42 patterns |
| Framework packs | 18 packs, 128 rules |
| Custom framework extensions | B11.5 complete |
| SCA (OSV.dev) | Local DB + API |
| License scanning | Registry-based |
| Reachability analysis | Dependency-level |
| Issue grouping | Function-boundary-first (B10.9) |
| Rule governance | 4 maturity levels, 4 profiles |
| SARIF output | v2.1.0 |
| JSON output | Stable schema |
| Markdown report | Stable |
| Suppression directives | `//patchflow:ignore` |
| Baseline comparison | New/known/resolved |
| Incremental scanning | File-level cache |

**Total rules:** 822 across 24 scanners + 18 framework packs

## Framework Packs

| Pack | Language | Rules |
|------|----------|-------|
| angular | typescript | 5 |
| aspnet | csharp | 8 |
| django | python | 7 |
| echo | go | 3 |
| express | javascript | 9 |
| fastapi | python | 9 |
| flask | python | 9 |
| gin | go | 4 |
| graphql | python | 5 |
| laravel | php | 6 |
| nestjs | typescript | 4 |
| nextjs | javascript | 4 |
| rails | ruby | 15 |
| razor | csharp | 2 |
| react | javascript | 4 |
| spring | java | 31 |
| spring-security | java | 4 |
| symfony | php | 3 |

## B11.5 Extension Hardening

| Feature | Status |
|---------|--------|
| Sink scoping by CWE/category | ✅ B11.5.1 |
| Source category scoping | ✅ B11.5.2 |
| Taint safe-pattern suppression | ✅ B11.5.3 |
| Unified `--config` flag | ✅ B11.5.4 |
| Strong validation | ✅ B11.5.5 |
| `func`/`function` YAML alias | ✅ |

## Test Results

- **Packages tested:** 61
- **All pass:** Yes
- **Vet clean:** Yes
- **New B11.5 tests:** 17 (11 sink scoping + 6 safe pattern suppression)

## Benchmark Results (no regression)

| Repo | Total | Blocking | Taint | Groups |
|------|-------|----------|-------|--------|
| DVGA | 99 | 0 | 1 | 25 |
| juice-shop | 314 | 0 | 33 | 148 |
| cobra | 18 | 0 | 0 | 12 |
| flask | 43 | 0 | 0 | 13 |

## CLI Surface

```bash
patchflow scan run           # Full scan (SAST + SCA + secrets + licenses)
patchflow scan run --config .patchflow/rules.yaml  # Unified config
patchflow scan run --profile deep  # Audit profile (all rules)
patchflow explain --rule PF-SPRING-SQLI-004  # Rule documentation
patchflow rules list         # List all rules
patchflow rules list-frameworks  # List framework packs
patchflow rules validate     # Validate config
patchflow rules init         # Generate starter config
patchflow rules maturity     # Governance coverage report
patchflow rules docs         # Generate rule documentation
patchflow version            # Version info
patchflow doctor             # Diagnostic check
```

## Known Limitations

1. Safe pattern suppression for taint rules uses function-scope regex matching (not whole-program auth proof)
2. Function boundary detection is regex-based (not AST-based) — may miss nested/anonymous functions
3. Custom sinks without CWE/category attach to all taint rules (validated with warning)
4. Go SAST and taint analysis use go/packages (not file-by-file) — separate from parallel scanner pipeline
5. External tools (gosec, bandit, semgrep, gitleaks) run sequentially after embedded scanners

## Release Infrastructure

| Component | Status |
|-----------|--------|
| GoReleaser config | ✅ 6 targets, checksums, SBOMs, cosign |
| CI (GitHub Actions) | ✅ Build/test on ubuntu/macos/windows |
| Release workflow | ✅ Tag-triggered, publishes to GHCR/Homebrew/Scoop |
| Self-scan workflow | ✅ SARIF upload to GitHub Code Scanning |
| Dockerfile | ✅ Distroless, multi-arch |
| Makefile | ✅ build/test/release/docker targets |
| RELEASE.md | ✅ Full release process documented |
