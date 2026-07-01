# Changelog

All notable changes to PatchFlow CLI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2025-07-01

### Security
- Pinned all GitHub Actions to immutable SHA commits (preplies mutable-action supply-chain attacks)
- Removed `curl | sh` syft install in release workflow — replaced with pinned download script
- Fixed composite-action shell injection risk in `action.yml`
- Hardened Docker runtime: non-root user, read-only filesystem, minimal base image
- Token retrieval now uses OS keychain with 0600-permission file fallback
- Report file permissions set to 0600 (was 0644)
- Gitleaks behavior fixed: `.gitleaks.toml` added for allowlist control
- Secret rule IDs normalized for consistent SARIF reporting

### Changed
- GoReleaser pinned to v2.15.4 (avoids `brews` deprecation as failing config in newer versions)
- Go version updated to 1.26.4 in all workflows
- `scripts/install.sh` hardened with better error handling and checksum verification
- Container image validation improved in `internal/container/scanner.go`

### Fixed
- pnpm workspaces under `packages/` were skipped during manifest detection
- Golden tests expected stale rule IDs that no longer match the registry
- PR artifact tests wrote outside the validated project path
- Bare `return err` wrapped with context in critical paths (SAST runner, report generator, benchmark, OSV DB)
- Hardcoded `/usr/bin/time` path in benchmark now tries PATH first, then absolute fallback

## [0.1.0] - 2025-06-27

### Added
- GoReleaser config with multi-platform builds (linux/darwin/windows, amd64/arm64)
- Docker images with multi-arch manifests (buildx)
- Homebrew tap and Scoop bucket auto-publish
- Cosign image and blob signing
- SPDX SBOM generation via syft
- GitHub Action (`action.yml`) for composite security scan workflow
- Pre-commit hooks for scan and secret detection
- Install script (`scripts/install.sh`) with checksum verification
- Benchmark results: 100% recall on 18 vulnerable repos, 0.094 HC/KLOC on clean repos
- Embedded SAST engine: pattern scanner, taint analysis (tree-sitter), AST rules
- Framework pack system (Rails reference pack)
- Governance registry with maturity levels (experimental/beta/stable)
- Incremental scanning with mtime fast-path and git diff pre-filter
