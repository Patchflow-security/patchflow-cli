# Changelog

All notable changes to PatchFlow CLI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- CI workflow (`.github/workflows/ci.yml`) with multi-OS build, vet, test, and goreleaser dry-run on PRs
- Release process documentation (`RELEASE.md`)
- `make install-tools` target for local release tooling setup
- `make release-check` target to validate goreleaser config
- Snapshot/dry-run release support via `workflow_dispatch` on the Release workflow
- Cosign signature verification step in the release pipeline
- SPDX SBOM upload to GitHub releases
- Patchflow-security GitHub org repos: `patchflow-cli`, `homebrew-tap`, `scoop-bucket`, `patchflow-benchmarks`

### Changed
- Go module path: `github.com/patchflow/patchflow-cli` → `github.com/Patchflow-security/patchflow-cli`
- Docker images: `ghcr.io/patchflow/cli` → `ghcr.io/patchflow-security/cli`
- Homebrew tap: `patchflow/homebrew-tap` → `Patchflow-security/homebrew-tap`
- Scoop bucket: `patchflow/scoop-bucket` → `Patchflow-security/scoop-bucket`
- `patchflow-scan.yml` now builds from source instead of `go install @latest` (scans actual PR code)
- `scripts/install.sh` now supports `shasum -a 256` fallback for macOS checksum verification
- Release workflow handles both tag pushes and manual `workflow_dispatch` triggers
- Release workflow uploads cosign signatures and SBOMs to the GitHub release

### Fixed
- Broken `go install` path in `patchflow-scan.yml` (referenced non-existent `cmd/patchflow` subpath)
- Broken relative benchmark path in goreleaser release header (now uses absolute GitHub URL)
- `sha256sum` not available on macOS in `scripts/install.sh`

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
