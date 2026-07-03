# PatchFlow CLI Installation Test Matrix

This directory contains containerized tests for the PatchFlow CLI install script and common post-install commands.

## Test platforms

| Container | What it tests |
|-----------|---------------|
| `Dockerfile.ubuntu-amd64` | Fresh Ubuntu, root user, default `~/.local/bin` install |
| `Dockerfile.ubuntu-arm64` | Fresh Ubuntu on arm64 |
| `Dockerfile.alpine-amd64` | Minimal musl-based Linux (Alpine) |
| `Dockerfile.ubuntu-nonroot` | Non-root user install into `~/.local/bin` |
| `Dockerfile.linuxbrew` | Homebrew/Linuxbrew environment (slow, optional) |

## Running all tests

```bash
cd /Users/digitalcenter/patchflow-cli
tests/install/run-tests.sh
```

This uses Podman if available, otherwise Docker.

### Run a single platform manually

```bash
cd /Users/digitalcenter/patchflow-cli
podman build -f tests/install/Dockerfile.ubuntu-amd64 -t patchflow-install-test-ubuntu-amd64 .
podman run --rm patchflow-install-test-ubuntu-amd64
```

### Enable the slow Linuxbrew test

```bash
INCLUDE_LINUXBREW=1 tests/install/run-tests.sh
```

## What is verified

`test-install.sh` checks:

- The install script is valid POSIX sh.
- The latest release downloads and checksums verify.
- The binary is installed to the expected location.
- The binary is executable.
- The install script prints a usable PATH hint.
- `--help`, `--version`, and `--install-dir` flags work.

`test-commands.sh` checks that core CLI commands work after install:

- `patchflow version --json`
- `patchflow doctor --json`
- `patchflow rules list`
- `patchflow rules list-frameworks`
- Help is available for `rules validate`, `config migrate`, `explain`, `scan run`, `doctor`.
- A smoke `scan run` on an empty directory does not crash.

## Notes

- The test script downloads the **latest GitHub release**, so it tests whatever is currently published (not the local source tree).
- To test the local binary instead, build it and mount it into the container or create a local release snapshot.
- The `ubuntu-amd64` image on an Apple Silicon host will run as arm64. For true amd64 coverage, use an amd64 runner or enable QEMU binfmt emulation.
