# Two-minute public demo

## Promise

Install PatchFlow, scan one intentionally vulnerable file, understand the
finding, compare it with a clean equivalent, and generate SARIF. The scan is
local, requires no account, and uses no source upload.

## Pinned inputs

- Release: `v0.1.6`
- Fixture: `examples/quickstart` at the CLI commit being demonstrated
- Rule: `PY001` (`eval()` with potential user input)
- Mode: offline, embedded scanners available with no extra install, no license
  or reachability lookup; supported external scanners may supplement if present

Use the launch commit SHA instead of `main` in the clone command when the launch
release is cut.

## Commands

Install on macOS or Linux:

```bash
curl -fsSL https://github.com/Patchflow-security/patchflow-cli/raw/main/scripts/install.sh |
  bash -s -- --version v0.1.6
export PATH="$HOME/.local/bin:$PATH"
patchflow version
```

Prepare isolated copies of the public fixtures. Isolation prevents the demo scan
from treating the CLI source repository as its Git root:

```bash
DEMO_ROOT="$(mktemp -d)"
git clone --depth 1 https://github.com/Patchflow-security/patchflow-cli.git "$DEMO_ROOT/source"
cp -R "$DEMO_ROOT/source/examples/quickstart/vulnerable" "$DEMO_ROOT/vulnerable"
cp -R "$DEMO_ROOT/source/examples/quickstart/clean" "$DEMO_ROOT/clean"
git -C "$DEMO_ROOT/vulnerable" init -q
git -C "$DEMO_ROOT/clean" init -q
git -C "$DEMO_ROOT/vulnerable" -c user.name=PatchFlow -c user.email=demo@patchflow.dev add .
git -C "$DEMO_ROOT/vulnerable" -c user.name=PatchFlow -c user.email=demo@patchflow.dev commit -qm fixture
git -C "$DEMO_ROOT/clean" -c user.name=PatchFlow -c user.email=demo@patchflow.dev add .
git -C "$DEMO_ROOT/clean" -c user.name=PatchFlow -c user.email=demo@patchflow.dev commit -qm fixture
```

Scan, explain, and export:

```bash
cd "$DEMO_ROOT/vulnerable"
patchflow doctor
patchflow scan run --offline --no-licenses --no-reachability
patchflow explain --rule PY001
patchflow scan run --offline --no-licenses --no-reachability \
  --format sarif --output patchflow-results.sarif --quiet

cd "$DEMO_ROOT/clean"
patchflow scan run --offline --no-licenses --no-reachability
```

Expected proof points:

- the vulnerable scan includes `PY001` and a fix hint;
- `explain` describes why `eval()` is unsafe and provides suppression syntax;
- `patchflow-results.sarif` is SARIF 2.1.0 and contains `PY001`;
- the clean scan does not contain `PY001`;
- none of the commands uses `login`, `--submit`, or a source-upload endpoint.

## Automated rehearsal

From a CLI checkout:

```bash
./scripts/verify-quickstart.sh "$(command -v patchflow)"
```

The script creates isolated fixtures, enforces the five-minute ceiling, and
writes `onboarding-evidence.json`. CI uploads one evidence file per supported
platform. The automated timing is not a replacement for the five human sessions.

## Failure handling

- Installer failure: retain the checksum or HTTP error and stop the demo.
- `doctor` warning: follow the printed `Next steps`; every non-pass structured
  check must include a remediation.
- Missing `PY001`: stop launch and treat the onboarding workflow as failed.
- Network outage: the scan still runs because the demo is offline; installation
  still requires GitHub release access.

Support and security reports: use the repository issue forms. Do not place a
real secret or undisclosed vulnerability in a public issue.
