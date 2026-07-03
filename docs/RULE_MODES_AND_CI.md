# Rule Modes and CI Blocking

## Overview

PatchFlow uses a three-mode system for rule governance. Every finding has an
effective mode that determines whether it is reported and whether it can fail
CI.

## Modes

| Mode | Behavior | CI Exit Code |
|------|----------|--------------|
| `block` | Finding is reported and fails CI | Non-zero if any blocking findings |
| `inform` | Finding is reported but does not fail CI | Zero (informational) |
| `off` | Finding is suppressed entirely | N/A (not reported) |

## Mode Resolution

The effective mode for a rule is determined by the following resolution order
(first match wins):

1. **Project config** (`.patchflow/rules.yaml`) — explicit `rule_modes` entry
2. **CLI override** — `--mode` flag or `--rules-config` pointing to a custom file
3. **Maturity-based default** — computed from the rule's maturity and severity
4. **Fallback** — `inform` (safe default for unknown rules)

## Maturity-Based Defaults

| Maturity | High/Critical Severity | Medium/Low Severity |
|----------|----------------------|---------------------|
| Stable | `block` | `inform` |
| Enterprise | `block` | `inform` |
| Beta | `inform` | `inform` |
| Experimental | `inform` | `inform` |

**Key principle:** Experimental rules never block by default. You must
explicitly set them to `block` in your config.

## Configuration Profiles

`patchflow rules init --profile <name>` generates a pre-configured
`.patchflow/rules.yaml` based on a named profile:

| Profile | Description | Block | Inform | Off |
|---------|-------------|-------|--------|-----|
| `starter` | Stable high-confidence rules block, rest inform | Stable high/crit | — | — |
| `strict` | Stable + beta injection/auth-critical block | Stable + beta inj/auth | — | — |
| `audit` | Everything inform, nothing blocks | — | All | — |
| `framework-heavy` | Enable framework packs, stable rules block | Stable high/crit | — | — |
| `ci-blocking` | Block all high/critical (stable + beta), experimental off | High/crit (stable+beta) | Medium/low | Experimental |
| `enterprise` | Stable block, beta inform, experimental off | Stable high/crit | Beta | Experimental |

### Usage

```bash
# Generate config with a profile
patchflow rules init --profile strict

# Generate default config (all rules commented out)
patchflow rules init

# List effective modes after applying config
patchflow rules list --mode
```

## JSON Output Fields

When using `--json`, each finding includes mode-related fields:

```json
{
  "rule_id": "PF-GRAPHQL-SQLI-001",
  "severity": "high",
  "mode": "inform",
  "blocking": false,
  "mode_source": "default",
  "maturity": "beta"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `mode` | string | Effective rule behavior: `block`, `inform`, or `off` |
| `blocking` | bool | Whether this finding can fail CI (true when mode = block) |
| `mode_source` | string | Where the mode came from: `default`, `project_config`, or `cli` |
| `maturity` | string | Rule maturity: `experimental`, `beta`, `stable`, or `enterprise` |

## SARIF Output

SARIF output includes the mode in the result's `properties` field:

```json
{
  "ruleId": "PF-GRAPHQL-SQLI-001",
  "level": "warning",
  "properties": {
    "mode": "inform",
    "blocking": false,
    "modeSource": "default",
    "maturity": "beta",
    "cwe": "CWE-89",
    "owasp": "A03:2021 - Injection (SQLi)"
  }
}
```

SARIF `level` mapping:
- `block` → `error`
- `inform` → `warning`
- `off` → (not reported)

## Overriding Modes

### Per-Rule Override

```yaml
# .patchflow/rules.yaml
rule_modes:
  PF-GRAPHQL-SQLI-001: block    # promote to blocking
  PF-GRAPHQL-AUTH-001: off      # disable noisy heuristic
  G101: inform                  # demote to informational
```

### Framework Pack Controls

```yaml
frameworks:
  auto_detect: true
  enabled: [flask, graphql, spring]   # force-enable packs
  disabled: [angular]                  # disable even if detected
```

### CLI Override

```bash
# Use a specific config file
patchflow scan run --rules-config .patchflow/rules.yaml

# Disable all framework packs
patchflow scan run --no-frameworks
```

## CI Integration

### GitHub Actions

```yaml
- name: Run PatchFlow scan
  run: patchflow scan run --rules-config .patchflow/rules.yaml
  # Exit code will be non-zero if any blocking findings exist
```

### Blocking vs Non-Blocking

```bash
# Blocking mode (default) — fails CI on blocking findings
patchflow scan run

# Non-blocking mode — always exits 0, reports all findings
patchflow scan run --no-fail
```

## Best Practices

1. **Start with `audit` profile** — see what PatchFlow finds before enabling
   blocking.
2. **Promote rules to `block` gradually** — start with stable high/critical,
   then add beta rules as you verify they're not false positives.
3. **Use `off` for irrelevant rules** — if a rule doesn't apply to your
   codebase, disable it rather than living with noise.
4. **Keep experimental rules as `inform`** — they need validation before
   blocking.
5. **Review `inform` findings regularly** — they may indicate real issues
   that should be promoted to `block`.
