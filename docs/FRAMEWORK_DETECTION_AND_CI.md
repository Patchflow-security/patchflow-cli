# Framework Detection and Overrides

## Auto-Detection

PatchFlow automatically detects frameworks in your project using filesystem
signals (manifest files, directory structure, file extensions). Detected
frameworks activate their corresponding rule packs.

```bash
# See detected frameworks
patchflow rules list-frameworks

# See which rules are active for your project
patchflow rules list --framework flask
```

## Detection Signals

Each framework has a set of independent signals. A framework is detected when
enough signals match (MinSignals threshold):

| Framework | MinSignals | Key Signals |
|-----------|------------|-------------|
| Spring | 2 | pom.xml (spring-boot), build.gradle, application.yml |
| Express | 2 | package.json ("express") |
| Django | 2 | manage.py, settings.py, urls.py |
| Flask | 2 | requirements.txt (flask), pyproject.toml |
| FastAPI | 2 | requirements.txt (fastapi), pyproject.toml |
| GraphQL | 1 | requirements.txt (graphene/ariadne/strawberry), .graphql files |
| Angular | 2 | package.json (@angular/core), angular.json |
| React | 2 | package.json ("react"), src/**/*.jsx |
| Rails | 2 | Gemfile (rails), config/routes.rb |

## Overriding Detection

### Force-Enable a Pack

```yaml
# .patchflow/rules.yaml
frameworks:
  auto_detect: true
  enabled: [graphql, flask]   # always enable these packs
```

```bash
# Via CLI
patchflow scan run --framework graphql --framework flask
```

### Disable a Pack

```yaml
frameworks:
  auto_detect: true
  disabled: [angular]   # don't run Angular rules even if detected
```

```bash
# Via CLI
patchflow scan run --disable-framework angular
```

### Disable All Framework Packs

```bash
patchflow scan run --no-frameworks
```

## Framework Pack Overrides

You can extend official packs with custom sources, sinks, and sanitizers
without modifying the pack itself:

```yaml
framework_overrides:
  flask:
    custom_sources:
      - func: request.get_json
        is_subscript: false
    custom_sinks:
      - func: my_custom_query
        arg: 0
    severity_overrides:
      PF-FLASK-SQLI-001: critical   # override severity
```

## CI Configuration Examples

### GitHub Actions — Strict Mode

```yaml
name: Security Scan
on: [pull_request]

jobs:
  patchflow:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install PatchFlow
        run: |
          curl -sSL https://github.com/Patchflow-security/patchflow-cli/releases/latest/download/patchflow-linux-amd64 -o /usr/local/bin/patchflow
          chmod +x /usr/local/bin/patchflow
      - name: Initialize strict config
        run: patchflow rules init --profile strict
      - name: Run scan
        run: patchflow scan run --rules-config .patchflow/rules.yaml
```

### GitHub Actions — Audit Mode (Non-Blocking)

```yaml
name: Security Audit
on: [pull_request]

jobs:
  patchflow:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install PatchFlow
        run: |
          curl -sSL https://github.com/Patchflow-security/patchflow-cli/releases/latest/download/patchflow-linux-amd64 -o /usr/local/bin/patchflow
          chmod +x /usr/local/bin/patchflow
      - name: Initialize audit config
        run: patchflow rules init --profile audit
      - name: Run scan (non-blocking)
        run: patchflow scan run --rules-config .patchflow/rules.yaml --no-fail
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: patchflow-results.sarif
```

### GitLab CI

```yaml
security-scan:
  image: patchflow/cli:latest
  script:
    - patchflow rules init --profile ci-blocking
    - patchflow scan run --rules-config .patchflow/rules.yaml
  artifacts:
    reports:
      sast: patchflow-results.sarif
```

### Pre-Commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Patchflow-security/patchflow-cli
    rev: v0.2.0
    hooks:
      - id: patchflow
        args: ["scan", "run", "--rules-config", ".patchflow/rules.yaml"]
```

## Scanner Changed Files Only

For PR scans, PatchFlow can scan only changed files:

```bash
# Scan only files changed vs. main branch
patchflow scan changed --base main

# Scan only files in a specific PR
patchflow scan changed --base origin/main --head HEAD
```

## Suppressing Findings

### Inline Suppression

```python
def resolve_user(root, info, id):
    # patchflow:ignore PF-GRAPHQL-AUTH-001 -- ownership checked in middleware
    return User.query.filter_by(id=id).first()
```

### Config-Level Suppression

```yaml
rule_modes:
  PF-GRAPHQL-AUTH-001: off
```

### File-Level Exclusion

```yaml
# Exclude test files from specific rules
framework_overrides:
  flask:
    exclusions:
      - glob: "tests/**"
        reason: "Test files are not deployed code"
```
