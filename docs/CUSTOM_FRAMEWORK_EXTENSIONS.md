# Custom Framework Extensions

PatchFlow's official framework packs (Spring, Express, Django, Rails, etc.) ship with built-in sources, sinks, sanitizers, and safe patterns. **Framework extensions** let you add organization-specific entries to these packs without writing full custom rules.

## Why Extensions?

Real companies have internal wrappers that the scanner cannot know by default:

```text
CompanyRequest.getParam()
LegacySql.run()
SecureHtml.clean()
InternalHttp.fetch()
TenantAuth.requireOwner()
```

Extensions let you teach the scanner about these without forking the official packs.

## Schema

Add a `framework_extensions` section to `.patchflow/rules.yaml`:

```yaml
framework_extensions:
  spring:
    custom_sources:
      - annotation: "@TenantInput"
      - function: "InternalRequest.getParam"

    custom_sinks:
      - function: "LegacySql.run"
        cwe: "CWE-89"
        category: "sql_injection"
        severity: "high"
      - function: "InternalHttp.fetch"
        cwe: "CWE-918"
        category: "ssrf"
        severity: "high"

    custom_sanitizers:
      - function: "CompanySql.safe"
      - function: "UrlAllowlist.validate"

    safe_patterns:
      - pattern: "TenantAuth.requireOwner"
        reason: "Ownership validation performed by internal auth helper"

  express:
    custom_sources:
      - function: "ctx.input"
      - function: "getRequestParam"

    custom_sinks:
      - function: "db.raw"
        cwe: "CWE-89"
        severity: "high"

    custom_sanitizers:
      - function: "sanitizeHtml"
      - function: "validateRedirectUrl"
```

## Field Reference

### custom_sources

| Field       | Type   | Required         | Description |
|-------------|--------|------------------|-------------|
| `func`      | string | one of func/annotation | Function/method name that produces tainted data |
| `annotation`| string | one of func/annotation | Java/C# annotation (e.g., `@TenantInput`) |
| `is_subscript` | bool | no | Whether this is a subscript access (e.g., `req["param"]`) |

### custom_sinks

| Field       | Type   | Required | Description |
|-------------|--------|----------|-------------|
| `func`      | string | yes      | Function/method name that consumes tainted data |
| `arg_index` | int    | no       | Which argument is tainted (default: 0) |
| `cwe`       | string | no       | CWE identifier (e.g., `CWE-89`) for categorization |
| `category`  | string | no       | Vulnerability category (e.g., `sql_injection`) |
| `severity`  | string | no       | Informational severity hint (the actual severity comes from the matching rule) |

### custom_sanitizers

| Field   | Type   | Required          | Description |
|---------|--------|-------------------|-------------|
| `func`  | string | one of func/regex | Function/method name that neutralizes taint |
| `regex` | string | one of func/regex | Regex pattern that indicates sanitization |

### safe_patterns

| Field    | Type   | Required | Description |
|----------|--------|----------|-------------|
| `pattern`| string | yes      | Regex pattern that suppresses a finding when found on the same line |
| `reason` | string | no       | Human-readable explanation (shown in `explain` output) |

## How Extensions Work

1. PatchFlow loads the official framework pack (e.g., `spring`)
2. Your extensions are merged **on top** of the official pack
3. Custom sources/sinks are added to all taint rules in the pack
4. Custom sanitizers are added to all rules in the pack
5. Safe patterns are added to all rules in the pack

Extensions **only add** — they never remove official sources, sinks, or sanitizers.

## Relationship to framework_overrides

`framework_overrides` is the original extension mechanism. `framework_extensions` is the B11 enhancement that adds:

- **`safe_patterns`** — not available in overrides
- **CWE/category/severity on sinks** — not available in overrides
- **Separate namespace** — keeps org-specific config visually distinct from pack tuning

Both sections are merged into the same pack override pipeline. If both define entries for the same framework, they are combined.

## Commands

### Explain with extensions

```bash
patchflow explain --rule PF-SPRING-SQLI-001
```

Output includes:

```text
  Project extensions:
    Additional sources:
      @TenantInput
    Additional sinks:
      LegacySql.run
    Additional sanitizers:
      CompanySql.safe
    Additional safe patterns:
      - Ownership validation performed by internal auth helper
```

### Validate extensions

```bash
patchflow rules validate .patchflow/rules.yaml
```

Checks:
- Valid framework names
- Sources have `func` or `annotation`
- Sinks have `func`
- Sanitizers have `func` or `regex`
- Safe patterns have `pattern`
- All regex patterns compile
- CWE format on sinks

## Examples

### Spring internal request wrapper

```yaml
framework_extensions:
  spring:
    custom_sources:
      - annotation: "@TenantInput"
    custom_sinks:
      - function: "LegacySql.run"
        cwe: "CWE-89"
```

### Express custom database wrapper

```yaml
framework_extensions:
  express:
    custom_sinks:
      - function: "db.raw"
        cwe: "CWE-89"
```

### Django internal sanitizer

```yaml
framework_extensions:
  django:
    custom_sanitizers:
      - function: "secure_markdown"
```

### Rails organization auth helper

```yaml
framework_extensions:
  rails:
    safe_patterns:
      - pattern: "TenantAuth.require_owner"
        reason: "Ownership validation by internal auth helper"
```

## Limitations

- **Extensions only extend** — you cannot remove official sources/sinks/sanitizers. This is intentional to prevent misconfiguration.
- **Safe pattern suppression for taint rules** uses function-scope matching: if the safe pattern regex matches any line in the same function as the taint finding, the finding is suppressed. This is intentionally conservative — it does not attempt whole-program auth proof.
- **Unscoped sinks (no CWE/category) attach to all taint rules** in the pack. Use `cwe` or `category` to scope sinks to specific rule types. `patchflow rules validate` warns about unscoped sinks.

## Sink Scoping (B11.5.1)

Custom sinks can be scoped by CWE or category to prevent cross-rule noise:

```yaml
framework_extensions:
  spring:
    custom_sinks:
      - function: "LegacySql.run"
        cwe: "CWE-89"           # only attaches to SQLi rules
      - function: "InternalHttp.fetch"
        category: "ssrf"        # only attaches to SSRF rules
```

A sink with no CWE/category attaches to ALL taint rules (backward compatible, but noisy). `patchflow rules validate` warns about unscoped sinks.

## Source Scoping (B11.5.2)

Custom sources can be scoped by category:

```yaml
framework_extensions:
  spring:
    custom_sources:
      - annotation: "@TenantInput"
        categories: [sql_injection, path_traversal]
```

A source with no categories attaches to ALL rules (backward compatible).

## Taint Safe Pattern Suppression (B11.5.3)

Safe patterns now suppress taint-mode findings when the pattern matches in the same function:

```yaml
framework_extensions:
  spring:
    safe_patterns:
      - pattern: "TenantAuth.requireOwner"
        reason: "Ownership validation by internal auth helper"
```

If `TenantAuth.requireOwner()` appears in the same function as a taint finding, the finding is suppressed. This works for both pattern/template and taint-mode rules.

## Validation (B11.5.5)

`patchflow rules validate` catches noisy extension mistakes:

```text
✓ 0 rules, 1 framework overrides, and 1 framework extensions validated successfully
  ⚠ framework_extensions.spring.custom_sinks[0] UnscopedSink.run: no cwe or category — will attach to ALL taint rules
  ⚠ framework_extensions.spring.custom_sources[1]: duplicate source "@TenantInput"
  ⚠ framework_extensions.spring.custom_sanitizers[1]: duplicate sanitizer
```

Warnings:
- Sink with no CWE/category (will attach to all rules)
- Duplicate source/sink/sanitizer
- Unknown framework name
- CWE format doesn't match `CWE-NNN`

Errors:
- Missing required fields (func, annotation, pattern)
- Invalid regex patterns
