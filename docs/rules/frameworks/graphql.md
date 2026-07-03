# GraphQL Framework Pack

## Overview

The GraphQL pack detects security vulnerabilities in Python GraphQL servers
built with Graphene, Ariadne, Strawberry, or graphql-core. It combines taint
tracking (resolver args → dangerous sinks) with pattern matching (IDOR, DoS
misconfiguration).

**Pack name:** `graphql`  
**Language:** Python  
**File extensions:** `.py`  
**Maturity:** Beta (taint rules), Experimental (DoS rule)

## Framework Detection

The GraphQL pack activates when any of the following signals are detected
(MinSignals: 1):

| Signal | Location | Contains |
|--------|----------|----------|
| `graphene` | requirements.txt | `graphene` |
| `ariadne` | requirements.txt | `ariadne` |
| `strawberry-graphql` | requirements.txt | `strawberry-graphql` |
| `graphql-core` | requirements.txt | `graphql-core` |
| `graphene` | pyproject.toml | `graphene` |
| `ariadne` | pyproject.toml | `ariadne` |
| `strawberry` | pyproject.toml | `strawberry` |
| `.graphql` schema files | `**/*.graphql` | — |
| `schema.graphql` | `**/schema.graphql` | — |

## Sources

GraphQL resolver arguments are modeled as taint sources via
`seedGraphQLResolverParams()` in the taint engine. The function detects:

- Functions named `resolve_*` with an `info` parameter
- Functions named `mutate` with an `info` parameter

Parameters after `root`/`parent`/`self` and `info` are pre-tainted as
user-controlled resolver arguments, including parameters with default values
(e.g., `filter=None`).

Additional source patterns:

| Source | Description |
|--------|-------------|
| `info.context` | GraphQL context object |
| `context.request` | HTTP request from context |
| `info.variable_values` | GraphQL query variables |
| `kwargs` | Generic resolver kwargs |

## Sinks

| Sink | ArgIndex | CWE |
|------|----------|-----|
| `text` | 0 | CWE-89 (SQLi) |
| `execute` | 0 | CWE-89 (SQLi) |
| `session.execute` | 0 | CWE-89 (SQLi) |
| `db.session.execute` | 0 | CWE-89 (SQLi) |
| `requests.get` | 0 | CWE-918 (SSRF) |
| `requests.post` | 0 | CWE-918 (SSRF) |
| `httpx.get` | 0 | CWE-918 (SSRF) |
| `httpx.post` | 0 | CWE-918 (SSRF) |
| `open` | 0 | CWE-22 (Path traversal) |
| `send_file` | 0 | CWE-22 (Path traversal) |
| `send_from_directory` | 0 | CWE-22 (Path traversal) |

## Sanitizers

| Sanitizer | Description |
|-----------|-------------|
| `bindparam` | SQLAlchemy bound parameter |
| `execute(..., {param: value})` | Parameterized execute (regex) |
| `url_has_allowed_host_and_scheme` | URL validation |
| `is_safe_url` | URL validation |
| `secure_filename` | Path sanitization |
| `safe_join` | Safe path join |
| `escape` | HTML escaping |
| `markupsafe.escape` | MarkupSafe escaping |
| `html.escape` | HTML escaping |

## Rules

### PF-GRAPHQL-SQLI-001 — GraphQL SQLi: resolver args → raw SQL

| Field | Value |
|-------|-------|
| CWE | CWE-89 |
| Severity | High |
| Confidence | Medium |
| Maturity | Beta |
| MatchMode | Taint |
| Default mode | Inform (beta maturity) |

**Detects:** GraphQL resolver arguments flowing into SQLAlchemy `text()` or
raw `execute()` calls without parameterization.

**Vulnerable:**
```python
def resolve_pastes(root, info, filter=None):
    result = result.filter(text("title = '%s'" % (filter, filter)))
    return result
```

**Safe:**
```python
def resolve_pastes(root, info, filter=None):
    result = result.filter(text("title = :filter"), {"filter": filter})
    return result
```

### PF-GRAPHQL-SSRF-001 — GraphQL SSRF: resolver args → HTTP request

| Field | Value |
|-------|-------|
| CWE | CWE-918 |
| Severity | High |
| Confidence | Medium |
| Maturity | Beta |
| MatchMode | Taint |
| Default mode | Inform |

**Detects:** Resolver arguments flowing into outbound HTTP requests.

### PF-GRAPHQL-PATH-001 — GraphQL path traversal: resolver args → file ops

| Field | Value |
|-------|-------|
| CWE | CWE-22 |
| Severity | High |
| Confidence | Medium |
| Maturity | Beta |
| MatchMode | Taint |
| Default mode | Inform |

**Detects:** Resolver arguments flowing into file operations (`open`,
`send_file`, `send_from_directory`).

### PF-GRAPHQL-AUTH-001 — GraphQL IDOR: object by id without ownership

| Field | Value |
|-------|-------|
| CWE | CWE-639 |
| Severity | Medium |
| Confidence | Low |
| Maturity | Beta |
| MatchMode | Pattern |
| Default mode | Inform |

**Detects:** Resolvers that fetch objects by `id` without ownership or
authorization checks. This is a heuristic rule — it looks for
`filter_by(id=id)` or similar patterns without `current_user`, `owner`, or
auth-related terms on the same line.

**Safe pattern suppression:** Lines containing `current_user`, `owner`,
`user_id`, `auth`, `permission`, or `authorize` suppress the finding.

### PF-GRAPHQL-DOS-001 — GraphQL DoS: missing depth/complexity limits

| Field | Value |
|-------|-------|
| CWE | CWE-400 |
| Severity | Medium |
| Confidence | Low |
| Maturity | Experimental |
| MatchMode | Pattern |
| Default mode | Inform |

**Detects:** `Schema()` or `build_schema()` calls without depth limit or
complexity analysis configuration.

**Safe pattern suppression:** Lines containing `depth_limit`, `complexity`,
`cost_analysis`, or `validation_rules` suppress the finding.

## Overriding Rules

In `.patchflow/rules.yaml`:

```yaml
rule_modes:
  PF-GRAPHQL-SQLI-001: block    # promote to blocking
  PF-GRAPHQL-AUTH-001: off      # disable noisy IDOR heuristic
  PF-GRAPHQL-DOS-001: off       # disable experimental DoS rule
```

Or via CLI:

```bash
patchflow scan run --rules-config .patchflow/rules.yaml
```

## Known Limitations

- IDOR detection (PF-GRAPHQL-AUTH-001) is heuristic and may produce false
  positives. It looks for `filter_by(id=id)` patterns without auth-related
  terms on the same line. Cross-line ownership checks are not tracked.
- DoS detection (PF-GRAPHQL-DOS-001) only checks the schema creation line.
  Depth limits configured elsewhere (middleware, plugins) may not be detected.
- Taint rules require the GraphQL resolver to have an `info` parameter. This
  is the standard GraphQL convention but may miss non-standard resolver
  implementations.
- The `text()` sink does not distinguish between parameterized and
  non-parameterized usage at the taint engine level. SafePatterns provide
  line-level suppression for `:param` placeholders and `bindparam()`.
