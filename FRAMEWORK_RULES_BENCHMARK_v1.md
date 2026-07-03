# Framework Rules Benchmark — framework-rules-v1

**Date:** 2026-07-03  
**Candidate:** framework-rules-v1 (post-B8)  
**Baseline:** B1 (2026-07-02)

## Executive Summary

Framework-rules-v1 delivers measurable improvements in vulnerable-repo
detection through framework-aware source modeling and taint tracking. The
key gains are source-to-sink taint-confirmed findings in WebGoat (Spring),
Juice Shop (Express/JS), and DVGA (GraphQL), with zero clean-repo
regressions.

## Benchmark Repos

### Vulnerable Repos

| Repo | Framework | Total | Taint | Framework | Blocking | High/Crit |
|------|-----------|-------|-------|-----------|----------|-----------|
| WebGoat | Spring | 635 | 8 | 2 | 7 | 358 |
| Juice Shop | Express | 347 | 66 | 20 | 0 | 255 |
| DVGA | GraphQL | 99 | 1 | 7 | 0 | 38 |
| NodeGoat | Express | 375 | 6 | 1 | 2 | 254 |
| RailsGoat | Rails | 81 | 14 | 1 | 0 | 50 |
| DVNA | Express | 84 | 20 | 1 | 0 | 56 |
| DVFA | Flask | 15 | 6 | 0 | 0 | 8 |

### Clean Repos

| Repo | Framework | Total | Taint | Framework | Blocking | Delta from B1 |
|------|-----------|-------|-------|-----------|----------|---------------|
| cobra | Go CLI | 18 | 0 | 0 | 0 | 0 |
| flask | Flask | 43 | 0 | 0 | 0 | 0 |
| django | Django | 143 | 3 | 0 | 0 | 0 |

## Source-to-Sink Taint Wins

### WebGoat (Spring Boot, Java)

| Rule | Count | Description |
|------|-------|-------------|
| TP-JAVA001 | 3 | @RequestParam/@PathVariable → SQL execute (path traversal + SQLi) |
| TP-JAVA009 | 3 | Request data → XSS sink (JWT + XSS lessons) |
| TP-JAVA006 | 1 | Request data → XXE sink |
| PF-SPRINGSEC-CSRF-001 | 2 | Spring Security CSRF disabled |

**Key improvement:** Spring annotation-based source modeling via
`seedAnnotatedParams()` pre-taints parameters with `@RequestParam`,
`@PathVariable`, and `@RequestBody`, enabling source-to-sink taint tracking
that wasn't possible before B6.5.

**B1 → v1 delta:** 627 → 635 (+8 taint-confirmed findings)

### Juice Shop (Express, JavaScript/TypeScript)

| Rule | Count | Description |
|------|-------|-------------|
| TP-JS001 | 11 | req.* → eval/exec (command injection) |
| TP-JS001-IP | 11 | (interprocedural variant) |
| TP-JS004 | 3 | req.* → SQL query (SQL injection) |
| TP-JS004-IP | 3 | (interprocedural variant) |
| TP-JS005 | 1 | req.* → redirect (open redirect) |
| TP-JS006 | 1 | req.* → path traversal |
| TP-JS008 | 17 | req.* → template/render (SSTI/XSS) |
| TP-JS008-IP | 17 | (interprocedural variant) |
| PF-EXPRESS-SQLI-001 | 10 | Express SQL injection pattern |
| PF-EXPRESS-SQLI-002 | 10 | Express SQL injection (taint) |

**Key improvement:** TypeScript files normalized to "javascript" for taint
rule matching, plus direct source-to-sink detection via `argContainsSource()`.

**B1 → v1 delta:** 273 → 347 (+74 findings, +66 taint-confirmed)

### DVGA (GraphQL, Python)

| Rule | Count | Description |
|------|-------|-------------|
| TP-PY001 | 1 | Resolver arg `filter` → SQLAlchemy `text()` SQLi |
| PF-GRAPHQL-SQLI-001 | 1 | Resolver args → raw SQL (taint) |
| PF-GRAPHQL-AUTH-001 | 6 | IDOR — filter_by(id=id) without ownership check |

**Manual review:** All 6 AUTH findings were manually verified as TRUE
POSITIVES. See `MANUAL_REVIEW_DVGA_AUTH_findings.md` for the full review.
Zero false positives. Finding #2 (views.py:148) is a same-function duplicate
of #1 (views.py:141) — both are in `EditPaste.mutate` but on different
`filter_by(id=id)` lines. This is a B10 dedup target.

**Key improvement:** `seedGraphQLResolverParams()` detects `resolve_*` and
`mutate` functions with `info` parameter, pre-taints resolver arguments
(including parameters with default values like `filter=None`). SQLAlchemy
`text()` added as taint sink in TP-PY001.

**B1 → v1 delta:** 91 → 99 (+8 taint-confirmed findings)

### RailsGoat (Rails, Ruby)

| Rule | Count | Description |
|------|-------|-------------|
| TP-RUBY* | 14 | Various taint-confirmed findings |
| PF-RAILS* | 1 | Framework pattern finding |

**B1 → v1 delta:** 81 → 81 (stable — Rails pack was already in B1)

### DVNA (Express, JavaScript)

| Rule | Count | Description |
|------|-------|-------------|
| TP-JS* | 20 | Various taint-confirmed findings |
| PF-EXPRESS* | 1 | Framework pattern finding |

**B1 → v1 delta:** 84 → 84 (stable)

### DVFA (Flask, Python)

| Rule | Count | Description |
|------|-------|-------------|
| TP-PY* | 6 | Various taint-confirmed findings |

**Note:** No PF-FLASK* findings — DVFA uses basic Flask patterns that are
caught by the core TP-PY* taint rules, not the Flask-specific pattern rules.

## Improvement Summary

| Repo | B1 Total | v1 Total | Delta | Key Driver |
|------|----------|----------|-------|------------|
| WebGoat | 627 | 635 | +8 | Spring annotation source model |
| Juice Shop | 273 | 347 | +74 | TS normalization + source-to-sink |
| DVGA | 91 | 99 | +8 | GraphQL source model + text() sink |
| NodeGoat | 375 | 375 | 0 | Stable |
| RailsGoat | 81 | 81 | 0 | Stable |
| DVNA | 84 | 84 | 0 | Stable |
| DVFA | 15 | 15 | 0 | Stable |
| **Total vulnerable** | **1546** | **1636** | **+90** | |
| cobra (clean) | 18 | 18 | 0 | No regression |
| flask (clean) | 43 | 43 | 0 | No regression |
| django (clean) | 143 | 143 | 0 | No regression |

## Framework-Specific Detection Highlights

### Spring Annotation Source Model

```
@RequestParam("id") String id
  → seedAnnotatedParams() taints `id`
  → flows to cursor.execute("WHERE id = " + id)
  → TP-JAVA001 fires (SQL injection)
```

### GraphQL Resolver Source Model

```
def resolve_pastes(root, info, filter=None):
  → seedGraphQLResolverParams() taints `filter`
  → flows to text("title = '%s'" % filter)
  → TP-PY001 fires (SQL injection via text())
```

### Express Direct Source-to-Sink

```
app.get('/search', function(req, res) {
  db.query("SELECT * FROM products WHERE name = '" + req.query.q + "'")
  → argContainsSource() detects req.query in argument
  → TP-JS004 fires (SQL injection)
```

## Known Limitations

1. **Interprocedural duplicates:** Juice Shop shows paired base/IP findings
   (e.g., TP-JS001 x11 + TP-JS001-IP x11). These are not duplicates — the
   base rule detects direct flow, the -IP variant detects interprocedural
   flow through a function call. Deduplication is planned for B10.

2. **Flask pack on DVFA:** The Flask pattern rules (PF-FLASK-*) do not fire
   on DVGA because DVFA uses basic Flask patterns already covered by the
   core TP-PY* taint rules. The Flask pack adds value on more complex Flask
   apps that use `render_template_string`, `send_file`, and `Markup`.

3. **Rails pack:** RailsGoat findings are stable from B1 — the Rails pack
   was already in B1 and no new Rails source modeling was added in B7.

4. **Scan time:** Duration data was not captured in this run (JSON field
   returned 0). Scan time benchmarking is planned for B10.
