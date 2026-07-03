# Express Framework Pack

## Overview

The Express pack detects security vulnerabilities in JavaScript and
TypeScript Node.js applications built with Express. It uses pattern matching
for direct source-to-sink detection via `argContainsSource()` and taint
tracking for multi-line data flows.

**Pack name:** `express`  
**Language:** JavaScript  
**File extensions:** `.js`, `.mjs`, `.cjs`, `.ts`  
**Maturity:** Beta (pattern rules), Experimental (taint rules)

## Framework Detection

The Express pack activates when any of the following signals are detected
(MinSignals: 1):

| Signal | Location | Contains |
|--------|----------|----------|
| `express` | package.json | `express` |

## Sources

Express request object properties are modeled as taint sources. All sources
use `IsSubscript: true` to match both dot notation (`req.query`) and bracket
notation (`req['query']`):

| Source | IsSubscript | Description |
|--------|-------------|-------------|
| `req.query` | true | URL query parameters |
| `req.body` | true | Request body (parsed by middleware) |
| `req.params` | true | Route path parameters |
| `req.headers` | true | Request headers |
| `req.cookies` | true | Request cookies |
| `req.get` | true | Request header getter method |

## Sinks

| Sink | ArgIndex | CWE |
|------|----------|-----|
| `query` | 0 | CWE-89 (SQLi) |
| `execute` | 0 | CWE-89 (SQLi) |
| `eval` | 0 | CWE-94 (Code injection) |
| `exec` | 0 | CWE-78 (Command injection) |
| `redirect` | 0 | CWE-601 (Open redirect) |
| `sendFile` | 0 | CWE-22 (Path traversal) |
| `render` | 0 | CWE-79 (XSS) |

## Sanitizers

| Sanitizer | Description |
|-----------|-------------|
| `PreparedStatement` | Parameterized SQL query |
| `mysql.escape` | MySQL string escaping |
| `pool.escape` | Connection pool escaping |
| `sqlstring.escape` | sqlstring library escaping |
| `encodeURIComponent` | URL component encoding |
| `escapeHtml` | HTML escaping |
| `validator.escape` | validator.js escaping |
| `path.resolve` | Path normalization |
| `path.join` | Safe path join |

## Rules

### PF-EXPRESS-SQLI-001 — Express SQL injection: request data → raw SQL

| Field | Value |
|-------|-------|
| CWE | CWE-89 |
| Severity | High |
| Confidence | Medium |
| Maturity | Beta |
| MatchMode | Pattern |
| Default mode | Inform (beta maturity) |

**Detects:** Express request data (`req.query`, `req.body`, `req.params`,
`req.headers`, `req.cookies`, `req.get`) flowing into `query()`, `execute()`,
or `executeUpdate()` calls via `argContainsSource()`. The rule checks whether
any argument to the sink contains a source pattern.

**Vulnerable:**
```javascript
app.get('/search', (req, res) => {
  const sql = "SELECT * FROM products WHERE name LIKE '%" + req.query.q + "%'";
  db.query(sql, (err, results) => {
    res.json(results);
  });
});
```

**Safe:**
```javascript
app.get('/search', (req, res) => {
  const sql = 'SELECT * FROM products WHERE name LIKE ?';
  db.query(sql, ['%' + req.query.q + '%'], (err, results) => {
    res.json(results);
  });
});
```

### PF-EXPRESS-XSS-001 — Express XSS: request data → template render

| Field | Value |
|-------|-------|
| CWE | CWE-79 |
| Severity | Medium |
| Confidence | Medium |
| Maturity | Beta |
| MatchMode | Pattern |
| Default mode | Inform |

**Detects:** Express request data flowing into `res.render()` or
`res.send()` without HTML escaping.

**Vulnerable:**
```javascript
app.get('/profile', (req, res) => {
  res.render('profile', { name: req.query.name });
});
```

**Safe:**
```javascript
app.get('/profile', (req, res) => {
  res.render('profile', { name: escapeHtml(req.query.name) });
});
```

### PF-EXPRESS-CMDI-001 — Express command injection: request data → exec

| Field | Value |
|-------|-------|
| CWE | CWE-78 |
| Severity | High |
| Confidence | Medium |
| Maturity | Beta |
| MatchMode | Pattern |
| Default mode | Inform |

**Detects:** Express request data flowing into `child_process.exec()` or
`eval()` calls.

**Vulnerable:**
```javascript
const { exec } = require('child_process');
app.get('/ping', (req, res) => {
  exec('ping -c 4 ' + req.query.host, (err, stdout) => {
    res.send(stdout);
  });
});
```

**Safe:**
```javascript
const { execFile } = require('child_process');
app.get('/ping', (req, res) => {
  execFile('ping', ['-c', '4', req.query.host], (err, stdout) => {
    res.send(stdout);
  });
});
```

### PF-EXPRESS-REDIRECT-001 — Express open redirect: request data → redirect

| Field | Value |
|-------|-------|
| CWE | CWE-601 |
| Severity | Medium |
| Confidence | Medium |
| Maturity | Beta |
| MatchMode | Pattern |
| Default mode | Inform |

**Detects:** Express request data flowing into `res.redirect()` without URL
validation.

**Vulnerable:**
```javascript
app.get('/login', (req, res) => {
  res.redirect(req.query.returnUrl);
});
```

**Safe:**
```javascript
app.get('/login', (req, res) => {
  const returnUrl = req.query.returnUrl;
  if (returnUrl && returnUrl.startsWith('/') && !returnUrl.startsWith('//')) {
    res.redirect(returnUrl);
  } else {
    res.redirect('/');
  }
});
```

### PF-EXPRESS-PATH-001 — Express path traversal: request data → sendFile

| Field | Value |
|-------|-------|
| CWE | CWE-22 |
| Severity | High |
| Confidence | Medium |
| Maturity | Beta |
| MatchMode | Pattern |
| Default mode | Inform |

**Detects:** Express request data flowing into `res.sendFile()` without path
normalization.

**Vulnerable:**
```javascript
app.get('/files', (req, res) => {
  res.sendFile('/var/uploads/' + req.params.filename);
});
```

**Safe:**
```javascript
const path = require('path');
app.get('/files', (req, res) => {
  const filePath = path.resolve('/var/uploads', req.params.filename);
  if (!filePath.startsWith('/var/uploads/')) {
    return res.status(403).send('Forbidden');
  }
  res.sendFile(filePath);
});
```

## Vulnerable Examples

### SQL injection via req.body

```javascript
app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  const sql = "SELECT * FROM users WHERE username = '" + username +
    "' AND password = '" + password + "'";
  db.query(sql, (err, user) => {
    if (user) res.json({ success: true });
    else res.status(401).json({ error: 'Invalid credentials' });
  });
});
```

### Code injection via eval

```javascript
app.post('/calculate', (req, res) => {
  const result = eval(req.body.expression);
  res.json({ result });
});
```

## Safe Examples

### Parameterized query with mysql2

```javascript
app.post('/login', (req, res) => {
  const sql = 'SELECT * FROM users WHERE username = ? AND password = ?';
  db.query(sql, [req.body.username, req.body.password], (err, user) => {
    if (user) res.json({ success: true });
    else res.status(401).json({ error: 'Invalid credentials' });
  });
});
```

### Safe redirect with allowlist

```javascript
const ALLOWED_REDIRECTS = ['/dashboard', '/profile', '/home'];
app.get('/login', (req, res) => {
  const returnUrl = req.query.returnUrl;
  if (ALLOWED_REDIRECTS.includes(returnUrl)) {
    res.redirect(returnUrl);
  } else {
    res.redirect('/');
  }
});
```

## Overriding Rules

In `.patchflow/rules.yaml`:

```yaml
rule_modes:
  PF-EXPRESS-SQLI-001: block       # promote to blocking
  PF-EXPRESS-CMDI-001: block       # block command injection
  PF-EXPRESS-REDIRECT-001: off     # disable open redirect heuristic
  PF-EXPRESS-PATH-001: block       # block path traversal
```

Or via CLI:

```bash
patchflow scan run --rules-config .patchflow/rules.yaml
```

## Known Limitations

- Pattern rules are line-oriented — they detect source and sink on the same
  line via `argContainsSource()`. Multi-line data flows (e.g., source
  assigned to a variable on one line, sink called on another) require taint
  tracking rules.
- TypeScript files are normalized to `javascript` for taint rule matching.
  TypeScript-specific constructs (type annotations, interfaces) are stripped
  during normalization but complex type narrowing may affect source detection.
- The `req.body` source requires body-parsing middleware (`express.json()`,
  `express.urlencoded()`) to be present. The pack does not verify middleware
  configuration; it assumes `req.body` is populated.
- The `req.get` source matches `req.get('header-name')` calls but does not
  distinguish between user-controlled and server-set headers.
- Template rendering via `res.render()` is flagged as an XSS sink, but the
  pack cannot determine whether the template engine auto-escapes output.
  Engines like EJS (`<%= %>`) escape by default while `<%- %>` does not.
