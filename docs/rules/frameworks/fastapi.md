# FastAPI Framework Pack

## Overview

The FastAPI pack detects security vulnerabilities in FastAPI applications.
It covers SQL injection, SSRF, open redirect, command injection, path
traversal, template XSS, and missing authentication.

**Pack name:** `fastapi`  
**Language:** Python  
**File extensions:** `.py`  
**Template extensions:** `.jinja`, `.jinja2`, `.html`  
**Maturity:** Experimental

## Framework Detection

| Signal | Location | Contains |
|--------|----------|----------|
| FastAPI | requirements.txt | `fastapi` |
| FastAPI | pyproject.toml | `fastapi` |
| FastAPI | Pipfile | `fastapi` |

MinSignals: 2

## Sources

| Source | Subscript | Description |
|--------|-----------|-------------|
| `request.query_params` | yes | URL query parameters |
| `request.path_params` | yes | Path parameters |
| `request.headers` | yes | HTTP headers |
| `request.cookies` | yes | Cookies |
| `request.json` | no | JSON body |
| `request.form` | no | Form data |
| `Query` | no | FastAPI Query() parameter |
| `Path` | no | FastAPI Path() parameter |
| `Header` | no | FastAPI Header() parameter |
| `Cookie` | no | FastAPI Cookie() parameter |
| `Body` | no | FastAPI Body() parameter |

## Sinks

| Sink | ArgIndex | CWE |
|------|----------|-----|
| `execute` | 0 | CWE-89 |
| `executemany` | 0 | CWE-89 |
| `text` | 0 | CWE-89 |
| `session.execute` | 0 | CWE-89 |
| `requests.get` | 0 | CWE-918 |
| `requests.post` | 0 | CWE-918 |
| `httpx.get` | 0 | CWE-918 |
| `httpx.post` | 0 | CWE-918 |
| `RedirectResponse` | 0 | CWE-601 |
| `subprocess.run` | 0 | CWE-78 |
| `subprocess.Popen` | 0 | CWE-78 |
| `subprocess.call` | 0 | CWE-78 |
| `subprocess.check_output` | 0 | CWE-78 |
| `FileResponse` | 0 | CWE-22 |
| `open` | 0 | CWE-22 |

## Rules

### Pattern Rules

| Rule ID | Title | CWE | Severity | Default |
|---------|-------|-----|----------|---------|
| PF-FASTAPI-SQLI-001 | execute with interpolated data | CWE-89 | High | Inform |
| PF-FASTAPI-SSRF-001 | outbound HTTP with request URL | CWE-918 | High | Inform |
| PF-FASTAPI-REDIRECT-001 | RedirectResponse with request input | CWE-601 | Medium | Inform |
| PF-FASTAPI-CMDI-001 | subprocess with request data | CWE-78 | Critical | Inform |
| PF-FASTAPI-PATH-001 | FileResponse/open with request input | CWE-22 | High | Inform |
| PF-FASTAPI-XSS-001 | Jinja safe filter | CWE-79 | High | Inform |
| PF-FASTAPI-AUTH-001 | sensitive endpoint missing Depends(auth) | CWE-862 | Medium | Inform |

### Taint Rules

| Rule ID | Title | CWE | Severity | Default |
|---------|-------|-----|----------|---------|
| PF-FASTAPI-SQLI-002 | request → execute/text() (taint) | CWE-89 | High | Inform |
| PF-FASTAPI-REDIRECT-002 | request → RedirectResponse (taint) | CWE-601 | Medium | Inform |

## Vulnerable Examples

### SQL Injection
```python
@app.get("/users/{user_id}")
def get_user(user_id: str = Path(...)):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

### Command Injection
```python
@app.post("/run")
def run_cmd(cmd: str = Body(...)):
    subprocess.run(cmd, shell=True)
```

### Missing Auth on Sensitive Endpoint
```python
@app.delete("/admin/users/{user_id}")
def delete_user(user_id: str):
    # No Depends(get_current_user) — anyone can delete
    ...
```

## Safe Examples

### Parameterized SQL
```python
@app.get("/users/{user_id}")
def get_user(user_id: str = Path(...)):
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

### Auth via Depends
```python
@app.delete("/admin/users/{user_id}")
def delete_user(user_id: str, user: User = Depends(get_current_admin)):
    ...
```

## Overriding Rules

```yaml
rule_modes:
  PF-FASTAPI-CMDI-001: block       # command injection should block
  PF-FASTAPI-AUTH-001: off         # auth is handled by gateway/middleware
```

## Known Limitations

- The AUTH rule (PF-FASTAPI-AUTH-001) is heuristic. It checks for
  `Depends()`, `current_user`, or auth-related terms on the decorator line.
  Auth configured via router-level dependencies or middleware may not be
  detected. Keep this rule as `inform` unless you have a simple per-endpoint
  auth model.
- FastAPI parameter sources (`Query()`, `Path()`, `Body()`) are modeled as
  taint sources, but the taint engine may not track all parameter
  extraction patterns (e.g., `*args` unpacking).
- All rules are Experimental maturity — they fire as `inform` by default and
  do not block CI.
