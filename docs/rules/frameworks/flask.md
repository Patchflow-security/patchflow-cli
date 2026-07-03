# Flask Framework Pack

## Overview

The Flask pack detects security vulnerabilities in Flask web applications.
It combines pattern matching (SQLi, SSRF, SSTI, XSS, path traversal, config)
with taint tracking (request data → SQL/HTTP sinks).

**Pack name:** `flask`  
**Language:** Python  
**File extensions:** `.py`  
**Template extensions:** `.html`, `.jinja`, `.jinja2`  
**Maturity:** Beta (pattern rules), Experimental (taint rules)

## Framework Detection

| Signal | Location | Contains |
|--------|----------|----------|
| Flask | requirements.txt | `flask` |
| Flask | pyproject.toml | `flask` |
| Flask | Pipfile | `flask` |

MinSignals: 2

## Sources

| Source | Subscript | Description |
|--------|-----------|-------------|
| `request.args` | yes | URL query parameters |
| `request.form` | yes | POST form data |
| `request.values` | yes | Combined args + form |
| `request.headers` | yes | HTTP headers |
| `request.cookies` | yes | Cookies |
| `request.json` | yes | JSON body |
| `request.get_json` | no | JSON body (method) |
| `request.files` | yes | Uploaded files |
| `request.data` | yes | Raw request body |

## Sinks

| Sink | ArgIndex | CWE |
|------|----------|-----|
| `cursor.execute` | 0 | CWE-89 |
| `session.execute` | 0 | CWE-89 |
| `db.session.execute` | 0 | CWE-89 |
| `text` | 0 | CWE-89 |
| `execute` | 0 | CWE-89 |
| `requests.get` | 0 | CWE-918 |
| `requests.post` | 0 | CWE-918 |
| `httpx.get` | 0 | CWE-918 |
| `httpx.post` | 0 | CWE-918 |
| `redirect` | 0 | CWE-601 |
| `Markup` | 0 | CWE-79 |
| `render_template_string` | 0 | CWE-94 |
| `send_file` | 0 | CWE-22 |
| `send_from_directory` | 0 | CWE-22 |
| `open` | 0 | CWE-22 |
| `subprocess.run` | 0 | CWE-78 |
| `os.system` | 0 | CWE-78 |

## Sanitizers

| Sanitizer | Description |
|-----------|-------------|
| `escape` | HTML escaping |
| `markupsafe.escape` | MarkupSafe escaping |
| `html.escape` | HTML escaping |
| `url_has_allowed_host_and_scheme` | URL validation |
| `is_safe_url` | URL validation |
| `execute(..., {params})` | Parameterized SQL (regex) |

## Rules

### Pattern Rules (Beta)

| Rule ID | Title | CWE | Severity | Default |
|---------|-------|-----|----------|---------|
| PF-FLASK-SQLI-001 | execute with request data | CWE-89 | High | Inform |
| PF-FLASK-SSRF-001 | outbound request with request URL | CWE-918 | High | Inform |
| PF-FLASK-REDIRECT-001 | redirect with request input | CWE-601 | Medium | Inform |
| PF-FLASK-XSS-001 | Jinja safe filter | CWE-79 | High | Inform |
| PF-FLASK-SSTI-001 | render_template_string with variable | CWE-94 | High | Inform |
| PF-FLASK-PATH-001 | send_file/open with request input | CWE-22 | High | Inform |
| PF-FLASK-CONFIG-001 | debug=True or hardcoded SECRET_KEY | CWE-489 | Medium | Inform |

### Taint Rules (Experimental)

| Rule ID | Title | CWE | Severity | Default |
|---------|-------|-----|----------|---------|
| PF-FLASK-SQLI-002 | request → text()/execute (taint) | CWE-89 | High | Inform |
| PF-FLASK-SSRF-002 | request → requests/httpx (taint) | CWE-918 | High | Inform |

## Vulnerable Examples

### SQL Injection (PF-FLASK-SQLI-001)
```python
@app.route("/users")
def get_user():
    cursor.execute("SELECT * FROM users WHERE id = " + request.args["id"])
```

### SSTI (PF-FLASK-SSTI-001)
```python
@app.route("/greet")
def greet():
    template = "Hello " + request.args["name"]
    return render_template_string(template)
```

### Path Traversal (PF-FLASK-PATH-001)
```python
@app.route("/download")
def download():
    return send_file(request.args["filename"])
```

### Debug Mode (PF-FLASK-CONFIG-001)
```python
app.run(debug=True)  # Never enable in production
SECRET_KEY = "hardcoded-secret"  # Load from environment instead
```

## Safe Examples

### Parameterized SQL
```python
cursor.execute("SELECT * FROM users WHERE id = ?", (request.args["id"],))
```

### SQLAlchemy with bound params
```python
db.session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": id})
```

### Secure file download
```python
from werkzeug.utils import secure_filename
filename = secure_filename(request.args["filename"])
return send_from_directory(UPLOAD_DIR, filename)
```

### Secret from environment
```python
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
```

## Overriding Rules

```yaml
# .patchflow/rules.yaml
rule_modes:
  PF-FLASK-SQLI-001: block
  PF-FLASK-CONFIG-001: block
  PF-FLASK-XSS-001: off  # disable if using a different template engine
```

## Known Limitations

- Pattern rules check single lines. Multi-line SQL injection patterns may
  be missed by PF-FLASK-SQLI-001.
- The SSTI rule triggers on any `render_template_string(variable)` call,
  not just request-controlled variables. Taint tracking (PF-FLASK-SQLI-002)
  provides more precise detection.
- The config rule may flag test files that set `debug=True` for testing.
  Use `Exclusions` or `off` mode for test directories.
