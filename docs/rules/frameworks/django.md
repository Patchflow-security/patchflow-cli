# Django Framework Pack

## Overview

The Django pack detects security vulnerabilities in Python web applications
built with Django. It leverages the built-in Python taint rules (TP-PY001,
TP-PY002, etc.) with Django-specific source modeling for `HttpRequest`
objects. The pack also includes conservative GraphQL resolver detection to
avoid false positives on Django ORM methods.

**Pack name:** `django`  
**Language:** Python  
**File extensions:** `.py`  
**Template extensions:** `.html`, `.jinja`, `.jinja2`  
**Maturity:** Beta (taint rules), Experimental (pattern rules)

## Framework Detection

The Django pack activates when any of the following signals are detected
(MinSignals: 1):

| Signal | Location | Contains |
|--------|----------|----------|
| `manage.py` | `**/manage.py` | — |
| `installed_apps` | settings.py | `installed_apps` |
| `django` | settings.py | `django` |
| `urls.py` | `**/urls.py` | — |

## Sources

Django `HttpRequest` object properties are modeled as taint sources:

| Source | Description |
|--------|-------------|
| `request.GET` | Query parameters (GET) |
| `request.POST` | Form POST data |
| `request.args` | Query arguments (alternative) |
| `request.form` | Form data (alternative) |
| `request.values` | Combined GET/POST values |
| `request.cookies` | Request cookies |
| `request.headers` | Request headers |
| `request.json` | Parsed JSON body |
| `sys.argv` | Command-line arguments |

## Sinks

| Sink | ArgIndex | CWE |
|------|----------|-----|
| `execute` | 0 | CWE-89 (SQLi) |
| `executemany` | 0 | CWE-89 (SQLi) |
| `executescript` | 0 | CWE-89 (SQLi) |
| `text` | 0 | CWE-89 (SQLi) |

## Sanitizers

| Sanitizer | Description |
|-----------|-------------|
| `escape` | Django HTML escaping |
| `markupsafe.escape` | MarkupSafe escaping |
| `html.escape` | Python stdlib HTML escaping |

## Rules

### TP-PY001 — SQL injection: request data → cursor.execute/text

| Field | Value |
|-------|-------|
| CWE | CWE-89 |
| Severity | High |
| Confidence | Medium |
| Maturity | Beta |
| MatchMode | Taint |
| Default mode | Inform (beta maturity) |

**Detects:** Django request data (`request.GET`, `request.POST`,
`request.headers`, `request.cookies`, `request.json`) flowing into
`cursor.execute()`, `executemany()`, `executescript()`, or SQLAlchemy
`text()` calls without parameterization.

**Vulnerable:**
```python
def search_view(request):
    query = request.GET.get('q', '')
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM products WHERE name LIKE '%%%s%%'" % query)
        rows = cursor.fetchall()
    return render(request, 'results.html', {'results': rows})
```

**Safe:**
```python
def search_view(request):
    query = request.GET.get('q', '')
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM products WHERE name LIKE %s", ['%' + query + '%'])
        rows = cursor.fetchall()
    return render(request, 'results.html', {'results': rows})
```

### TP-PY002 — Command injection: request data → subprocess/os.exec

| Field | Value |
|-------|-------|
| CWE | CWE-78 |
| Severity | High |
| Confidence | Medium |
| Maturity | Beta |
| MatchMode | Taint |
| Default mode | Inform |

**Detects:** Django request data flowing into `subprocess.run()`,
`subprocess.call()`, `os.system()`, `os.exec*()` calls without shell
escaping.

**Vulnerable:**
```python
import subprocess
def ping_view(request):
    host = request.GET.get('host', '')
    result = subprocess.run('ping -c 4 ' + host, shell=True, capture_output=True)
    return HttpResponse(result.stdout)
```

**Safe:**
```python
import subprocess
def ping_view(request):
    host = request.GET.get('host', '')
    result = subprocess.run(['ping', '-c', '4', host], capture_output=True)
    return HttpResponse(result.stdout)
```

### TP-PY003 — Path traversal: request data → file operations

| Field | Value |
|-------|-------|
| CWE | CWE-22 |
| Severity | High |
| Confidence | Medium |
| Maturity | Beta |
| MatchMode | Taint |
| Default mode | Inform |

**Detects:** Django request data flowing into `open()`, `send_file()`, or
file path operations without path normalization.

**Vulnerable:**
```python
def download_view(request):
    filename = request.GET.get('file', '')
    return FileResponse(open('/var/uploads/' + filename, 'rb'))
```

**Safe:**
```python
import os
def download_view(request):
    filename = request.GET.get('file', '')
    filepath = os.path.realpath(os.path.join('/var/uploads', filename))
    if not filepath.startswith('/var/uploads/'):
        return HttpResponseForbidden('Forbidden')
    return FileResponse(open(filepath, 'rb'))
```

### TP-PY004 — SSRF: request data → HTTP requests

| Field | Value |
|-------|-------|
| CWE | CWE-918 |
| Severity | High |
| Confidence | Medium |
| Maturity | Beta |
| MatchMode | Taint |
| Default mode | Inform |

**Detects:** Django request data flowing into `requests.get()`,
`requests.post()`, `httpx.get()`, `httpx.post()` calls without URL
validation.

### TP-PY005 — XSS: request data → template output without escaping

| Field | Value |
|-------|-------|
| CWE | CWE-79 |
| Severity | Medium |
| Confidence | Medium |
| Maturity | Beta |
| MatchMode | Taint |
| Default mode | Inform |

**Detects:** Django request data flowing into `HttpResponse()` or
`render()` with `mark_safe()` or `|safe` template filter usage.

## Vulnerable Examples

### SQL injection via request.GET

```python
from django.db import connection
from django.shortcuts import render

def user_view(request):
    user_id = request.GET.get('id', '')
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
        user = cursor.fetchone()
    return render(request, 'user.html', {'user': user})
```

### Command injection via request.POST

```python
import os
def run_task(request):
    if request.method == 'POST':
        task = request.POST.get('task', '')
        os.system('python manage.py ' + task)
    return render(request, 'task.html')
```

## Safe Examples

### Parameterized cursor.execute

```python
from django.db import connection
from django.shortcuts import render

def user_view(request):
    user_id = request.GET.get('id', '')
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])
        user = cursor.fetchone()
    return render(request, 'user.html', {'user': user})
```

### Django ORM with parameterized raw query

```python
from django.shortcuts import render
from myapp.models import Product

def search_view(request):
    query = request.GET.get('q', '')
    products = Product.objects.filter(name__icontains=query)
    return render(request, 'results.html', {'products': products})
```

## Overriding Rules

In `.patchflow/rules.yaml`:

```yaml
rule_modes:
  TP-PY001: block    # block SQL injection findings
  TP-PY002: block    # block command injection findings
  TP-PY003: block    # block path traversal findings
  TP-PY005: off      # disable XSS heuristic
```

Or via CLI:

```bash
patchflow scan run --rules-config .patchflow/rules.yaml
```

## Known Limitations

- Django ORM raw queries via `.raw()` may not be detected. The taint engine
  models `cursor.execute()`, `executemany()`, `executescript()`, and
  `text()` as sinks, but `Model.objects.raw()` is not currently registered
  as a sink.
- The GraphQL resolver detection is conservative to avoid Django ORM false
  positives. Django ORM methods like `resolve_expression_parameter` are NOT
  flagged as GraphQL resolvers. The detection requires an `info` parameter
  in the function signature to identify a true GraphQL resolver.
- The `request.json` source assumes the request body has been parsed as
  JSON (e.g., via `json.loads(request.body)`). The pack does not verify
  that the parsing has occurred.
- Template-level XSS detection (`TP-PY005`) is limited to `mark_safe()` and
  `|safe` filter usage in Python code. Template files (`.html`, `.jinja`,
  `.jinja2`) are not scanned for auto-escaping bypass patterns.
- Multi-line SQL string construction (e.g., building a query across
  multiple lines with `.format()` or f-strings) may be missed if the source
  and sink are on different lines and taint tracking cannot connect them.
