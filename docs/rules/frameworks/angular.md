# Angular Framework Pack

## Overview

The Angular pack detects security vulnerabilities in TypeScript Angular
applications. It combines pattern matching (dangerous API usage with route
data) with taint tracking (route/form data → DOM sinks and navigation).

**Pack name:** `angular`  
**Language:** TypeScript  
**File extensions:** `.ts`  
**Template extensions:** `.html`  
**Maturity:** Beta (pattern rules), Experimental (taint rules)

## Framework Detection

The Angular pack activates when any of the following signals are detected
(MinSignals: 1):

| Signal | Location | Contains |
|--------|----------|----------|
| `@angular/core` | package.json | `@angular/core` |
| `angular.json` | `**/angular.json` | — |

## Sources

Angular route, form, and DOM sources are modeled as taint sources. The pack
includes 25 source patterns matching real Angular code:

| Source | Description |
|--------|-------------|
| `route.queryParams` | Observable of query parameters |
| `route.params` | Observable of route parameters |
| `route.paramMap` | Observable of parameter map |
| `route.snapshot.paramMap` | Snapshot of parameter map |
| `route.snapshot.queryParams` | Snapshot of query parameters |
| `route.snapshot.params` | Snapshot of route parameters |
| `route.data` | Route resolved data |
| `route.fragment` | Route fragment |
| `FormControl.value` | Reactive form control value |
| `FormGroup.value` | Reactive form group value |
| `http.get` | HTTP GET response |
| `http.post` | HTTP POST response |
| `@Input` | Component input property |
| `ElementRef.nativeElement` | Direct DOM element reference |

## Sinks

| Sink | ArgIndex | CWE |
|------|----------|-----|
| `bypassSecurityTrustHtml` | 0 | CWE-79 (XSS) |
| `bypassSecurityTrustUrl` | 0 | CWE-79 (XSS) |
| `bypassSecurityTrustResourceUrl` | 0 | CWE-79 (XSS) |
| `bypassSecurityTrustScript` | 0 | CWE-79 (XSS) |
| `innerHTML` | 0 | CWE-79 (XSS) |
| `nativeElement.innerHTML` | 0 | CWE-79 (XSS) |
| `insertAdjacentHTML` | 0 | CWE-79 (XSS) |
| `navigateByUrl` | 0 | CWE-601 (Open redirect) |
| `navigate` | 0 | CWE-601 (Open redirect) |
| `window.location` | 0 | CWE-601 (Open redirect) |
| `document.location` | 0 | CWE-601 (Open redirect) |
| `createComponent` | 0 | CWE-79 (XSS) |

## Sanitizers

| Sanitizer | Description |
|-----------|-------------|
| `DomSanitizer.sanitize` | Angular built-in sanitization |
| `sanitizer.sanitize` | Angular sanitizer instance |
| `DOMPurify.sanitize` | DOMPurify HTML sanitization |
| `sanitizeHtml` | Generic HTML sanitization |
| `encodeURIComponent` | URL component encoding |
| `isSafeUrl` | URL validation |
| `validateUrl` | URL validation |

## Rules

### PF-ANGULAR-XSS-001 — Angular XSS: bypassSecurityTrust with route data

| Field | Value |
|-------|-------|
| CWE | CWE-79 |
| Severity | High |
| Confidence | Medium |
| Maturity | Beta |
| MatchMode | Pattern |
| Default mode | Inform (beta maturity) |

**Detects:** `bypassSecurityTrustHtml`, `bypassSecurityTrustUrl`,
`bypassSecurityTrustResourceUrl`, or `bypassSecurityTrustScript` calls on the
same line as route data sources (`route.snapshot.queryParams`,
`route.snapshot.params`, `route.snapshot.paramMap`, `route.data`,
`route.fragment`, `route.queryParams`, `route.params`, `route.paramMap`).

**Vulnerable:**
```typescript
constructor(private sanitizer: DomSanitizer, private route: ActivatedRoute) {
  this.html = this.sanitizer.bypassSecurityTrustHtml(this.route.snapshot.queryParams['html']);
}
```

**Safe:**
```typescript
constructor(private sanitizer: DomSanitizer) {
  // Angular auto-sanitizes [innerHTML] bindings; no bypass needed
  this.safeHtml = userInput;
}
```

### PF-ANGULAR-XSS-002 — Angular XSS: innerHTML binding in template

| Field | Value |
|-------|-------|
| CWE | CWE-79 |
| Severity | Medium |
| Confidence | Medium |
| Maturity | Beta |
| MatchMode | Template |
| Default mode | Inform |

**Detects:** `[innerHTML]` bindings in Angular HTML templates that bind to
component properties not passed through `bypassSecurityTrustHtml` or a
sanitizer. Template-level rule scans `.html` template files.

**Vulnerable:**
```html
<!-- component template -->
<div [innerHTML]="userContent"></div>
```

**Safe:**
```html
<!-- Angular sanitizes [innerHTML] by default; only flag if bypass is used -->
<div [innerHTML]="sanitizedContent"></div>
```

### PF-ANGULAR-REDIRECT-001 — Angular open redirect: router navigation with route input

| Field | Value |
|-------|-------|
| CWE | CWE-601 |
| Severity | Medium |
| Confidence | Medium |
| Maturity | Beta |
| MatchMode | Pattern |
| Default mode | Inform |

**Detects:** `router.navigateByUrl()` or `router.navigate()` calls on the
same line as route data sources (`route.snapshot.queryParams`,
`route.snapshot.params`, `route.data`, `route.fragment`, etc.).

**Vulnerable:**
```typescript
constructor(private router: Router, private route: ActivatedRoute) {
  this.router.navigateByUrl(this.route.snapshot.queryParams['returnUrl']);
}
```

**Safe:**
```typescript
constructor(private router: Router, private route: ActivatedRoute) {
  const returnUrl = this.route.snapshot.queryParams['returnUrl'];
  if (returnUrl && returnUrl.startsWith('/') && !returnUrl.startsWith('//')) {
    this.router.navigateByUrl(returnUrl);
  }
}
```

### PF-ANGULAR-XSS-003 — Angular XSS: route/form data → bypassSecurityTrust/innerHTML (taint)

| Field | Value |
|-------|-------|
| CWE | CWE-79 |
| Severity | High |
| Confidence | Medium |
| Maturity | Experimental |
| MatchMode | Taint |
| Default mode | Inform |

**Detects:** Route data, form control values, or `@Input` properties flowing
into `bypassSecurityTrustHtml`, `bypassSecurityTrustUrl`,
`bypassSecurityTrustResourceUrl`, `bypassSecurityTrustScript`, `innerHTML`,
`nativeElement.innerHTML`, or `insertAdjacentHTML` via taint tracking.

**Vulnerable:**
```typescript
@Component({ template: '<div [innerHTML]="trustedHtml"></div>' })
export class UnsafeComponent {
  trustedHtml: SafeHtml;
  constructor(private sanitizer: DomSanitizer, private route: ActivatedRoute) {
    this.route.queryParams.subscribe(params => {
      this.trustedHtml = this.sanitizer.bypassSecurityTrustHtml(params['content']);
    });
  }
}
```

**Safe:**
```typescript
@Component({ template: '<div [innerHTML]="content"></div>' })
export class SafeComponent implements OnInit {
  content: string;
  constructor(private route: ActivatedRoute) {
    this.route.queryParams.subscribe(params => {
      this.content = params['content'] || ''; // Angular auto-sanitizes
    });
  }
}
```

### PF-ANGULAR-REDIRECT-002 — Angular open redirect: route data → navigation (taint)

| Field | Value |
|-------|-------|
| CWE | CWE-601 |
| Severity | Medium |
| Confidence | Medium |
| Maturity | Experimental |
| MatchMode | Taint |
| Default mode | Inform |

**Detects:** Route data flowing into `router.navigateByUrl()`,
`router.navigate()`, `window.location`, or `document.location` via taint
tracking across multiple lines.

**Vulnerable:**
```typescript
export class RedirectComponent implements OnInit {
  constructor(private router: Router, private route: ActivatedRoute) {}

  ngOnInit() {
    this.route.queryParams.subscribe(params => {
      const url = params['redirect'];
      this.router.navigateByUrl(url);
    });
  }
}
```

**Safe:**
```typescript
export class RedirectComponent implements OnInit {
  constructor(private router: Router, private route: ActivatedRoute) {}

  ngOnInit() {
    this.route.queryParams.subscribe(params => {
      const url = params['redirect'];
      if (url && url.startsWith('/') && !url.startsWith('//')) {
        this.router.navigateByUrl(url);
      }
    });
  }
}
```

## Vulnerable Examples

### bypassSecurityTrustHtml with snapshot data

```typescript
export class ProfileComponent {
  bio: SafeHtml;
  constructor(private sanitizer: DomSanitizer, private route: ActivatedRoute) {
    this.bio = this.sanitizer.bypassSecurityTrustHtml(
      this.route.snapshot.paramMap.get('bio')
    );
  }
}
```

### Direct DOM manipulation with ElementRef

```typescript
export class BannerComponent implements AfterViewInit {
  @ViewChild('banner') banner: ElementRef;
  constructor(private route: ActivatedRoute) {}

  ngAfterViewInit() {
    this.banner.nativeElement.innerHTML = this.route.snapshot.queryParams['content'];
  }
}
```

## Safe Examples

### Angular auto-sanitization (no bypass)

```typescript
export class ProfileComponent {
  bio: string;
  constructor(private route: ActivatedRoute) {
    this.bio = this.route.snapshot.paramMap.get('bio') || '';
    // Template: <div [innerHTML]="bio"></div>
    // Angular sanitizes [innerHTML] bindings automatically
  }
}
```

### Explicit sanitization with DOMPurify

```typescript
export class ProfileComponent {
  bio: string;
  constructor(private route: ActivatedRoute) {
    const raw = this.route.snapshot.paramMap.get('bio') || '';
    this.bio = DOMPurify.sanitize(raw);
  }
}
```

## Overriding Rules

In `.patchflow/rules.yaml`:

```yaml
rule_modes:
  PF-ANGULAR-XSS-001: block         # promote to blocking
  PF-ANGULAR-XSS-002: off           # disable template-level innerHTML rule
  PF-ANGULAR-XSS-003: off           # disable experimental taint rule
  PF-ANGULAR-REDIRECT-001: block    # promote to blocking
  PF-ANGULAR-REDIRECT-002: off      # disable experimental taint rule
```

Or via CLI:

```bash
patchflow scan run --rules-config .patchflow/rules.yaml
```

## Known Limitations

- `MatchTaint` rules (`PF-ANGULAR-XSS-003`, `PF-ANGULAR-REDIRECT-002`) are
  Experimental maturity. They may produce false positives due to the
  complexity of tracking data through RxJS observables (`.subscribe()`
  callbacks) and template bindings.
- Angular interpolation `{{ }}` is safe by default — Angular auto-escapes
  interpolated values. The pack does not flag `{{ userInput }}` patterns.
- The pattern rules (`PF-ANGULAR-XSS-001`, `PF-ANGULAR-REDIRECT-001`) are
  line-oriented. They require the source and sink to appear on the same line.
  Multi-line flows require the taint rules (`PF-ANGULAR-XSS-003`,
  `PF-ANGULAR-REDIRECT-002`).
- The template rule (`PF-ANGULAR-XSS-002`) flags `[innerHTML]` bindings but
  cannot determine whether the bound value was sanitized in the component
  class. Review findings manually for sanitization context.
- `@Input` source modeling treats the entire input property as tainted;
  downstream sanitization in child components is not tracked.
