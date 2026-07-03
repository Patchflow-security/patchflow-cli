# Spring Framework Pack

## Overview

The Spring pack detects security vulnerabilities in Java applications built
with Spring Boot. It combines taint tracking (Spring annotation-based source
modeling → dangerous sinks) with pattern matching (Spring Security
misconfiguration).

**Pack name:** `spring`  
**Language:** Java  
**File extensions:** `.java`  
**Template extensions:** `.jsp`, `.jspx`, `.ftl`, `.vm`, `.html`, `.thymeleaf.html`  
**Maturity:** Beta (taint rules), Experimental (CSRF rule)

## Framework Detection

The Spring pack activates when any of the following signals are detected
(MinSignals: 1):

| Signal | Location | Contains |
|--------|----------|----------|
| `spring-boot` | pom.xml | `spring-boot` |
| `spring-boot` | build.gradle | `spring-boot` |
| `application.yml` | `**/application.yml` | — |
| `application.properties` | `**/application.properties` | — |
| `*Application.java` | `**/*Application.java` | — |

## Sources

Spring controller parameters annotated with the following annotations are
modeled as taint sources via `seedAnnotatedParams()` in the taint engine.
Parameters carrying these annotations are pre-tainted as user-controlled
input:

| Source | Description |
|--------|-------------|
| `@RequestParam` | Query parameter binding |
| `@PathVariable` | URL path variable binding |
| `@RequestBody` | Request body binding |
| `@RequestHeader` | Request header binding |
| `@CookieValue` | Cookie value binding |
| `@ModelAttribute` | Model attribute binding |

## Sinks

| Sink | ArgIndex | CWE |
|------|----------|-----|
| `bypassSecurityTrustHtml` | 0 | CWE-79 (XSS) |
| `execute` | 0 | CWE-89 (SQLi) |
| `query` | 0 | CWE-89 (SQLi) |
| `createQuery` | 0 | CWE-89 (SQLi) |
| `executeUpdate` | 0 | CWE-89 (SQLi) |
| `RestTemplate` | 0 | CWE-918 (SSRF) |
| `redirect` | 0 | CWE-601 (Open redirect) |
| `forward` | 0 | CWE-601 (Open redirect) |

## Sanitizers

| Sanitizer | Description |
|-----------|-------------|
| `PreparedStatement` | Parameterized SQL query |
| `bindparam` | Bound parameter |
| `escape` | HTML escaping |
| `HtmlUtils.htmlEscape` | Spring HTML escaping |
| `StringEscapeUtils` | Apache Commons escaping |

## Rules

### PF-SPRINGSEC-CSRF-001 — Spring Security CSRF disabled

| Field | Value |
|-------|-------|
| CWE | CWE-352 |
| Severity | High |
| Confidence | Medium |
| Maturity | Beta |
| MatchMode | Pattern |
| Default mode | Inform (beta maturity) |

**Detects:** Spring Security configurations where CSRF protection is
explicitly disabled via `.csrf().disable()` or `csrf().ignoringRequestMatchers(...)`.

**Vulnerable:**
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
        return http.build();
    }
}
```

**Safe:**
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));
        return http.build();
    }
}
```

### TP-JAVA001 — SQL injection: @RequestParam → raw SQL

| Field | Value |
|-------|-------|
| CWE | CWE-89 |
| Severity | High |
| Confidence | Medium |
| Maturity | Beta |
| MatchMode | Taint |
| Default mode | Inform |

**Detects:** Spring controller parameters annotated with `@RequestParam`,
`@PathVariable`, or `@RequestBody` flowing into raw SQL `execute()`,
`createQuery()`, or `executeUpdate()` calls without parameterization.

**Vulnerable:**
```java
@GetMapping("/users")
public List<User> getUsers(@RequestParam String name) {
    return jdbcTemplate.query("SELECT * FROM users WHERE name = '" + name + "'",
        userRowMapper);
}
```

**Safe:**
```java
@GetMapping("/users")
public List<User> getUsers(@RequestParam String name) {
    return jdbcTemplate.query("SELECT * FROM users WHERE name = ?",
        userRowMapper, name);
}
```

### TP-JAVA002 — Command injection: @RequestParam → exec

| Field | Value |
|-------|-------|
| CWE | CWE-78 |
| Severity | High |
| Confidence | Medium |
| Maturity | Beta |
| MatchMode | Taint |
| Default mode | Inform |

**Detects:** Spring controller parameters flowing into `Runtime.exec()` or
`ProcessBuilder` without sanitization.

### TP-JAVA003 — XSS: @RequestParam → template output

| Field | Value |
|-------|-------|
| CWE | CWE-79 |
| Severity | Medium |
| Confidence | Medium |
| Maturity | Beta |
| MatchMode | Taint |
| Default mode | Inform |

**Detects:** Spring controller parameters flowing into template rendering
without HTML escaping.

### TP-JAVA004 — SSRF: @RequestParam → RestTemplate

| Field | Value |
|-------|-------|
| CWE | CWE-918 |
| Severity | High |
| Confidence | Medium |
| Maturity | Beta |
| MatchMode | Taint |
| Default mode | Inform |

**Detects:** Spring controller parameters flowing into `RestTemplate` HTTP
calls without URL validation.

### TP-JAVA005 — Open redirect: @RequestParam → redirect

| Field | Value |
|-------|-------|
| CWE | CWE-601 |
| Severity | Medium |
| Confidence | Medium |
| Maturity | Beta |
| MatchMode | Taint |
| Default mode | Inform |

**Detects:** Spring controller parameters flowing into `redirect:` or
`forward:` prefixes without URL validation.

### TP-JAVA006–010 — Additional taint rules

| Rule | CWE | Description |
|------|-----|-------------|
| TP-JAVA006 | CWE-89 | `@PathVariable` → raw SQL |
| TP-JAVA007 | CWE-89 | `@RequestBody` → raw SQL |
| TP-JAVA008 | CWE-78 | `@PathVariable` → command exec |
| TP-JAVA009 | CWE-79 | `@ModelAttribute` → template output |
| TP-JAVA010 | CWE-918 | `@RequestHeader` → RestTemplate |

## Vulnerable Examples

### SQL injection via @RequestParam

```java
@RestController
public class ProductController {
    @Autowired
    private JdbcTemplate jdbcTemplate;

    @GetMapping("/search")
    public List<Map<String, Object>> search(@RequestParam String q) {
        String sql = "SELECT * FROM products WHERE name LIKE '%" + q + "%'";
        return jdbcTemplate.queryForList(sql);
    }
}
```

### Open redirect via @RequestParam

```java
@Controller
public class AuthController {
    @GetMapping("/login")
    public String login(@RequestParam String redirectUrl) {
        return "redirect:" + redirectUrl;
    }
}
```

## Safe Examples

### Parameterized SQL query

```java
@RestController
public class ProductController {
    @Autowired
    private JdbcTemplate jdbcTemplate;

    @GetMapping("/search")
    public List<Map<String, Object>> search(@RequestParam String q) {
        String sql = "SELECT * FROM products WHERE name LIKE ?";
        return jdbcTemplate.queryForList(sql, "%" + q + "%");
    }
}
```

### Validated redirect

```java
@Controller
public class AuthController {
    @GetMapping("/login")
    public String login(@RequestParam String redirectUrl) {
        if (redirectUrl.startsWith("/") && !redirectUrl.startsWith("//")) {
            return "redirect:" + redirectUrl;
        }
        return "redirect:/home";
    }
}
```

## Overriding Rules

In `.patchflow/rules.yaml`:

```yaml
rule_modes:
  PF-SPRINGSEC-CSRF-001: block    # promote to blocking
  TP-JAVA001: block               # block SQL injection findings
  TP-JAVA005: off                 # disable open redirect heuristic
```

Or via CLI:

```bash
patchflow scan run --rules-config .patchflow/rules.yaml
```

## Known Limitations

- The annotation-based source model requires tree-sitter Java parsing. If the
  Java parser is unavailable or the file cannot be parsed, annotated parameters
  will not be seeded as taint sources.
- Multi-line SQL string concatenation may be missed by taint tracking when the
  source and sink span different AST nodes across complex builder chains.
- The CSRF pattern rule (`PF-SPRINGSEC-CSRF-001`) is line-oriented and may not
  detect CSRF disabled via configuration properties (e.g.,
  `spring.security.csrf.enabled=false`).
- `@ModelAttribute` source modeling treats the entire bound object as tainted;
  individual field-level sanitization within the model is not tracked.
- Spring Data JPA derived query methods (e.g., `findByName`) are not flagged
  as sinks — only explicit `createQuery`, `query`, and `executeUpdate` calls.
