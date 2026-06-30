package spring

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

// scanFixture writes content to a temp file with the given extension and
// runs the Spring pack's matchable rules against it, returning the findings.
func scanFixture(t *testing.T, ext, content string) []analysis.Finding {
	t.Helper()
	pack := New()
	matcher := frameworks.NewMatcher(pack.Rules())
	root := t.TempDir()
	target := filepath.Join(root, "fixture"+ext)
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	findings, err := matcher.ScanFile(target, root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return findings
}

// hasFinding returns true if any finding matches the given rule ID.
func hasFinding(findings []analysis.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

func TestSpringPackContract(t *testing.T) {
	pack := New()
	if pack.Name() != "spring" {
		t.Fatalf("name = %s, want spring", pack.Name())
	}
	if pack.Language() != "java" {
		t.Fatalf("language = %s, want java", pack.Language())
	}
	if len(pack.FileExtensions()) == 0 {
		t.Fatal("FileExtensions should not be empty")
	}
	if len(pack.TemplateExtensions()) == 0 {
		t.Fatal("TemplateExtensions should not be empty")
	}
	if len(pack.Rules()) == 0 {
		t.Fatal("Rules should not be empty")
	}
	if len(pack.Sources()) == 0 {
		t.Fatal("Sources should not be empty")
	}
	if len(pack.Sinks()) == 0 {
		t.Fatal("Sinks should not be empty")
	}
	if len(pack.Sanitizers()) == 0 {
		t.Fatal("Sanitizers should not be empty")
	}
}

// === SQL injection ===

func TestSpringSQLiVulnerableJdbcTemplate(t *testing.T) {
	findings := scanFixture(t, ".java",
		`jdbcTemplate.query("SELECT * FROM users WHERE id = " + request.getParameter("id"))`)
	if !hasFinding(findings, "PF-SPRING-SQLI-001") {
		t.Fatalf("expected PF-SPRING-SQLI-001, got %+v", findings)
	}
}

func TestSpringSQLiSafeParameterized(t *testing.T) {
	findings := scanFixture(t, ".java",
		`jdbcTemplate.query("SELECT * FROM users WHERE id = ?", request.getParameter("id"))`)
	if hasFinding(findings, "PF-SPRING-SQLI-001") {
		t.Fatal("PF-SPRING-SQLI-001 should not fire on parameterized query")
	}
}

func TestSpringSQLiVulnerableEntityManager(t *testing.T) {
	findings := scanFixture(t, ".java",
		`entityManager.createNativeQuery("SELECT * FROM users WHERE name = '" + request.getParameter("name") + "'")`)
	if !hasFinding(findings, "PF-SPRING-SQLI-002") {
		t.Fatalf("expected PF-SPRING-SQLI-002, got %+v", findings)
	}
}

// === SSRF ===

func TestSpringSSRFVulnerableRestTemplate(t *testing.T) {
	findings := scanFixture(t, ".java",
		`restTemplate.getForObject(request.getParameter("url"), String.class)`)
	if !hasFinding(findings, "PF-SPRING-SSRF-001") {
		t.Fatalf("expected PF-SPRING-SSRF-001, got %+v", findings)
	}
}

func TestSpringSSRFVulnerableWebClient(t *testing.T) {
	findings := scanFixture(t, ".java",
		`webClient.get().uri(request.getParameter("url")).retrieve()`)
	if !hasFinding(findings, "PF-SPRING-SSRF-002") {
		t.Fatalf("expected PF-SPRING-SSRF-002, got %+v", findings)
	}
}

func TestSpringSSRFSafeUriBuilder(t *testing.T) {
	findings := scanFixture(t, ".java",
		`restTemplate.getForObject(UriComponentsBuilder.fromHttpUrl("https://api.example.com").build().toUri(), String.class)`)
	if hasFinding(findings, "PF-SPRING-SSRF-001") {
		t.Fatal("PF-SPRING-SSRF-001 should not fire when UriComponentsBuilder is used")
	}
}

// === Open redirect ===

func TestSpringRedirectVulnerableSendRedirect(t *testing.T) {
	findings := scanFixture(t, ".java",
		`response.sendRedirect(request.getParameter("returnUrl"))`)
	if !hasFinding(findings, "PF-SPRING-REDIRECT-001") {
		t.Fatalf("expected PF-SPRING-REDIRECT-001, got %+v", findings)
	}
}

func TestSpringRedirectVulnerableRedirectView(t *testing.T) {
	findings := scanFixture(t, ".java",
		`return new RedirectView(request.getParameter("returnUrl"))`)
	if !hasFinding(findings, "PF-SPRING-REDIRECT-002") {
		t.Fatalf("expected PF-SPRING-REDIRECT-002, got %+v", findings)
	}
}

// === Deserialization ===

func TestSpringDeserVulnerableObjectInputStream(t *testing.T) {
	findings := scanFixture(t, ".java",
		`Object obj = new ObjectInputStream(request.getInputStream()).readObject();`)
	if !hasFinding(findings, "PF-SPRING-DESER-001") {
		t.Fatalf("expected PF-SPRING-DESER-001, got %+v", findings)
	}
}

func TestSpringDeserSafeWithFilter(t *testing.T) {
	findings := scanFixture(t, ".java",
		`Object obj = new ObjectInputStream(request.getInputStream()).readObject(); // ObjectInputFilter set`)
	if hasFinding(findings, "PF-SPRING-DESER-001") {
		t.Fatal("PF-SPRING-DESER-001 should not fire when ObjectInputFilter is referenced on the same line")
	}
}

func TestSpringDeserVulnerableXStream(t *testing.T) {
	findings := scanFixture(t, ".java",
		`Object obj = new XStream().fromXML(request.getParameter("data"));`)
	if !hasFinding(findings, "PF-SPRING-DESER-002") {
		t.Fatalf("expected PF-SPRING-DESER-002, got %+v", findings)
	}
}

func TestSpringDeserSafeXStreamAllowTypes(t *testing.T) {
	findings := scanFixture(t, ".java",
		`XStream xstream = new XStream();
		 xstream.allowTypes(new Class[]{MyClass.class});
		 Object obj = xstream.fromXML(request.getParameter("data"));`)
	if hasFinding(findings, "PF-SPRING-DESER-002") {
		t.Fatal("PF-SPRING-DESER-002 should not fire when allowTypes is set")
	}
}

// === XXE ===

func TestSpringXXEVulnerableDocumentBuilderFactory(t *testing.T) {
	findings := scanFixture(t, ".java",
		`DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		 DocumentBuilder builder = factory.newDocumentBuilder();
		 Document doc = builder.parse(request.getInputStream());`)
	if !hasFinding(findings, "PF-SPRING-XXE-001") {
		t.Fatalf("expected PF-SPRING-XXE-001, got %+v", findings)
	}
}

func TestSpringXXESecureDocumentBuilderFactory(t *testing.T) {
	// Line-oriented matcher: safe pattern must be on the same line as newInstance().
	// Multi-line secure config (setFeature on separate lines) is a known limitation
	// of MatchPattern mode; MatchAST mode will handle it in a future iteration.
	findings := scanFixture(t, ".java",
		`DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance(); factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);`)
	if hasFinding(findings, "PF-SPRING-XXE-001") {
		t.Fatal("PF-SPRING-XXE-001 should not fire when disallow-doctype-decl is set on the same line")
	}
}

func TestSpringXXEVulnerableSAXParserFactory(t *testing.T) {
	findings := scanFixture(t, ".java",
		`SAXParserFactory factory = SAXParserFactory.newInstance();
		 SAXParser parser = factory.newSAXParser();`)
	if !hasFinding(findings, "PF-SPRING-XXE-002") {
		t.Fatalf("expected PF-SPRING-XXE-002, got %+v", findings)
	}
}

// === Auth bypass ===

func TestSpringAuthBypassPermitAll(t *testing.T) {
	findings := scanFixture(t, ".java",
		`http.authorizeRequests().antMatchers("/admin/**").permitAll()`)
	if !hasFinding(findings, "PF-SPRING-AUTH-001") {
		t.Fatalf("expected PF-SPRING-AUTH-001, got %+v", findings)
	}
}

func TestSpringAuthBypassPermitAllAnnotation(t *testing.T) {
	findings := scanFixture(t, ".java",
		`@PermitAll
		 @GetMapping("/public")
		 public String publicEndpoint() { return "ok"; }`)
	if !hasFinding(findings, "PF-SPRING-AUTH-002") {
		t.Fatalf("expected PF-SPRING-AUTH-002, got %+v", findings)
	}
}

// === CSRF ===

func TestSpringCSRFDisabled(t *testing.T) {
	findings := scanFixture(t, ".java",
		`http.csrf().disable()`)
	if !hasFinding(findings, "PF-SPRING-CSRF-001") {
		t.Fatalf("expected PF-SPRING-CSRF-001, got %+v", findings)
	}
}

// === XSS (Thymeleaf) ===

func TestSpringXSSVulnerableThymeleafUtext(t *testing.T) {
	findings := scanFixture(t, ".html",
		`<div th:utext="${userInput}"></div>`)
	if !hasFinding(findings, "PF-SPRING-XSS-001") {
		t.Fatalf("expected PF-SPRING-XSS-001, got %+v", findings)
	}
}

func TestSpringXSSSafeThymeleafText(t *testing.T) {
	findings := scanFixture(t, ".html",
		`<div th:text="${userInput}"></div>`)
	if hasFinding(findings, "PF-SPRING-XSS-001") {
		t.Fatal("PF-SPRING-XSS-001 should not fire on th:text (escaped)")
	}
}

// === XSS (JSP) ===

func TestSpringXSSVulnerableJSPCOutEscapeXmlFalse(t *testing.T) {
	findings := scanFixture(t, ".jsp",
		`<c:out value="${param.input}" escapeXml="false" />`)
	if !hasFinding(findings, "PF-SPRING-XSS-002") {
		t.Fatalf("expected PF-SPRING-XSS-002, got %+v", findings)
	}
}

func TestSpringXSSSafeJSPCOutDefault(t *testing.T) {
	findings := scanFixture(t, ".jsp",
		`<c:out value="${param.input}" />`)
	if hasFinding(findings, "PF-SPRING-XSS-002") {
		t.Fatal("PF-SPRING-XSS-002 should not fire when escapeXml is default (true)")
	}
}

// === Command injection ===

func TestSpringCmdiVulnerableRuntimeExec(t *testing.T) {
	findings := scanFixture(t, ".java",
		`Runtime.getRuntime().exec(request.getParameter("cmd"))`)
	if !hasFinding(findings, "PF-SPRING-CMDI-001") {
		t.Fatalf("expected PF-SPRING-CMDI-001, got %+v", findings)
	}
}

func TestSpringCmdiVulnerableProcessBuilderConcat(t *testing.T) {
	findings := scanFixture(t, ".java",
		`new ProcessBuilder("ls " + request.getParameter("dir")).start()`)
	if !hasFinding(findings, "PF-SPRING-CMDI-002") {
		t.Fatalf("expected PF-SPRING-CMDI-002, got %+v", findings)
	}
}

func TestSpringCmdiSafeProcessBuilderList(t *testing.T) {
	findings := scanFixture(t, ".java",
		`new ProcessBuilder(List.of("ls", "-la", "/tmp")).start()`)
	if hasFinding(findings, "PF-SPRING-CMDI-002") {
		t.Fatal("PF-SPRING-CMDI-002 should not fire when ProcessBuilder uses a list")
	}
}

// === Path traversal ===

func TestSpringPathTraversalVulnerableFile(t *testing.T) {
	findings := scanFixture(t, ".java",
		`File file = new File(request.getParameter("path"))`)
	if !hasFinding(findings, "PF-SPRING-PATH-001") {
		t.Fatalf("expected PF-SPRING-PATH-001, got %+v", findings)
	}
}

func TestSpringPathTraversalVulnerablePathsGet(t *testing.T) {
	findings := scanFixture(t, ".java",
		`Path path = Paths.get(request.getParameter("file"))`)
	if !hasFinding(findings, "PF-SPRING-PATH-001") {
		t.Fatalf("expected PF-SPRING-PATH-001, got %+v", findings)
	}
}

// === Normal Spring code (no noise) ===

func TestSpringNormalControllerNoNoise(t *testing.T) {
	findings := scanFixture(t, ".java",
		`@RestController
		 @RequestMapping("/api")
		 public class UserController {
		     @GetMapping("/users/{id}")
		     public ResponseEntity<User> getUser(@PathVariable Long id) {
		         User user = userService.findById(id);
		         return ResponseEntity.ok(user);
		     }
		     @PostMapping("/users")
		     public ResponseEntity<User> createUser(@RequestBody UserDto dto) {
		         User user = userService.create(dto);
		         return ResponseEntity.created(URI.create("/api/users/" + user.getId())).body(user);
		     }
		 }`)
	// Normal controller code should not produce framework findings.
	for _, f := range findings {
		t.Fatalf("normal Spring controller should produce 0 findings, got %s at %s:%d", f.RuleID, f.FilePath, f.LineStart)
	}
}

func TestSpringNormalThymeleafNoNoise(t *testing.T) {
	findings := scanFixture(t, ".html",
		`<!DOCTYPE html>
		 <html xmlns:th="http://www.thymeleaf.org">
		 <body>
		   <h1 th:text="${title}">Welcome</h1>
		   <p th:text="${message}">Hello</p>
		 </body>
		 </html>`)
	for _, f := range findings {
		t.Fatalf("normal Thymeleaf template should produce 0 findings, got %s", f.RuleID)
	}
}

func TestSpringNormalJSPNoNoise(t *testing.T) {
	findings := scanFixture(t, ".jsp",
		`<%@ page contentType="text/html" %>
		 <c:out value="${user.name}" />
		 <c:out value="${user.email}" />`)
	for _, f := range findings {
		t.Fatalf("normal JSP should produce 0 findings, got %s", f.RuleID)
	}
}
