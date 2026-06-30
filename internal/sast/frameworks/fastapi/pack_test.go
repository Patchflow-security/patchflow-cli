package fastapi

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

func scanFixture(t *testing.T, name, content string) []analysis.Finding {
	t.Helper()
	pack := New()
	matcher := frameworks.NewMatcher(pack.Rules())
	root := t.TempDir()
	target := filepath.Join(root, name)
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	findings, err := matcher.ScanFile(target, root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return findings
}

func hasFinding(findings []analysis.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

func TestFastAPIPackContract(t *testing.T) {
	pack := New()
	if pack.Name() != "fastapi" {
		t.Fatalf("name = %s, want fastapi", pack.Name())
	}
	if pack.Language() != "python" {
		t.Fatalf("language = %s, want python", pack.Language())
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
}

func TestFastAPISQLiVulnerable(t *testing.T) {
	findings := scanFixture(t, "main.py", `cursor.execute(f"SELECT * FROM users WHERE id = {request.query_params['id']}")`)
	if !hasFinding(findings, "PF-FASTAPI-SQLI-001") {
		t.Fatalf("expected PF-FASTAPI-SQLI-001, got %+v", findings)
	}
}

func TestFastAPISQLiParameterizedSafe(t *testing.T) {
	findings := scanFixture(t, "main.py", `cursor.execute("SELECT * FROM users WHERE id = %s", (request.query_params["id"],))`)
	if hasFinding(findings, "PF-FASTAPI-SQLI-001") {
		t.Fatalf("PF-FASTAPI-SQLI-001 should not fire on parameterized query, got %+v", findings)
	}
}

func TestFastAPIRedirectVulnerable(t *testing.T) {
	findings := scanFixture(t, "main.py", `return RedirectResponse(url=request.query_params["next"])`)
	if !hasFinding(findings, "PF-FASTAPI-REDIRECT-001") {
		t.Fatalf("expected PF-FASTAPI-REDIRECT-001, got %+v", findings)
	}
}

func TestFastAPICommandInjectionVulnerable(t *testing.T) {
	findings := scanFixture(t, "main.py", `subprocess.run(["sh", "-c", request.query_params["cmd"]])`)
	if !hasFinding(findings, "PF-FASTAPI-CMDI-001") {
		t.Fatalf("expected PF-FASTAPI-CMDI-001, got %+v", findings)
	}
}

func TestFastAPITemplateXSSVulnerable(t *testing.T) {
	findings := scanFixture(t, "profile.jinja2", `{{ user_input|safe }}`)
	if !hasFinding(findings, "PF-FASTAPI-XSS-001") {
		t.Fatalf("expected PF-FASTAPI-XSS-001, got %+v", findings)
	}
}

func TestFastAPITemplateEscapedSafe(t *testing.T) {
	findings := scanFixture(t, "profile.jinja2", `{{ user_input }}`)
	if hasFinding(findings, "PF-FASTAPI-XSS-001") {
		t.Fatalf("PF-FASTAPI-XSS-001 should not fire on escaped output, got %+v", findings)
	}
}
