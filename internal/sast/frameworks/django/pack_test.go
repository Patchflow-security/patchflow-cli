package django

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

func scanFixture(t *testing.T, name, content string) []analysis.Finding {
	t.Helper()
	root := t.TempDir()
	target := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := frameworks.NewMatcher(New().Rules()).ScanFile(target, root)
	if err != nil {
		t.Fatal(err)
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

func TestDjangoPackContract(t *testing.T) {
	pack := New()
	if pack.Name() != "django" || pack.Language() != "python" {
		t.Fatalf("unexpected pack identity: %s/%s", pack.Name(), pack.Language())
	}
	if len(pack.Rules()) == 0 || len(pack.Sources()) == 0 || len(pack.Sinks()) == 0 {
		t.Fatal("pack contract should expose rules and catalogs")
	}
}

func TestDjangoSQLiVulnerable(t *testing.T) {
	findings := scanFixture(t, "views.py", `User.objects.raw("SELECT * FROM users WHERE id = " + request.GET["id"])`)
	if !hasFinding(findings, "PF-DJANGO-SQLI-001") {
		t.Fatalf("expected SQLi finding, got %+v", findings)
	}
}

func TestDjangoTemplateSafeFilterVulnerable(t *testing.T) {
	findings := scanFixture(t, "profile.jinja2", `{{ user_input|safe }}`)
	if !hasFinding(findings, "PF-DJANGO-XSS-002") {
		t.Fatalf("expected template XSS finding, got %+v", findings)
	}
}

func TestDjangoNormalTemplateOutputSafe(t *testing.T) {
	findings := scanFixture(t, "profile.jinja2", `{{ user_input }}`)
	if hasFinding(findings, "PF-DJANGO-XSS-002") {
		t.Fatalf("normal escaped output should not trigger safe-filter rule: %+v", findings)
	}
}

func TestDjangoFrameworkSourceExcluded(t *testing.T) {
	findings := scanFixture(t, filepath.Join("django", "contrib", "admin", "templates", "x.html"), `{{ help_text|safe }}`)
	if hasFinding(findings, "PF-DJANGO-XSS-002") {
		t.Fatalf("Django framework source should not trigger app template rule: %+v", findings)
	}
}
