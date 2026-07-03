package flask

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

func TestFlaskPackContract(t *testing.T) {
	pack := New()
	if pack.Name() != "flask" || pack.Language() != "python" {
		t.Fatalf("unexpected pack identity: %s/%s", pack.Name(), pack.Language())
	}
	if len(pack.Rules()) == 0 || len(pack.Sources()) == 0 || len(pack.Sinks()) == 0 {
		t.Fatal("pack contract should expose rules and catalogs")
	}
}

func TestFlaskSQLiVulnerable(t *testing.T) {
	findings := scanFixture(t, "app.py", `cursor.execute("SELECT * FROM users WHERE id = " + request.args["id"])`)
	if !hasFinding(findings, "PF-FLASK-SQLI-001") {
		t.Fatalf("expected SQLi finding, got %+v", findings)
	}
}

func TestFlaskTemplateSafeFilterVulnerable(t *testing.T) {
	findings := scanFixture(t, "profile.jinja2", `{{ user_input|safe }}`)
	if !hasFinding(findings, "PF-FLASK-XSS-001") {
		t.Fatalf("expected template XSS finding, got %+v", findings)
	}
}

func TestFlaskRenderTemplateStringVariableVulnerable(t *testing.T) {
	findings := scanFixture(t, "app.py", `return render_template_string(template)`)
	if !hasFinding(findings, "PF-FLASK-SSTI-001") {
		t.Fatalf("expected SSTI finding, got %+v", findings)
	}
}

func TestFlaskTemplateNormalOutputSafe(t *testing.T) {
	findings := scanFixture(t, "profile.jinja2", `{{ user_input }}`)
	if hasFinding(findings, "PF-FLASK-XSS-001") {
		t.Fatalf("normal escaped output should not trigger safe filter rule: %+v", findings)
	}
}

func TestFlaskDoesNotRunOnDjangoFrameworkSource(t *testing.T) {
	findings := scanFixture(t, filepath.Join("django", "forms", "jinja2", "field.html"), `{{ widget|safe }}`)
	if hasFinding(findings, "PF-FLASK-XSS-001") {
		t.Fatalf("Flask template rule should not run on Django framework source: %+v", findings)
	}
}
