package express

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

func TestExpressPackContract(t *testing.T) {
	pack := New()
	if pack.Name() != "express" || pack.Language() != "javascript" {
		t.Fatalf("unexpected pack identity: %s/%s", pack.Name(), pack.Language())
	}
	if len(pack.FileExtensions()) == 0 || len(pack.TemplateExtensions()) == 0 || len(pack.Rules()) == 0 {
		t.Fatal("pack contract should expose extensions and rules")
	}
	if len(pack.Sources()) == 0 || len(pack.Sinks()) == 0 || len(pack.Sanitizers()) == 0 {
		t.Fatal("pack contract should expose taint catalogs")
	}
}

func TestExpressSQLiVulnerable(t *testing.T) {
	findings := scanFixture(t, "app.js", `db.query("SELECT * FROM users WHERE id = " + req.query.id)`)
	if !hasFinding(findings, "PF-EXPRESS-SQLI-001") {
		t.Fatalf("expected SQLi finding, got %+v", findings)
	}
}

func TestExpressSQLiParameterizedSafe(t *testing.T) {
	findings := scanFixture(t, "app.js", `db.query("SELECT * FROM users WHERE id = ?", [req.query.id])`)
	if hasFinding(findings, "PF-EXPRESS-SQLI-001") {
		t.Fatalf("SQLi rule should not fire on bound parameters: %+v", findings)
	}
}

func TestExpressRedirectVulnerable(t *testing.T) {
	findings := scanFixture(t, "app.js", `res.redirect(req.query.next)`)
	if !hasFinding(findings, "PF-EXPRESS-REDIRECT-001") {
		t.Fatalf("expected redirect finding, got %+v", findings)
	}
}
