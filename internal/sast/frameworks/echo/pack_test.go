package echo

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

func scanFixture(t *testing.T, content string) []analysis.Finding {
	t.Helper()
	root := t.TempDir()
	target := filepath.Join(root, "handler.go")
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

func TestEchoPackContract(t *testing.T) {
	pack := New()
	if pack.Name() != "echo" || pack.Language() != "go" {
		t.Fatalf("unexpected pack identity: %s/%s", pack.Name(), pack.Language())
	}
	if len(pack.Rules()) == 0 || len(pack.Sources()) == 0 || len(pack.Sinks()) == 0 {
		t.Fatal("pack contract should expose rules and catalogs")
	}
}

func TestEchoSQLiVulnerable(t *testing.T) {
	findings := scanFixture(t, `db.Raw("select * from users where id = " + c.QueryParam("id")).Scan(&users)`)
	if !hasFinding(findings, "PF-ECHO-SQLI-001") {
		t.Fatalf("expected SQLi finding, got %+v", findings)
	}
}

func TestEchoRedirectVulnerable(t *testing.T) {
	findings := scanFixture(t, `return c.Redirect(302, c.QueryParam("next"))`)
	if !hasFinding(findings, "PF-ECHO-REDIRECT-001") {
		t.Fatalf("expected redirect finding, got %+v", findings)
	}
}

func TestEchoHTMLEscapedSafe(t *testing.T) {
	findings := scanFixture(t, `return c.HTML(200, html.EscapeString(c.QueryParam("name")))`)
	if hasFinding(findings, "PF-ECHO-XSS-001") {
		t.Fatalf("escaped HTML should not trigger XSS: %+v", findings)
	}
}
