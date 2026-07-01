package gin

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

func TestGinPackContract(t *testing.T) {
	pack := New()
	if pack.Name() != "gin" || pack.Language() != "go" {
		t.Fatalf("unexpected pack identity: %s/%s", pack.Name(), pack.Language())
	}
	if len(pack.Rules()) == 0 || len(pack.Sources()) == 0 || len(pack.Sinks()) == 0 {
		t.Fatal("pack contract should expose rules and catalogs")
	}
}

func TestGinSQLiVulnerable(t *testing.T) {
	findings := scanFixture(t, `db.Raw("select * from users where id = " + c.Query("id")).Scan(&users)`)
	if !hasFinding(findings, "PF-GIN-SQLI-001") {
		t.Fatalf("expected SQLi finding, got %+v", findings)
	}
}

func TestGinRedirectVulnerable(t *testing.T) {
	findings := scanFixture(t, `c.Redirect(302, c.Query("next"))`)
	if !hasFinding(findings, "PF-GIN-REDIRECT-001") {
		t.Fatalf("expected redirect finding, got %+v", findings)
	}
}

func TestGinStringEscapedSafe(t *testing.T) {
	findings := scanFixture(t, `c.String(200, html.EscapeString(c.Query("name")))`)
	if hasFinding(findings, "PF-GIN-XSS-001") {
		t.Fatalf("escaped c.String output should not trigger XSS: %+v", findings)
	}
}
