package aspnet

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
	target := filepath.Join(root, "UsersController.cs")
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

func TestASPNETPackContract(t *testing.T) {
	pack := New()
	if pack.Name() != "aspnet" || pack.Language() != "csharp" {
		t.Fatalf("unexpected pack identity: %s/%s", pack.Name(), pack.Language())
	}
	if len(pack.Rules()) == 0 || len(pack.Sources()) == 0 || len(pack.Sinks()) == 0 {
		t.Fatal("pack contract should expose rules and catalogs")
	}
}

func TestASPNETSQLiVulnerable(t *testing.T) {
	findings := scanFixture(t, `db.Users.FromSqlRaw("SELECT * FROM Users WHERE id = " + Request.Query["id"]);`)
	if !hasFinding(findings, "PF-ASPNET-SQLI-001") {
		t.Fatalf("expected SQLi finding, got %+v", findings)
	}
}

func TestASPNETRedirectSafe(t *testing.T) {
	findings := scanFixture(t, `return LocalRedirect(Request.Query["returnUrl"]);`)
	if hasFinding(findings, "PF-ASPNET-REDIRECT-001") {
		t.Fatalf("LocalRedirect should suppress open redirect: %+v", findings)
	}
}
