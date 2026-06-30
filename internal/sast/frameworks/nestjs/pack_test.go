package nestjs

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
	target := filepath.Join(root, "users.controller.ts")
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

func TestNestJSPackContract(t *testing.T) {
	pack := New()
	if pack.Name() != "nestjs" || pack.Language() != "typescript" {
		t.Fatalf("unexpected pack identity: %s/%s", pack.Name(), pack.Language())
	}
	if len(pack.Rules()) == 0 || len(pack.Sources()) == 0 || len(pack.Sinks()) == 0 {
		t.Fatal("pack contract should expose rules and catalogs")
	}
}

func TestNestJSSQLiVulnerable(t *testing.T) {
	findings := scanFixture(t, `this.repo.query("select * from users where id = " + req.query.id)`)
	if !hasFinding(findings, "PF-NESTJS-SQLI-001") {
		t.Fatalf("expected SQLi finding, got %+v", findings)
	}
}

func TestNestJSRedirectVulnerable(t *testing.T) {
	findings := scanFixture(t, `return res.redirect(req.query.next)`)
	if !hasFinding(findings, "PF-NESTJS-REDIRECT-001") {
		t.Fatalf("expected redirect finding, got %+v", findings)
	}
}
