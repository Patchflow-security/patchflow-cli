package razor

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

func TestRazorPackContract(t *testing.T) {
	pack := New()
	if pack.Name() != "razor" || pack.Language() != "csharp" {
		t.Fatalf("unexpected pack identity: %s/%s", pack.Name(), pack.Language())
	}
	if len(pack.Rules()) == 0 || len(pack.TemplateExtensions()) == 0 {
		t.Fatal("pack contract should expose template rules")
	}
}

func TestRazorHtmlRawVulnerable(t *testing.T) {
	findings := scanFixture(t, "Index.cshtml", `@Html.Raw(Request.Query["name"])`)
	if !hasFinding(findings, "PF-RAZOR-XSS-001") {
		t.Fatalf("expected XSS finding, got %+v", findings)
	}
}

func TestRazorNormalOutputSafe(t *testing.T) {
	findings := scanFixture(t, "Index.cshtml", `@Request.Query["name"]`)
	if hasFinding(findings, "PF-RAZOR-XSS-001") {
		t.Fatalf("normal Razor output should not trigger Html.Raw rule: %+v", findings)
	}
}
