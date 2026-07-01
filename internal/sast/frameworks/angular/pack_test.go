package angular

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

func TestAngularPackContract(t *testing.T) {
	pack := New()
	if pack.Name() != "angular" || pack.Language() != "typescript" {
		t.Fatalf("unexpected pack identity: %s/%s", pack.Name(), pack.Language())
	}
	if len(pack.Rules()) == 0 || len(pack.Sources()) == 0 || len(pack.TemplateExtensions()) == 0 {
		t.Fatal("pack contract should expose rules, sources, and templates")
	}
}

func TestAngularBypassSecurityTrustVulnerable(t *testing.T) {
	findings := scanFixture(t, "component.ts", `this.html = this.sanitizer.bypassSecurityTrustHtml(this.route.queryParams["html"]);`)
	if !hasFinding(findings, "PF-ANGULAR-XSS-001") {
		t.Fatalf("expected XSS finding, got %+v", findings)
	}
}

func TestAngularTemplateInnerHTMLVulnerable(t *testing.T) {
	findings := scanFixture(t, "component.html", `<div [innerHTML]="html"></div>`)
	if !hasFinding(findings, "PF-ANGULAR-XSS-002") {
		t.Fatalf("expected innerHTML finding, got %+v", findings)
	}
}

func TestAngularNormalInterpolationSafe(t *testing.T) {
	findings := scanFixture(t, "component.html", `<div>{{ html }}</div>`)
	if hasFinding(findings, "PF-ANGULAR-XSS-002") {
		t.Fatalf("normal interpolation should not trigger innerHTML rule: %+v", findings)
	}
}
