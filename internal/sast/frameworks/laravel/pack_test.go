package laravel

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

func TestLaravelPackContract(t *testing.T) {
	pack := New()
	if pack.Name() != "laravel" || pack.Language() != "php" {
		t.Fatalf("unexpected pack identity: %s/%s", pack.Name(), pack.Language())
	}
	if len(pack.Rules()) == 0 || len(pack.TemplateExtensions()) == 0 || len(pack.Sources()) == 0 {
		t.Fatal("pack contract should expose rules, templates, and sources")
	}
}

func TestLaravelSQLiVulnerable(t *testing.T) {
	findings := scanFixture(t, "UserController.php", `DB::select("select * from users where id = " . $request->input('id'));`)
	if !hasFinding(findings, "PF-LARAVEL-SQLI-001") {
		t.Fatalf("expected SQLi finding, got %+v", findings)
	}
}

func TestLaravelBladeXSSVulnerable(t *testing.T) {
	findings := scanFixture(t, "show.blade.php", `{!! $name !!}`)
	if !hasFinding(findings, "PF-LARAVEL-XSS-001") {
		t.Fatalf("expected Blade XSS finding, got %+v", findings)
	}
}

func TestLaravelBladeEscapedSafe(t *testing.T) {
	findings := scanFixture(t, "show.blade.php", `{{ $name }}`)
	if hasFinding(findings, "PF-LARAVEL-XSS-001") {
		t.Fatalf("escaped Blade output should not trigger unescaped rule: %+v", findings)
	}
}
