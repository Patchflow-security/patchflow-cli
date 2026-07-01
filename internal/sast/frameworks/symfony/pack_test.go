package symfony

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

func TestSymfonyPackContract(t *testing.T) {
	pack := New()
	if pack.Name() != "symfony" || pack.Language() != "php" {
		t.Fatalf("unexpected pack identity: %s/%s", pack.Name(), pack.Language())
	}
	if len(pack.Rules()) == 0 || len(pack.Sources()) == 0 || len(pack.TemplateExtensions()) == 0 {
		t.Fatal("pack contract should expose rules, sources, and templates")
	}
}

func TestSymfonySQLiVulnerable(t *testing.T) {
	findings := scanFixture(t, "Controller.php", `$em->createQuery("SELECT u FROM User u WHERE u.id = ".$request->query->get('id'));`)
	if !hasFinding(findings, "PF-SYMFONY-SQLI-001") {
		t.Fatalf("expected SQLi finding, got %+v", findings)
	}
}

func TestSymfonyTwigRawVulnerable(t *testing.T) {
	findings := scanFixture(t, "show.twig", `{{ name|raw }}`)
	if !hasFinding(findings, "PF-SYMFONY-XSS-001") {
		t.Fatalf("expected Twig raw finding, got %+v", findings)
	}
}

func TestSymfonyTwigEscapedSafe(t *testing.T) {
	findings := scanFixture(t, "show.twig", `{{ name }}`)
	if hasFinding(findings, "PF-SYMFONY-XSS-001") {
		t.Fatalf("normal Twig output should not trigger raw rule: %+v", findings)
	}
}
