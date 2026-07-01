package springsecurity

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
	target := filepath.Join(root, "SecurityConfig.java")
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

func TestSpringSecurityPackContract(t *testing.T) {
	pack := New()
	if pack.Name() != "spring-security" || pack.Language() != "java" {
		t.Fatalf("unexpected pack identity: %s/%s", pack.Name(), pack.Language())
	}
	if len(pack.FileExtensions()) == 0 || len(pack.Rules()) == 0 || len(pack.Sinks()) == 0 {
		t.Fatal("pack contract should expose extensions, rules, and sinks")
	}
}

func TestSpringSecurityCSRFDisabled(t *testing.T) {
	findings := scanFixture(t, `http.csrf().disable();`)
	if !hasFinding(findings, "PF-SPRINGSEC-CSRF-001") {
		t.Fatalf("expected CSRF finding, got %+v", findings)
	}
}

func TestSpringSecuritySensitivePermitAll(t *testing.T) {
	findings := scanFixture(t, `http.authorizeRequests().antMatchers("/admin/**").permitAll();`)
	if !hasFinding(findings, "PF-SPRINGSEC-AUTH-001") {
		t.Fatalf("expected auth bypass finding, got %+v", findings)
	}
}

func TestSpringSecurityAuthenticatedSafe(t *testing.T) {
	findings := scanFixture(t, `http.authorizeRequests().antMatchers("/admin/**").hasRole("ADMIN");`)
	if hasFinding(findings, "PF-SPRINGSEC-AUTH-001") {
		t.Fatalf("hasRole should not trigger permitAll rule: %+v", findings)
	}
}
