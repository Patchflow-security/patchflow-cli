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

func TestNestJSAuthSensitiveRouteDeleteAdmin(t *testing.T) {
	findings := scanFixture(t, "@Delete(\"/admin/users/:id\")\n  remove(@Param() params) { return this.repo.remove(params.id); }")
	if !hasFinding(findings, "PF-NESTJS-AUTH-001") {
		t.Fatalf("expected AUTH finding for sensitive admin route without guard, got %+v", findings)
	}
}

func TestNestJSAuthSensitiveRouteAccountPassword(t *testing.T) {
	findings := scanFixture(t, "@Post(\"/account/password\")\n  changePassword(@Body() dto) { return this.service.change(dto); }")
	if !hasFinding(findings, "PF-NESTJS-AUTH-001") {
		t.Fatalf("expected AUTH finding for account/password route without guard, got %+v", findings)
	}
}

func TestNestJSAuthPublicRouteNoFinding(t *testing.T) {
	findings := scanFixture(t, "@Get(\"/public/health\")\n  health() { return { ok: true }; }")
	if hasFinding(findings, "PF-NESTJS-AUTH-001") {
		t.Fatalf("expected no AUTH finding for public route, got %+v", findings)
	}
}

func TestNestJSAuthUseGuardsSuppressesFinding(t *testing.T) {
	findings := scanFixture(t, "@UseGuards(AuthGuard) @Delete(\"/admin/users/:id\")\n  remove(@Param() params) { return this.repo.remove(params.id); }")
	if hasFinding(findings, "PF-NESTJS-AUTH-001") {
		t.Fatalf("expected no AUTH finding when @UseGuards present on same line, got %+v", findings)
	}
}

func TestNestJSAuthRolesSuppressesFinding(t *testing.T) {
	findings := scanFixture(t, "@Roles(\"admin\") @Post(\"/settings/manage\")\n  manage(@Body() dto) { return this.service.manage(dto); }")
	if hasFinding(findings, "PF-NESTJS-AUTH-001") {
		t.Fatalf("expected no AUTH finding when @Roles present on same line, got %+v", findings)
	}
}

func TestNestJSAuthRuleMetadata(t *testing.T) {
	var rule *frameworks.FrameworkRule
	for i := range New().Rules() {
		r := New().Rules()[i]
		if r.ID == "PF-NESTJS-AUTH-001" {
			rule = &r
			break
		}
	}
	if rule == nil {
		t.Fatal("PF-NESTJS-AUTH-001 rule not found")
	}
	if rule.Maturity != frameworks.MaturityBeta {
		t.Fatalf("expected MaturityBeta, got %s", rule.Maturity)
	}
	if rule.Severity != analysis.SeverityMedium {
		t.Fatalf("expected SeverityMedium, got %s", rule.Severity)
	}
	if rule.Confidence != analysis.ConfidenceLow {
		t.Fatalf("expected ConfidenceLow, got %s", rule.Confidence)
	}
	if rule.CWE != "CWE-862" {
		t.Fatalf("expected CWE-862, got %s", rule.CWE)
	}
	if rule.MatchMode != frameworks.MatchPattern {
		t.Fatalf("expected MatchPattern, got %s", rule.MatchMode)
	}
	if len(rule.SafePatterns) == 0 {
		t.Fatal("expected SafePatterns to be defined")
	}
}
