package nextjs

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

func TestNextJSPackContract(t *testing.T) {
	pack := New()
	if pack.Name() != "nextjs" || pack.Language() != "javascript" {
		t.Fatalf("unexpected pack identity: %s/%s", pack.Name(), pack.Language())
	}
	if len(pack.Rules()) == 0 || len(pack.Sources()) == 0 || len(pack.Sinks()) == 0 {
		t.Fatal("pack contract should expose rules and catalogs")
	}
}

func TestNextJSSSRFVulnerable(t *testing.T) {
	findings := scanFixture(t, "route.ts", `return fetch(request.nextUrl.searchParams.get("url"))`)
	if !hasFinding(findings, "PF-NEXTJS-SSRF-001") {
		t.Fatalf("expected SSRF finding, got %+v", findings)
	}
}

func TestNextJSRedirectVulnerable(t *testing.T) {
	findings := scanFixture(t, "route.ts", `return NextResponse.redirect(request.nextUrl.searchParams.get("next"))`)
	if !hasFinding(findings, "PF-NEXTJS-REDIRECT-001") {
		t.Fatalf("expected redirect finding, got %+v", findings)
	}
}

func TestNextJSRedirectDoesNotMatchExpressResponseRedirect(t *testing.T) {
	findings := scanFixture(t, "routes.js", `return res.redirect(req.query.url)`)
	if hasFinding(findings, "PF-NEXTJS-REDIRECT-001") {
		t.Fatalf("Next.js redirect rule should not match Express res.redirect: %+v", findings)
	}
}

func TestNextJSXSSSafeNormalText(t *testing.T) {
	findings := scanFixture(t, "page.tsx", `<div>{searchParams.name}</div>`)
	if hasFinding(findings, "PF-NEXTJS-XSS-001") {
		t.Fatalf("normal JSX text rendering should not trigger XSS: %+v", findings)
	}
}

func TestNextJSSecretExposedAPIKey(t *testing.T) {
	findings := scanFixture(t, "page.tsx", `const key = process.env.NEXT_PUBLIC_API_KEY`)
	if !hasFinding(findings, "PF-NEXTJS-SECRET-001") {
		t.Fatalf("expected SECRET finding for NEXT_PUBLIC_API_KEY, got %+v", findings)
	}
}

func TestNextJSSecretExposedJWTSecret(t *testing.T) {
	findings := scanFixture(t, "page.tsx", `const secret = process.env.NEXT_PUBLIC_JWT_SECRET`)
	if !hasFinding(findings, "PF-NEXTJS-SECRET-001") {
		t.Fatalf("expected SECRET finding for NEXT_PUBLIC_JWT_SECRET, got %+v", findings)
	}
}

func TestNextJSSecretNonSecretPublicVar(t *testing.T) {
	findings := scanFixture(t, "page.tsx", `const analytics = process.env.NEXT_PUBLIC_ANALYTICS_ID`)
	if hasFinding(findings, "PF-NEXTJS-SECRET-001") {
		t.Fatalf("non-secret NEXT_PUBLIC_ANALYTICS_ID should not trigger SECRET: %+v", findings)
	}
}

func TestNextJSSecretServerOnlyEnvVar(t *testing.T) {
	findings := scanFixture(t, "route.ts", `const key = process.env.API_KEY`)
	if hasFinding(findings, "PF-NEXTJS-SECRET-001") {
		t.Fatalf("server-only env var without NEXT_PUBLIC prefix should not trigger SECRET: %+v", findings)
	}
}

func TestNextJSRuleMaturityAndSeverity(t *testing.T) {
	for _, rule := range New().Rules() {
		if rule.Maturity != frameworks.MaturityBeta {
			t.Fatalf("rule %s expected MaturityBeta, got %s", rule.ID, rule.Maturity)
		}
	}
	for _, rule := range New().Rules() {
		if rule.ID == "PF-NEXTJS-SECRET-001" && rule.Severity != analysis.SeverityMedium {
			t.Fatalf("SECRET rule expected Medium severity, got %s", rule.Severity)
		}
	}
}
