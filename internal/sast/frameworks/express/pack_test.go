package express

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

func TestExpressPackContract(t *testing.T) {
	pack := New()
	if pack.Name() != "express" || pack.Language() != "javascript" {
		t.Fatalf("unexpected pack identity: %s/%s", pack.Name(), pack.Language())
	}
	if len(pack.FileExtensions()) == 0 || len(pack.TemplateExtensions()) == 0 || len(pack.Rules()) == 0 {
		t.Fatal("pack contract should expose extensions and rules")
	}
	if len(pack.Sources()) == 0 || len(pack.Sinks()) == 0 || len(pack.Sanitizers()) == 0 {
		t.Fatal("pack contract should expose taint catalogs")
	}
}

func TestExpressSQLiVulnerable(t *testing.T) {
	findings := scanFixture(t, "app.js", `db.query("SELECT * FROM users WHERE id = " + req.query.id)`)
	if !hasFinding(findings, "PF-EXPRESS-SQLI-001") {
		t.Fatalf("expected SQLi finding, got %+v", findings)
	}
}

func TestExpressSQLiParameterizedSafe(t *testing.T) {
	findings := scanFixture(t, "app.js", `db.query("SELECT * FROM users WHERE id = ?", [req.query.id])`)
	if hasFinding(findings, "PF-EXPRESS-SQLI-001") {
		t.Fatalf("SQLi rule should not fire on bound parameters: %+v", findings)
	}
}

func TestExpressRedirectVulnerable(t *testing.T) {
	findings := scanFixture(t, "app.js", `res.redirect(req.query.next)`)
	if !hasFinding(findings, "PF-EXPRESS-REDIRECT-001") {
		t.Fatalf("expected redirect finding, got %+v", findings)
	}
}

// === PF-EXPRESS-SQLI-002 ===

func TestExpressSQLi002Vulnerable(t *testing.T) {
	findings := scanFixture(t, "app.js", `knex.raw("SELECT * FROM users WHERE id = " + req.query.id)`)
	if !hasFinding(findings, "PF-EXPRESS-SQLI-002") {
		t.Fatalf("expected SQLi-002 finding, got %+v", findings)
	}
}

func TestExpressSQLi002SequelizeVulnerable(t *testing.T) {
	findings := scanFixture(t, "app.ts", `sequelize.query("SELECT * FROM users WHERE name = '" + req.body.name + "'")`)
	if !hasFinding(findings, "PF-EXPRESS-SQLI-002") {
		t.Fatalf("expected SQLi-002 finding for sequelize, got %+v", findings)
	}
}

func TestExpressSQLi002ParameterizedSafe(t *testing.T) {
	findings := scanFixture(t, "app.js", `db.query("SELECT * FROM users WHERE id = ?", [req.query.id])`)
	if hasFinding(findings, "PF-EXPRESS-SQLI-002") {
		t.Fatalf("SQLi-002 should not fire on bound parameters: %+v", findings)
	}
}

func TestExpressSQLi002NoReqInputSafe(t *testing.T) {
	findings := scanFixture(t, "app.js", `db.query("SELECT * FROM users WHERE id = 1")`)
	if hasFinding(findings, "PF-EXPRESS-SQLI-002") {
		t.Fatalf("SQLi-002 should not fire without request input: %+v", findings)
	}
}

// === PF-EXPRESS-NOSQL-001 ===

func TestExpressNoSQLVulnerable(t *testing.T) {
	findings := scanFixture(t, "app.js", `User.find(req.body)`)
	if !hasFinding(findings, "PF-EXPRESS-NOSQL-001") {
		t.Fatalf("expected NoSQL finding, got %+v", findings)
	}
}

func TestExpressNoSQLFindOneVulnerable(t *testing.T) {
	findings := scanFixture(t, "app.ts", `User.findOne(req.query.filter)`)
	if !hasFinding(findings, "PF-EXPRESS-NOSQL-001") {
		t.Fatalf("expected NoSQL finding for findOne, got %+v", findings)
	}
}

func TestExpressNoSQLSanitizedSafe(t *testing.T) {
	findings := scanFixture(t, "app.js", `User.find({ name: validator.escape(req.body.name) })`)
	if hasFinding(findings, "PF-EXPRESS-NOSQL-001") {
		t.Fatalf("NoSQL rule should not fire on sanitized input: %+v", findings)
	}
}

func TestExpressNoSQLLiteralObjectSafe(t *testing.T) {
	findings := scanFixture(t, "app.js", `User.find({ status: "active" })`)
	if hasFinding(findings, "PF-EXPRESS-NOSQL-001") {
		t.Fatalf("NoSQL rule should not fire on literal query object: %+v", findings)
	}
}

// === PF-EXPRESS-SSRF-001 ===

func TestExpressSSRFVulnerable(t *testing.T) {
	findings := scanFixture(t, "app.js", `axios(req.query.url)`)
	if !hasFinding(findings, "PF-EXPRESS-SSRF-001") {
		t.Fatalf("expected SSRF finding, got %+v", findings)
	}
}

func TestExpressSSRFFetchVulnerable(t *testing.T) {
	findings := scanFixture(t, "app.ts", `fetch(req.body.target)`)
	if !hasFinding(findings, "PF-EXPRESS-SSRF-001") {
		t.Fatalf("expected SSRF finding for fetch, got %+v", findings)
	}
}

func TestExpressSSRFSafeUrlSafe(t *testing.T) {
	findings := scanFixture(t, "app.js", `axios.get("https://api.example.com/users")`)
	if hasFinding(findings, "PF-EXPRESS-SSRF-001") {
		t.Fatalf("SSRF rule should not fire on fixed URL: %+v", findings)
	}
}

// === PF-EXPRESS-XSS-002 ===

func TestExpressXSS002SendVulnerable(t *testing.T) {
	findings := scanFixture(t, "app.js", `res.send(req.query.name)`)
	if !hasFinding(findings, "PF-EXPRESS-XSS-002") {
		t.Fatalf("expected XSS-002 finding, got %+v", findings)
	}
}

func TestExpressXSS002RenderWithTemplateSafe(t *testing.T) {
	// res.render with a string-literal template name uses template engines
	// that auto-escape output by default — safe pattern suppresses finding.
	findings := scanFixture(t, "app.js", `res.render('user', req.body)`)
	if hasFinding(findings, "PF-EXPRESS-XSS-002") {
		t.Fatalf("XSS-002 should not fire on res.render with template name: %+v", findings)
	}
}

func TestExpressXSS002SanitizedSafe(t *testing.T) {
	findings := scanFixture(t, "app.js", `res.send(escapeHtml(req.query.name))`)
	if hasFinding(findings, "PF-EXPRESS-XSS-002") {
		t.Fatalf("XSS-002 should not fire on escaped output: %+v", findings)
	}
}

// === Mode tests ===

func TestExpressRuleModesAreBeta(t *testing.T) {
	for _, rule := range New().Rules() {
		if rule.Maturity != frameworks.MaturityBeta {
			t.Errorf("rule %s: expected MaturityBeta, got %s", rule.ID, rule.Maturity)
		}
	}
}

func TestExpressNewRulesPresent(t *testing.T) {
	rules := New().Rules()
	want := map[string]bool{
		"PF-EXPRESS-SQLI-002":  false,
		"PF-EXPRESS-NOSQL-001": false,
		"PF-EXPRESS-SSRF-001":  false,
		"PF-EXPRESS-XSS-002":   false,
	}
	for _, r := range rules {
		if _, ok := want[r.ID]; ok {
			want[r.ID] = true
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("expected rule %s to be present in pack", id)
		}
	}
}
