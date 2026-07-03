package django

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
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
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

func TestDjangoPackContract(t *testing.T) {
	pack := New()
	if pack.Name() != "django" || pack.Language() != "python" {
		t.Fatalf("unexpected pack identity: %s/%s", pack.Name(), pack.Language())
	}
	if len(pack.Rules()) == 0 || len(pack.Sources()) == 0 || len(pack.Sinks()) == 0 {
		t.Fatal("pack contract should expose rules and catalogs")
	}
}

func TestDjangoSQLiVulnerable(t *testing.T) {
	findings := scanFixture(t, "views.py", `User.objects.raw("SELECT * FROM users WHERE id = " + request.GET["id"])`)
	if !hasFinding(findings, "PF-DJANGO-SQLI-001") {
		t.Fatalf("expected SQLi finding, got %+v", findings)
	}
}

func TestDjangoTemplateSafeFilterVulnerable(t *testing.T) {
	findings := scanFixture(t, "profile.jinja2", `{{ user_input|safe }}`)
	if !hasFinding(findings, "PF-DJANGO-XSS-002") {
		t.Fatalf("expected template XSS finding, got %+v", findings)
	}
}

func TestDjangoNormalTemplateOutputSafe(t *testing.T) {
	findings := scanFixture(t, "profile.jinja2", `{{ user_input }}`)
	if hasFinding(findings, "PF-DJANGO-XSS-002") {
		t.Fatalf("normal escaped output should not trigger safe-filter rule: %+v", findings)
	}
}

func TestDjangoFrameworkSourceExcluded(t *testing.T) {
	findings := scanFixture(t, filepath.Join("django", "contrib", "admin", "templates", "x.html"), `{{ help_text|safe }}`)
	if hasFinding(findings, "PF-DJANGO-XSS-002") {
		t.Fatalf("Django framework source should not trigger app template rule: %+v", findings)
	}
}

// === PF-DJANGO-REDIRECT-001: Open redirect ===

func TestDjangoRedirectVulnerable(t *testing.T) {
	findings := scanFixture(t, "views.py", `return redirect(request.GET.get("next"))`)
	if !hasFinding(findings, "PF-DJANGO-REDIRECT-001") {
		t.Fatalf("expected redirect finding, got %+v", findings)
	}
}

func TestDjangoRedirectSafeStaticURL(t *testing.T) {
	findings := scanFixture(t, "views.py", `return redirect("/dashboard/")`)
	if hasFinding(findings, "PF-DJANGO-REDIRECT-001") {
		t.Fatalf("static redirect should not trigger rule: %+v", findings)
	}
}

// === PF-DJANGO-XSS-001: mark_safe ===

func TestDjangoMarkSafeVulnerable(t *testing.T) {
	findings := scanFixture(t, "views.py", `return HttpResponse(mark_safe(request.GET["html"]))`)
	if !hasFinding(findings, "PF-DJANGO-XSS-001") {
		t.Fatalf("expected mark_safe finding, got %+v", findings)
	}
}

func TestDjangoMarkSafeSafeFormatHTML(t *testing.T) {
	findings := scanFixture(t, "views.py", `return format_html("<b>{}</b>", request.GET["name"])`)
	if hasFinding(findings, "PF-DJANGO-XSS-001") {
		t.Fatalf("format_html is safe and should not trigger mark_safe rule: %+v", findings)
	}
}

// === PF-DJANGO-DESER-001: pickle.loads ===

func TestDjangoPickleDeserVulnerable(t *testing.T) {
	findings := scanFixture(t, "views.py", `data = pickle.loads(request.body)`)
	if !hasFinding(findings, "PF-DJANGO-DESER-001") {
		t.Fatalf("expected pickle.loads finding, got %+v", findings)
	}
}

func TestDjangoPickleDeserSafeJSON(t *testing.T) {
	findings := scanFixture(t, "views.py", `data = json.loads(request.body)`)
	if hasFinding(findings, "PF-DJANGO-DESER-001") {
		t.Fatalf("json.loads should not trigger pickle rule: %+v", findings)
	}
}

// === PF-DJANGO-CSRF-001: @csrf_exempt ===

func TestDjangoCSRFExemptVulnerable(t *testing.T) {
	findings := scanFixture(t, "views.py", `@csrf_exempt\ndef webhook(request):\n    return HttpResponse("ok")`)
	if !hasFinding(findings, "PF-DJANGO-CSRF-001") {
		t.Fatalf("expected csrf_exempt finding, got %+v", findings)
	}
}

func TestDjangoCSRFExemptSafeReadOnly(t *testing.T) {
	// SafePattern suppresses when read-only HTTP methods are mentioned
	findings := scanFixture(t, "views.py", `@csrf_exempt  # GET only\ndef status(request):\n    return HttpResponse("ok")`)
	if hasFinding(findings, "PF-DJANGO-CSRF-001") {
		t.Fatalf("read-only view with GET mention should be suppressed: %+v", findings)
	}
}

// === PF-DJANGO-SSRF-001: requests.get with user input ===

func TestDjangoSSRFVulnerable(t *testing.T) {
	findings := scanFixture(t, "views.py", `response = requests.get(request.GET["url"])`)
	if !hasFinding(findings, "PF-DJANGO-SSRF-001") {
		t.Fatalf("expected SSRF finding, got %+v", findings)
	}
}

func TestDjangoSSRFSafeStaticURL(t *testing.T) {
	findings := scanFixture(t, "views.py", `response = requests.get("https://api.example.com/status")`)
	if hasFinding(findings, "PF-DJANGO-SSRF-001") {
		t.Fatalf("static URL should not trigger SSRF rule: %+v", findings)
	}
}

// === Mode tests ===

func TestDjangoRuleModesAreBeta(t *testing.T) {
	for _, rule := range New().Rules() {
		if rule.Maturity != frameworks.MaturityBeta {
			t.Errorf("rule %s: expected MaturityBeta, got %s", rule.ID, rule.Maturity)
		}
	}
}

func TestDjangoCSRFRuleIsInformNotBlock(t *testing.T) {
	// CSRF rule should be beta maturity (inform by default, not block)
	// This is enforced by the rulesconfig resolver — beta rules never block
	// unless explicitly configured.
	for _, rule := range New().Rules() {
		if rule.ID == "PF-DJANGO-CSRF-001" {
			if rule.Maturity != frameworks.MaturityBeta {
				t.Errorf("CSRF rule should be beta (inform), got %s", rule.Maturity)
			}
			if rule.Severity == analysis.SeverityHigh || rule.Severity == analysis.SeverityCritical {
				t.Errorf("CSRF rule should not be high/critical severity (it's noisy), got %s", rule.Severity)
			}
		}
	}
}
