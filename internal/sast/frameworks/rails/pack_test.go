package rails

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

// runRules runs the Rails pack's matchable rules against a temp file and
// returns the finding count.
func runRules(t *testing.T, ext, content string) []frameworks.FrameworkRule {
	t.Helper()
	pack := New()
	root := t.TempDir()
	target := filepath.Join(root, "fixture"+ext)
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	matcher := frameworks.NewMatcher(pack.Rules())
	findings, err := matcher.ScanFile(target, root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	_ = findings
	return pack.Rules()
}

func TestRailsPackContract(t *testing.T) {
	pack := New()
	if pack.Name() != "rails" {
		t.Fatalf("name = %s, want rails", pack.Name())
	}
	if pack.Language() != "ruby" {
		t.Fatalf("language = %s, want ruby", pack.Language())
	}
	if len(pack.FileExtensions()) == 0 {
		t.Fatal("FileExtensions should not be empty")
	}
	if len(pack.TemplateExtensions()) == 0 {
		t.Fatal("TemplateExtensions should not be empty")
	}
	if len(pack.Rules()) == 0 {
		t.Fatal("Rules should not be empty")
	}
	if len(pack.Sources()) == 0 {
		t.Fatal("Sources should not be empty")
	}
	if len(pack.Sinks()) == 0 {
		t.Fatal("Sinks should not be empty")
	}
}

func TestRailsXSSVulnerableERB(t *testing.T) {
	pack := New()
	matcher := frameworks.NewMatcher(pack.Rules())
	root := t.TempDir()
	target := filepath.Join(root, "view.html.erb")
	content := `<div><%= raw(params[:name]) %></div>`
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := matcher.ScanFile(target, root)
	if err != nil {
		t.Fatal(err)
	}
	var sawXSS bool
	for _, f := range findings {
		if f.RuleID == "PF-RAILS-XSS-003" {
			sawXSS = true
		}
	}
	if !sawXSS {
		t.Fatalf("expected PF-RAILS-XSS-003 finding for raw() in ERB, got %+v", findings)
	}
}

func TestRailsXSSSanitizedERB(t *testing.T) {
	pack := New()
	matcher := frameworks.NewMatcher(pack.Rules())
	root := t.TempDir()
	target := filepath.Join(root, "view.html.erb")
	// h() escapes output — no finding expected for the template rule.
	content := `<div><%= h(params[:name]) %></div>`
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := matcher.ScanFile(target, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.RuleID == "PF-RAILS-XSS-003" {
			t.Fatalf("PF-RAILS-XSS-003 should not fire on h()-escaped output, got %+v", f)
		}
	}
}

func TestRailsSQLiVulnerable(t *testing.T) {
	pack := New()
	matcher := frameworks.NewMatcher(pack.Rules())
	root := t.TempDir()
	target := filepath.Join(root, "controller.rb")
	content := `User.find_by_sql("SELECT * FROM users WHERE name = '#{params[:name]}'")`
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := matcher.ScanFile(target, root)
	if err != nil {
		t.Fatal(err)
	}
	var sawSQLi bool
	for _, f := range findings {
		if f.RuleID == "PF-RAILS-SQLI-001" {
			sawSQLi = true
		}
	}
	if !sawSQLi {
		t.Fatalf("expected PF-RAILS-SQLI-001 finding, got %+v", findings)
	}
}

func TestRailsSQLiParameterizedSafe(t *testing.T) {
	pack := New()
	matcher := frameworks.NewMatcher(pack.Rules())
	root := t.TempDir()
	target := filepath.Join(root, "controller.rb")
	// Parameterized where — the sanitizer regex should suppress.
	content := `User.where("name = ?", params[:name])`
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := matcher.ScanFile(target, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.RuleID == "PF-RAILS-SQLI-002" {
			t.Fatalf("PF-RAILS-SQLI-002 should not fire on parameterized where, got %+v", f)
		}
	}
}

func TestRailsNormalViewHelpersNoNoise(t *testing.T) {
	pack := New()
	matcher := frameworks.NewMatcher(pack.Rules())
	root := t.TempDir()
	target := filepath.Join(root, "view.html.erb")
	// Normal ERB with escaped output — should not produce framework findings.
	content := `<h1><%= @user.name %></h1>\n<p><%= link_to "Home", root_path %></p>`
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := matcher.ScanFile(target, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("normal ERB should produce 0 findings, got %d: %+v", len(findings), findings)
	}
}

func TestRailsDeserSafeLoadNoFinding(t *testing.T) {
	pack := New()
	matcher := frameworks.NewMatcher(pack.Rules())
	root := t.TempDir()
	target := filepath.Join(root, "model.rb")
	content := `data = YAML.safe_load(payload)`
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := matcher.ScanFile(target, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.RuleID == "PF-RAILS-DESER-001" {
			t.Fatalf("PF-RAILS-DESER-001 should not fire on safe_load, got %+v", f)
		}
	}
}
