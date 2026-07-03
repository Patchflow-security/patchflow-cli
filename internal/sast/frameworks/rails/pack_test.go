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

// === Command injection (PF-RAILS-CMDI-001) ===

func TestRailsCMDISystemInterpVulnerable(t *testing.T) {
	pack := New()
	matcher := frameworks.NewMatcher(pack.Rules())
	root := t.TempDir()
	target := filepath.Join(root, "controller.rb")
	content := `system("ls #{params[:dir]}")`
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := matcher.ScanFile(target, root)
	if err != nil {
		t.Fatal(err)
	}
	var sawCMDI bool
	for _, f := range findings {
		if f.RuleID == "PF-RAILS-CMDI-001" {
			sawCMDI = true
		}
	}
	if !sawCMDI {
		t.Fatalf("expected PF-RAILS-CMDI-001 finding for system() with params interpolation, got %+v", findings)
	}
}

func TestRailsCMDIBackticksInterpVulnerable(t *testing.T) {
	pack := New()
	matcher := frameworks.NewMatcher(pack.Rules())
	root := t.TempDir()
	target := filepath.Join(root, "controller.rb")
	content := "`rm #{params[:file]}`"
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := matcher.ScanFile(target, root)
	if err != nil {
		t.Fatal(err)
	}
	var sawCMDI bool
	for _, f := range findings {
		if f.RuleID == "PF-RAILS-CMDI-001" {
			sawCMDI = true
		}
	}
	if !sawCMDI {
		t.Fatalf("expected PF-RAILS-CMDI-001 finding for backticks with params interpolation, got %+v", findings)
	}
}

func TestRailsCMDISeparateArgsSafe(t *testing.T) {
	pack := New()
	matcher := frameworks.NewMatcher(pack.Rules())
	root := t.TempDir()
	target := filepath.Join(root, "controller.rb")
	// system with separate arguments and no interpolation is safe.
	content := `system("ls", "-la")`
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := matcher.ScanFile(target, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.RuleID == "PF-RAILS-CMDI-001" {
			t.Fatalf("PF-RAILS-CMDI-001 should not fire on system() with separate args, got %+v", f)
		}
	}
}

func TestRailsCMDIShellwordsSanitizedSafe(t *testing.T) {
	pack := New()
	matcher := frameworks.NewMatcher(pack.Rules())
	root := t.TempDir()
	target := filepath.Join(root, "controller.rb")
	// Shellwords.escape sanitizer suppresses the finding even though the
	// pattern matches (interpolated params inside system()).
	content := `system("ls #{Shellwords.escape(params[:dir])}")`
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := matcher.ScanFile(target, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.RuleID == "PF-RAILS-CMDI-001" {
			t.Fatalf("PF-RAILS-CMDI-001 should not fire when Shellwords.escape sanitizer is applied, got %+v", f)
		}
	}
}

// === SSRF (PF-RAILS-SSRF-001) ===

func TestRailsSSRFNetHTTPGetInterpVulnerable(t *testing.T) {
	pack := New()
	matcher := frameworks.NewMatcher(pack.Rules())
	root := t.TempDir()
	target := filepath.Join(root, "controller.rb")
	content := `Net::HTTP.get(URI.parse("https://#{params[:host]}"))`
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := matcher.ScanFile(target, root)
	if err != nil {
		t.Fatal(err)
	}
	var sawSSRF bool
	for _, f := range findings {
		if f.RuleID == "PF-RAILS-SSRF-001" {
			sawSSRF = true
		}
	}
	if !sawSSRF {
		t.Fatalf("expected PF-RAILS-SSRF-001 finding for Net::HTTP.get with params interpolation, got %+v", findings)
	}
}

func TestRailsSSRFNetHTTPStartInterpVulnerable(t *testing.T) {
	pack := New()
	matcher := frameworks.NewMatcher(pack.Rules())
	root := t.TempDir()
	target := filepath.Join(root, "controller.rb")
	content := `Net::HTTP.start("https://#{params[:host]}")`
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := matcher.ScanFile(target, root)
	if err != nil {
		t.Fatal(err)
	}
	var sawSSRF bool
	for _, f := range findings {
		if f.RuleID == "PF-RAILS-SSRF-001" {
			sawSSRF = true
		}
	}
	if !sawSSRF {
		t.Fatalf("expected PF-RAILS-SSRF-001 finding for Net::HTTP.start with params interpolation, got %+v", findings)
	}
}

func TestRailsSSRFStaticURLSafe(t *testing.T) {
	pack := New()
	matcher := frameworks.NewMatcher(pack.Rules())
	root := t.TempDir()
	target := filepath.Join(root, "controller.rb")
	// Static URL with no interpolation — no finding expected.
	content := `Net::HTTP.get(URI.parse("https://example.com"))`
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := matcher.ScanFile(target, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.RuleID == "PF-RAILS-SSRF-001" {
			t.Fatalf("PF-RAILS-SSRF-001 should not fire on a static URL, got %+v", f)
		}
	}
}

// === Weak crypto (PF-RAILS-CRYPTO-001) ===

func TestRailsCryptoMD5HexdigestVulnerable(t *testing.T) {
	pack := New()
	matcher := frameworks.NewMatcher(pack.Rules())
	root := t.TempDir()
	target := filepath.Join(root, "model.rb")
	content := `Digest::MD5.hexdigest(password)`
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := matcher.ScanFile(target, root)
	if err != nil {
		t.Fatal(err)
	}
	var sawCrypto bool
	for _, f := range findings {
		if f.RuleID == "PF-RAILS-CRYPTO-001" {
			sawCrypto = true
		}
	}
	if !sawCrypto {
		t.Fatalf("expected PF-RAILS-CRYPTO-001 finding for Digest::MD5.hexdigest, got %+v", findings)
	}
}

func TestRailsCryptoSHA1Base64Vulnerable(t *testing.T) {
	pack := New()
	matcher := frameworks.NewMatcher(pack.Rules())
	root := t.TempDir()
	target := filepath.Join(root, "model.rb")
	content := `Digest::SHA1.base64digest(data)`
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := matcher.ScanFile(target, root)
	if err != nil {
		t.Fatal(err)
	}
	var sawCrypto bool
	for _, f := range findings {
		if f.RuleID == "PF-RAILS-CRYPTO-001" {
			sawCrypto = true
		}
	}
	if !sawCrypto {
		t.Fatalf("expected PF-RAILS-CRYPTO-001 finding for Digest::SHA1.base64digest, got %+v", findings)
	}
}

func TestRailsCryptoChecksumSafePatternSuppressed(t *testing.T) {
	pack := New()
	matcher := frameworks.NewMatcher(pack.Rules())
	root := t.TempDir()
	target := filepath.Join(root, "model.rb")
	// MD5 used for a cache checksum is a non-security context — the
	// SafePattern (cache|checksum|etag|fingerprint) suppresses the finding.
	content := `Digest::MD5.hexdigest(content) # for cache checksum`
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := matcher.ScanFile(target, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.RuleID == "PF-RAILS-CRYPTO-001" {
			t.Fatalf("PF-RAILS-CRYPTO-001 should not fire on a cache checksum context, got %+v", f)
		}
	}
}

func TestRailsCryptoBCryptSafe(t *testing.T) {
	pack := New()
	matcher := frameworks.NewMatcher(pack.Rules())
	root := t.TempDir()
	target := filepath.Join(root, "model.rb")
	// BCrypt is a strong password hashing algorithm — no weak-hash finding.
	content := `BCrypt::Password.create(password)`
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := matcher.ScanFile(target, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.RuleID == "PF-RAILS-CRYPTO-001" {
			t.Fatalf("PF-RAILS-CRYPTO-001 should not fire on BCrypt, got %+v", f)
		}
	}
}
