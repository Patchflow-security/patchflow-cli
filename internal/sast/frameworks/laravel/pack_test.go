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

func findingFor(findings []analysis.Finding, ruleID string) (analysis.Finding, bool) {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return f, true
		}
	}
	return analysis.Finding{}, false
}

func ruleByID(id string) (frameworks.FrameworkRule, bool) {
	for _, r := range New().Rules() {
		if r.ID == id {
			return r, true
		}
	}
	return frameworks.FrameworkRule{}, false
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

func TestLaravelDeserVulnerable(t *testing.T) {
	findings := scanFixture(t, "ImportController.php", `$data = unserialize($request->input('payload'));`)
	if !hasFinding(findings, "PF-LARAVEL-DESER-001") {
		t.Fatalf("expected deserialization finding, got %+v", findings)
	}
}

func TestLaravelDeserRequestHelperVulnerable(t *testing.T) {
	findings := scanFixture(t, "ImportController.php", `$obj = unserialize(request('data'));`)
	if !hasFinding(findings, "PF-LARAVEL-DESER-001") {
		t.Fatalf("expected deserialization finding for request(), got %+v", findings)
	}
}

func TestLaravelDeserSupercookieVulnerable(t *testing.T) {
	findings := scanFixture(t, "ImportController.php", `$obj = unserialize($_COOKIE['token']);`)
	if !hasFinding(findings, "PF-LARAVEL-DESER-001") {
		t.Fatalf("expected deserialization finding for $_COOKIE, got %+v", findings)
	}
}

func TestLaravelDeserConstantSafe(t *testing.T) {
	findings := scanFixture(t, "ImportController.php", `$cfg = unserialize(file_get_contents(base_path('config.dat')));`)
	if hasFinding(findings, "PF-LARAVEL-DESER-001") {
		t.Fatalf("unserialize of non-user input should not trigger deser rule: %+v", findings)
	}
}

func TestLaravelDeserJsonDecodeSafe(t *testing.T) {
	findings := scanFixture(t, "ImportController.php", `$data = json_decode($request->input('payload'), true);`)
	if hasFinding(findings, "PF-LARAVEL-DESER-001") {
		t.Fatalf("json_decode should not trigger deserialization rule: %+v", findings)
	}
}

func TestLaravelAuthSensitiveRouteVulnerable(t *testing.T) {
	findings := scanFixture(t, "routes.php", `Route::get('/admin', [AdminController::class, 'index']);`)
	if !hasFinding(findings, "PF-LARAVEL-AUTH-001") {
		t.Fatalf("expected missing-auth finding on admin route, got %+v", findings)
	}
}

func TestLaravelAuthManageRouteVulnerable(t *testing.T) {
	findings := scanFixture(t, "routes.php", `Route::post('/settings/manage', 'SettingsController@manage');`)
	if !hasFinding(findings, "PF-LARAVEL-AUTH-001") {
		t.Fatalf("expected missing-auth finding on manage route, got %+v", findings)
	}
}

func TestLaravelAuthMiddlewareSafe(t *testing.T) {
	findings := scanFixture(t, "routes.php", `Route::get('/admin', [AdminController::class, 'index'])->middleware('auth');`)
	if hasFinding(findings, "PF-LARAVEL-AUTH-001") {
		t.Fatalf("route with auth middleware should not trigger missing-auth rule: %+v", findings)
	}
}

func TestLaravelAuthAuthGroupSafe(t *testing.T) {
	findings := scanFixture(t, "routes.php", `Route::middleware('auth:api')->get('/admin', [AdminController::class, 'index']);`)
	if hasFinding(findings, "PF-LARAVEL-AUTH-001") {
		t.Fatalf("route guarded by auth: guard should not trigger missing-auth rule: %+v", findings)
	}
}

func TestLaravelAuthPublicRouteSafe(t *testing.T) {
	findings := scanFixture(t, "routes.php", `Route::get('/posts/{id}', [PostController::class, 'show']);`)
	if hasFinding(findings, "PF-LARAVEL-AUTH-001") {
		t.Fatalf("public route should not trigger missing-auth rule: %+v", findings)
	}
}

func TestLaravelDeserRuleMaturityAndSeverity(t *testing.T) {
	r, ok := ruleByID("PF-LARAVEL-DESER-001")
	if !ok {
		t.Fatal("PF-LARAVEL-DESER-001 rule not found")
	}
	if r.Maturity != frameworks.MaturityBeta {
		t.Fatalf("deser rule maturity = %s, want beta", r.Maturity)
	}
	if r.Severity != analysis.SeverityCritical {
		t.Fatalf("deser rule severity = %s, want critical", r.Severity)
	}
	if r.Confidence != analysis.ConfidenceHigh {
		t.Fatalf("deser rule confidence = %v, want high", r.Confidence)
	}
	if r.CWE != "CWE-502" {
		t.Fatalf("deser rule CWE = %s, want CWE-502", r.CWE)
	}
}

func TestLaravelAuthRuleMaturityAndSeverity(t *testing.T) {
	r, ok := ruleByID("PF-LARAVEL-AUTH-001")
	if !ok {
		t.Fatal("PF-LARAVEL-AUTH-001 rule not found")
	}
	if r.Maturity != frameworks.MaturityBeta {
		t.Fatalf("auth rule maturity = %s, want beta", r.Maturity)
	}
	if r.Severity != analysis.SeverityMedium {
		t.Fatalf("auth rule severity = %s, want medium (not high/critical)", r.Severity)
	}
	if r.Confidence != analysis.ConfidenceLow {
		t.Fatalf("auth rule confidence = %v, want low", r.Confidence)
	}
	if r.CWE != "CWE-306" {
		t.Fatalf("auth rule CWE = %s, want CWE-306", r.CWE)
	}
	if len(r.SafePatterns) == 0 {
		t.Fatal("auth rule should declare safe patterns for middleware/auth guards")
	}
}

func TestLaravelDeserFindingSeverityCritical(t *testing.T) {
	findings := scanFixture(t, "ImportController.php", `$data = unserialize($request->input('payload'));`)
	f, ok := findingFor(findings, "PF-LARAVEL-DESER-001")
	if !ok {
		t.Fatalf("expected deserialization finding, got %+v", findings)
	}
	if f.Severity != analysis.SeverityCritical {
		t.Fatalf("deser finding severity = %s, want critical", f.Severity)
	}
}

func TestLaravelAuthFindingSeverityMedium(t *testing.T) {
	findings := scanFixture(t, "routes.php", `Route::get('/admin', [AdminController::class, 'index']);`)
	f, ok := findingFor(findings, "PF-LARAVEL-AUTH-001")
	if !ok {
		t.Fatalf("expected missing-auth finding, got %+v", findings)
	}
	if f.Severity != analysis.SeverityMedium {
		t.Fatalf("auth finding severity = %s, want medium", f.Severity)
	}
}

func TestLaravelSourcesIncludeNewEntries(t *testing.T) {
	srcs := New().Sources()
	want := map[string]bool{"$request->get": false, "Input::get": false, "request()": false, "$_COOKIE": false}
	for _, s := range srcs {
		if _, ok := want[s.FuncName]; ok {
			want[s.FuncName] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("source %q not registered in pack", name)
		}
	}
}

func TestLaravelSinksIncludeNewEntries(t *testing.T) {
	sinks := New().Sinks()
	want := map[string]bool{"whereRaw": false, "selectRaw": false, "unserialize": false, "redirect": false, "Storage::put": false}
	for _, s := range sinks {
		if _, ok := want[s.FuncName]; ok {
			want[s.FuncName] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("sink %q not registered in pack", name)
		}
	}
}

func TestLaravelSanitizersIncludeNewEntries(t *testing.T) {
	sans := New().Sanitizers()
	want := map[string]bool{"validator": false, "bcrypt": false, "e(": false}
	for _, s := range sans {
		if _, ok := want[s.FuncName]; ok {
			want[s.FuncName] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("sanitizer %q not registered in pack", name)
		}
	}
}
