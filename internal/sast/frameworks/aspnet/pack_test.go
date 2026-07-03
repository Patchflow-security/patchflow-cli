package aspnet

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

func scanFixture(t *testing.T, content string) []analysis.Finding {
	t.Helper()
	return scanFixtureExt(t, ".cs", "UsersController.cs", content)
}

// scanFixtureExt writes content to a temp file with the given extension and
// filename, then runs the ASP.NET pack's matchable rules against it. This is
// needed for template rules (e.g. .cshtml) that only apply to specific file
// types.
func scanFixtureExt(t *testing.T, ext, name, content string) []analysis.Finding {
	t.Helper()
	root := t.TempDir()
	target := filepath.Join(root, name+ext)
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

func TestASPNETPackContract(t *testing.T) {
	pack := New()
	if pack.Name() != "aspnet" || pack.Language() != "csharp" {
		t.Fatalf("unexpected pack identity: %s/%s", pack.Name(), pack.Language())
	}
	if len(pack.Rules()) == 0 || len(pack.Sources()) == 0 || len(pack.Sinks()) == 0 {
		t.Fatal("pack contract should expose rules and catalogs")
	}
}

func TestASPNETSQLiVulnerable(t *testing.T) {
	findings := scanFixture(t, `db.Users.FromSqlRaw("SELECT * FROM Users WHERE id = " + Request.Query["id"]);`)
	if !hasFinding(findings, "PF-ASPNET-SQLI-001") {
		t.Fatalf("expected SQLi finding, got %+v", findings)
	}
}

func TestASPNETRedirectSafe(t *testing.T) {
	findings := scanFixture(t, `return LocalRedirect(Request.Query["returnUrl"]);`)
	if hasFinding(findings, "PF-ASPNET-REDIRECT-001") {
		t.Fatalf("LocalRedirect should suppress open redirect: %+v", findings)
	}
}

// === PF-ASPNET-SQLI-002: FromSqlRaw with string interpolation of user input ===

func TestASPNETSQLiFromSqlRawInterpolationVulnerable(t *testing.T) {
	findings := scanFixture(t, `var users = context.Users.FromSqlRaw($"SELECT * FROM Users WHERE name = {Request.Query["name"]}");`)
	if !hasFinding(findings, "PF-ASPNET-SQLI-002") {
		t.Fatalf("expected PF-ASPNET-SQLI-002 for interpolated FromSqlRaw, got %+v", findings)
	}
}

func TestASPNETSQLiFromSqlInterpolatedSafe(t *testing.T) {
	findings := scanFixture(t, `var users = context.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE name = {name}");`)
	if hasFinding(findings, "PF-ASPNET-SQLI-002") {
		t.Fatal("PF-ASPNET-SQLI-002 should not fire on FromSqlInterpolated")
	}
}

// === PF-ASPNET-XSS-002: @Html.Raw with request data (Razor templates) ===

func TestASPNETXSSHtmlRawRequestVulnerable(t *testing.T) {
	findings := scanFixtureExt(t, ".cshtml", "Index", `@Html.Raw(Request.Query["html"])`)
	if !hasFinding(findings, "PF-ASPNET-XSS-002") {
		t.Fatalf("expected PF-ASPNET-XSS-002 for @Html.Raw with request data, got %+v", findings)
	}
}

func TestASPNETXSSHtmlEncodeSafe(t *testing.T) {
	findings := scanFixtureExt(t, ".cshtml", "Index", `@Html.Encode(Model.Name)`)
	if hasFinding(findings, "PF-ASPNET-XSS-002") {
		t.Fatal("PF-ASPNET-XSS-002 should not fire on @Html.Encode")
	}
}

// === PF-ASPNET-DESER-001: BinaryFormatter.Deserialize ===

func TestASPNETDeserBinaryFormatterVulnerable(t *testing.T) {
	findings := scanFixture(t, `var obj = new BinaryFormatter().Deserialize(stream);`)
	if !hasFinding(findings, "PF-ASPNET-DESER-001") {
		t.Fatalf("expected PF-ASPNET-DESER-001 for BinaryFormatter.Deserialize, got %+v", findings)
	}
}

func TestASPNETDeserBinaryFormatterSplitVulnerable(t *testing.T) {
	// BinaryFormatter deserialization is dangerous regardless of whether
	// the formatter is created and called on the same line or split across
	// statements. The pattern matches both forms.
	findings := scanFixture(t, `var bf = new BinaryFormatter(); var obj = bf.Deserialize(stream);`)
	if !hasFinding(findings, "PF-ASPNET-DESER-001") {
		t.Fatalf("expected PF-ASPNET-DESER-001 for split BinaryFormatter usage, got %+v", findings)
	}
}

func TestASPNETDeserJsonSerializerSafe(t *testing.T) {
	findings := scanFixture(t, `var obj = JsonSerializer.Deserialize<User>(jsonString);`)
	if hasFinding(findings, "PF-ASPNET-DESER-001") {
		t.Fatal("PF-ASPNET-DESER-001 should not fire on JsonSerializer.Deserialize")
	}
}

// === PF-ASPNET-CMDI-001: Process.Start with user input ===

func TestASPNETCmdInjectionVulnerable(t *testing.T) {
	findings := scanFixture(t, `Process.Start(Request.Query["cmd"]);`)
	if !hasFinding(findings, "PF-ASPNET-CMDI-001") {
		t.Fatalf("expected PF-ASPNET-CMDI-001 for Process.Start with request data, got %+v", findings)
	}
}

func TestASPNETCmdInjectionSafeStaticArgs(t *testing.T) {
	findings := scanFixture(t, `Process.Start("ls", "-la");`)
	if hasFinding(findings, "PF-ASPNET-CMDI-001") {
		t.Fatal("PF-ASPNET-CMDI-001 should not fire on static process arguments")
	}
}

// === PF-ASPNET-PATH-001: Path.Combine with user input ===

func TestASPNETPathTraversalVulnerable(t *testing.T) {
	findings := scanFixture(t, `var path = Path.Combine(baseDir, Request.Query["file"]);`)
	if !hasFinding(findings, "PF-ASPNET-PATH-001") {
		t.Fatalf("expected PF-ASPNET-PATH-001 for Path.Combine with request data, got %+v", findings)
	}
}

func TestASPNETPathTraversalSafeStaticArg(t *testing.T) {
	findings := scanFixture(t, `var path = Path.Combine(baseDir, "config.json");`)
	if hasFinding(findings, "PF-ASPNET-PATH-001") {
		t.Fatal("PF-ASPNET-PATH-001 should not fire on static Path.Combine argument")
	}
}
