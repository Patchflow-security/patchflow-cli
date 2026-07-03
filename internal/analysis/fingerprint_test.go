package analysis

import (
	"strings"
	"testing"
)

func TestNormalizePath(t *testing.T) {
	cases := map[string]string{
		"foo/bar.go":      "foo/bar.go",
		"foo\\bar.go":     "foo/bar.go",
		"./foo/../bar.go": "bar.go",
		"Foo/Bar.GO":      "foo/bar.go",
		"":                "",
	}
	for in, want := range cases {
		if got := NormalizePath(in); got != want {
			t.Errorf("NormalizePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeSnippet(t *testing.T) {
	cases := map[string]string{
		"  eval(input)  ":      "eval(input)",
		"eval(  input  )":      "eval( input )",
		"  foo\n\tbar  baz  ":  "foo bar baz",
		"":                     "",
		"EVAL(x)":              "eval(x)",
	}
	for in, want := range cases {
		if got := NormalizeSnippet(in); got != want {
			t.Errorf("NormalizeSnippet(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSemanticFingerprintStableAcrossLineShift(t *testing.T) {
	base := Finding{
		Type:      TypeSAST,
		Analyzer:  "gosast-embedded",
		RuleID:    "G104",
		FilePath:  "app/handler.go",
		LineStart: 42,
		Evidence:  "resp, err := http.Get(url)",
	}
	shifted := base
	shifted.LineStart = 99 // code moved down due to unrelated edits

	fpBase := ComputeSemanticFingerprint(base)
	fpShift := ComputeSemanticFingerprint(shifted)
	if fpBase != fpShift {
		t.Errorf("semantic fingerprint should be line-independent: base=%s shifted=%s", fpBase, fpShift)
	}
	if fpBase == "" {
		t.Error("semantic fingerprint should not be empty")
	}
}

func TestSemanticFingerprintDifferentForDifferentEvidence(t *testing.T) {
	a := Finding{Type: TypeSAST, Analyzer: "gosast", RuleID: "G104", FilePath: "a.go", Evidence: "http.Get(url)"}
	b := Finding{Type: TypeSAST, Analyzer: "gosast", RuleID: "G104", FilePath: "a.go", Evidence: "http.Get(other)"}
	if ComputeSemanticFingerprint(a) == ComputeSemanticFingerprint(b) {
		t.Error("different evidence should produce different semantic fingerprints")
	}
}

func TestSemanticFingerprintSCAUsesPackage(t *testing.T) {
	a := Finding{Type: TypeSCA, Analyzer: "osv", RuleID: "OSV-1", FilePath: "go.mod", PackageName: "logrus", PackageVersion: "1.2.0", CVEID: "CVE-2024-1"}
	b := Finding{Type: TypeSCA, Analyzer: "osv", RuleID: "OSV-1", FilePath: "go.mod", PackageName: "logrus", PackageVersion: "1.2.1", CVEID: "CVE-2024-1"}
	if ComputeSemanticFingerprint(a) == ComputeSemanticFingerprint(b) {
		t.Error("different package versions should produce different semantic fingerprints")
	}
}

func TestLocationFingerprintLineSensitive(t *testing.T) {
	a := Finding{Type: TypeSAST, Analyzer: "gosast", RuleID: "G104", FilePath: "a.go", Evidence: "x", LineStart: 10}
	b := a
	b.LineStart = 20
	if ComputeLocationFingerprint(a) == ComputeLocationFingerprint(b) {
		t.Error("location fingerprint should differ when line changes")
	}
}

func TestPopulateFingerprintsIdempotent(t *testing.T) {
	findings := []Finding{
		{Type: TypeSAST, Analyzer: "gosast", RuleID: "G104", FilePath: "a.go", Evidence: "x"},
		{Type: TypeSecret, Analyzer: "secrets", RuleID: "SECRET-aws", FilePath: "b.go", Evidence: "AKIA..."},
	}
	PopulateFingerprints(findings)
	first := findings[0].SemanticFingerprint
	// Second call should not overwrite.
	findings[0].SemanticFingerprint = "preset"
	PopulateFingerprints(findings)
	if findings[0].SemanticFingerprint != "preset" {
		t.Error("PopulateFingerprints should not overwrite existing fingerprints")
	}
	if first == "" {
		t.Error("first population should set a non-empty fingerprint")
	}
}

func TestShortHashDeterministic(t *testing.T) {
	if shortHash("abc") != shortHash("abc") {
		t.Error("shortHash should be deterministic")
	}
	if shortHash("abc") == shortHash("abcd") {
		t.Error("shortHash should differ for different inputs")
	}
	if len(shortHash("abc")) != 16 {
		t.Error("shortHash should return 16 hex chars")
	}
}

func TestItoa(t *testing.T) {
	cases := map[int]string{0: "0", 1: "1", 42: "42", -7: "-7", 12345: "12345"}
	for in, want := range cases {
		if got := itoa(in); got != want {
			t.Errorf("itoa(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestFingerprintHexOnly(t *testing.T) {
	fp := ComputeSemanticFingerprint(Finding{Type: TypeSAST, Analyzer: "x", RuleID: "R", FilePath: "f.go", Evidence: "e"})
	for _, c := range fp {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Errorf("fingerprint should be hex only, got %q", fp)
			break
		}
	}
}

func TestDedupFingerprintBaseIPSameLine(t *testing.T) {
	base := Finding{RuleID: "TP-JS001", FilePath: "src/app.js", LineStart: 42, Evidence: "eval(req.body)"}
	ip := Finding{RuleID: "TP-JS001-IP", FilePath: "src/app.js", LineStart: 42, Evidence: "eval(req.body)"}
	fpBase := ComputeDedupFingerprint(base)
	fpIP := ComputeDedupFingerprint(ip)
	if fpBase != fpIP {
		t.Errorf("base and IP variants on same line should have same dedup fingerprint: %s vs %s", fpBase, fpIP)
	}
}

func TestDedupFingerprintDifferentLinesNotEqual(t *testing.T) {
	f1 := Finding{RuleID: "TP-JS001", FilePath: "src/app.js", LineStart: 42, Evidence: "eval(x)"}
	f2 := Finding{RuleID: "TP-JS001", FilePath: "src/app.js", LineStart: 100, Evidence: "eval(x)"}
	if ComputeDedupFingerprint(f1) == ComputeDedupFingerprint(f2) {
		t.Error("findings on different lines should have different dedup fingerprints")
	}
}

func TestDedupFingerprintStableAcrossLineShift(t *testing.T) {
	// Semantic fingerprint should NOT include line number (stable across shifts)
	f1 := Finding{RuleID: "TP-JS001", FilePath: "src/app.js", LineStart: 42, Evidence: "eval(req.body)"}
	f2 := Finding{RuleID: "TP-JS001", FilePath: "src/app.js", LineStart: 45, Evidence: "eval(req.body)"}
	if ComputeSemanticFingerprint(f1) != ComputeSemanticFingerprint(f2) {
		t.Error("semantic fingerprint should be stable across line shifts")
	}
}

func TestIssueGroupIDSameFileSameRule(t *testing.T) {
	f1 := Finding{RuleID: "PF-GRAPHQL-AUTH-001", FilePath: "core/views.py", LineStart: 141, Title: "GraphQL IDOR"}
	f2 := Finding{RuleID: "PF-GRAPHQL-AUTH-001", FilePath: "core/views.py", LineStart: 148, Title: "GraphQL IDOR"}
	// Same rule + file should produce same base group ID
	gid1 := ComputeIssueGroupID(f1)
	gid2 := ComputeIssueGroupID(f2)
	if gid1 != gid2 {
		t.Errorf("same rule+file should produce same base group ID: %s vs %s", gid1, gid2)
	}
}

func TestIssueGroupIDDifferentRules(t *testing.T) {
	f1 := Finding{RuleID: "PF-GRAPHQL-AUTH-001", FilePath: "core/views.py", LineStart: 141}
	f2 := Finding{RuleID: "PF-GRAPHQL-SQLI-001", FilePath: "core/views.py", LineStart: 142}
	if ComputeIssueGroupID(f1) == ComputeIssueGroupID(f2) {
		t.Error("different rules should produce different group IDs")
	}
}

func TestExtractFunctionName(t *testing.T) {
	cases := map[string]string{
		"GraphQL IDOR in EditPaste.mutate":        "editpaste.mutate",
		"SQL injection in resolve_pastes":         "resolve_pastes",
		"XSS in render_template (Jinja)":          "render_template",
		"No function name here":                   "",
		"":                                        "",
	}
	for input, want := range cases {
		got := ExtractFunctionName(input, "")
		if got != want {
			t.Errorf("ExtractFunctionName(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestPopulateFingerprintsIncludesDedup(t *testing.T) {
	findings := []Finding{
		{RuleID: "TP-JS001", FilePath: "src/app.js", LineStart: 42, Evidence: "eval(x)"},
	}
	PopulateFingerprints(findings)
	if findings[0].DedupFingerprint == "" {
		t.Error("PopulateFingerprints should set DedupFingerprint")
	}
}
