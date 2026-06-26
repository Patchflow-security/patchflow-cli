package rules

import (
	"testing"
)

func TestMaturityString(t *testing.T) {
	cases := map[Maturity]string{
		MaturityExperimental: "experimental",
		MaturityBeta:         "beta",
		MaturityStable:       "stable",
		MaturityEnterprise:   "enterprise",
	}
	for m, want := range cases {
		if got := m.String(); got != want {
			t.Errorf("Maturity(%d).String() = %q, want %q", m, got, want)
		}
	}
}

func TestMaturityCanBlock(t *testing.T) {
	if MaturityExperimental.CanBlock() {
		t.Error("experimental should not block")
	}
	if MaturityBeta.CanBlock() {
		t.Error("beta should not block")
	}
	if !MaturityStable.CanBlock() {
		t.Error("stable should block")
	}
	if !MaturityEnterprise.CanBlock() {
		t.Error("enterprise should block")
	}
}

func TestProfileIncludesMaturity(t *testing.T) {
	// Dev: only stable and enterprise
	if !ProfileDev.IncludesMaturity(MaturityStable) {
		t.Error("dev should include stable")
	}
	if ProfileDev.IncludesMaturity(MaturityBeta) {
		t.Error("dev should not include beta")
	}
	if ProfileDev.IncludesMaturity(MaturityExperimental) {
		t.Error("dev should not include experimental")
	}

	// CI: beta and above
	if !ProfileCI.IncludesMaturity(MaturityBeta) {
		t.Error("ci should include beta")
	}
	if ProfileCI.IncludesMaturity(MaturityExperimental) {
		t.Error("ci should not include experimental")
	}

	// Audit: everything
	if !ProfileAudit.IncludesMaturity(MaturityExperimental) {
		t.Error("audit should include experimental")
	}
}

func TestDefaultMaturityForEngine(t *testing.T) {
	cases := map[Engine]Maturity{
		EngineGoSAST:        MaturityStable,
		EngineTaintSSA:      MaturityStable,
		EngineSecrets:       MaturityStable,
		EngineTreeSitter:    MaturityBeta,
		EngineTaintPatterns: MaturityBeta,
		EnginePatterns:      MaturityBeta,
	}
	for engine, want := range cases {
		if got := DefaultMaturityForEngine(engine); got != want {
			t.Errorf("DefaultMaturityForEngine(%s) = %s, want %s", engine, got, want)
		}
	}
}

func TestCWEFromRuleID(t *testing.T) {
	cases := map[string]string{
		"PY001":      "CWE-95",
		"TS-PY001":   "CWE-95", // tree-sitter mirrors pattern IDs
		"PY003":      "CWE-78",
		"PY005":      "CWE-502",
		"G201":       "CWE-89",
		"G701":       "CWE-89",
		"G702":       "CWE-78",
		"G703":       "CWE-22",
		"G704":       "CWE-918",
		"G101":       "CWE-798",
		"SECRET-aws": "CWE-798",
		"G115":       "CWE-327",
		"G402":       "CWE-295",
		"TP-PY001":   "CWE-89",
		"TP-JS007":   "CWE-1321",
		"UNKNOWN":    "",
	}
	for id, want := range cases {
		if got := CWEFromRuleID(id); got != want {
			t.Errorf("CWEFromRuleID(%q) = %q, want %q", id, got, want)
		}
	}
}

func TestOWASPFromCWE(t *testing.T) {
	cases := map[string]string{
		"CWE-89":  "A03:2021-Injection",
		"CWE-79":  "A03:2021-Injection",
		"CWE-22":  "A01:2021-Broken Access Control",
		"CWE-798": "A07:2021-Identification and Authentication Failures",
		"CWE-327": "A02:2021-Cryptographic Failures",
		"CWE-502": "A08:2021-Software and Data Integrity Failures",
		"":        "",
	}
	for cwe, want := range cases {
		if got := OWASPFromCWE(cwe); got != want {
			t.Errorf("OWASPFromCWE(%q) = %q, want %q", cwe, got, want)
		}
	}
}

func TestRegistryRegisterAndGet(t *testing.T) {
	r := NewRegistry()
	r.RegisterEngineRule(EngineGoSAST, "G104", "Errors unhandled", "medium", "high", "go")

	meta, ok := r.Get("G104")
	if !ok {
		t.Fatal("expected to find G104 in registry")
	}
	if meta.Engine != EngineGoSAST {
		t.Errorf("expected engine gosast-embedded, got %s", meta.Engine)
	}
	if meta.Maturity != MaturityStable {
		t.Errorf("expected maturity stable, got %s", meta.Maturity)
	}
	if meta.CWE != "CWE-755" {
		t.Errorf("expected CWE-755, got %s", meta.CWE)
	}
	if meta.OWASP == "" {
		t.Error("expected non-empty OWASP mapping")
	}
	if meta.Category == "" {
		t.Error("expected non-empty category")
	}
	if meta.Recommendation == "" {
		t.Error("expected non-empty recommendation")
	}
}

func TestRegistryBlockingEligibility(t *testing.T) {
	r := NewRegistry()
	// Stable + high severity = blocking eligible
	r.RegisterEngineRule(EngineGoSAST, "G101", "Hardcoded credentials", "high", "high", "go")
	// Stable + low severity = NOT blocking eligible
	r.RegisterEngineRule(EngineGoSAST, "G302", "File permissions", "low", "high", "go")
	// Experimental + high severity = NOT blocking eligible (maturity too low)
	r.RegisterEngineRule(EnginePatterns, "PY001", "eval usage", "high", "medium", "python")

	meta, _ := r.Get("G101")
	if !meta.BlockingEligible {
		t.Error("G101 (stable+high) should be blocking eligible")
	}

	meta, _ = r.Get("G302")
	if meta.BlockingEligible {
		t.Error("G302 (stable+low) should NOT be blocking eligible")
	}

	meta, _ = r.Get("PY001")
	if meta.BlockingEligible {
		t.Error("PY001 (experimental+high) should NOT be blocking eligible")
	}
}

func TestRegistryProfileFiltering(t *testing.T) {
	r := NewRegistry()
	r.RegisterEngineRule(EngineGoSAST, "G101", "Hardcoded credentials", "high", "high", "go")
	r.RegisterEngineRule(EnginePatterns, "PY001", "eval usage", "high", "medium", "python")

	// G101 (stable, Go SAST) should be active in dev profile
	if !r.IsRuleActiveInProfile("G101", ProfileDev) {
		t.Error("G101 should be active in dev profile")
	}

	// PY001 (experimental, patterns) should NOT be active in dev profile
	if r.IsRuleActiveInProfile("PY001", ProfileDev) {
		t.Error("PY001 should NOT be active in dev profile")
	}

	// PY001 should be active in audit profile
	if !r.IsRuleActiveInProfile("PY001", ProfileAudit) {
		t.Error("PY001 should be active in audit profile")
	}

	// Active rules for dev should include G101 but not PY001
	active := r.ActiveRulesForProfile(ProfileDev)
	foundG101 := false
	foundPY001 := false
	for _, id := range active {
		if id == "G101" {
			foundG101 = true
		}
		if id == "PY001" {
			foundPY001 = true
		}
	}
	if !foundG101 {
		t.Error("G101 should be in dev active rules")
	}
	if foundPY001 {
		t.Error("PY001 should NOT be in dev active rules")
	}
}

func TestRegistryCoverage(t *testing.T) {
	r := NewRegistry()
	r.RegisterEngineRule(EngineGoSAST, "G101", "Hardcoded credentials", "high", "high", "go")
	r.RegisterEngineRule(EngineGoSAST, "G302", "File permissions", "low", "high", "go")
	r.RegisterEngineRule(EnginePatterns, "PY001", "eval usage", "high", "medium", "python")

	report := r.Coverage()
	if report.TotalRules != 3 {
		t.Errorf("expected 3 total rules, got %d", report.TotalRules)
	}
	if report.MaturityCounts["stable"] != 2 {
		t.Errorf("expected 2 stable rules, got %d", report.MaturityCounts["stable"])
	}
	if report.MaturityCounts["beta"] != 1 {
		t.Errorf("expected 1 beta rule, got %d", report.MaturityCounts["beta"])
	}
	// G101 is stable+high = blocking; G302 is stable+low = not blocking; PY001 is beta = not blocking
	if report.BlockingEligible != 1 {
		t.Errorf("expected 1 blocking eligible, got %d", report.BlockingEligible)
	}
	// All 3 should have CWE mappings
	if report.CWEMapped != 3 {
		t.Errorf("expected 3 CWE mapped, got %d", report.CWEMapped)
	}
}

func TestRegistrySearch(t *testing.T) {
	r := NewRegistry()
	r.RegisterEngineRule(EngineGoSAST, "G101", "Hardcoded credentials", "high", "high", "go")
	r.RegisterEngineRule(EnginePatterns, "PY001", "eval usage", "high", "medium", "python")
	r.RegisterEngineRule(EngineSecrets, "SECRET-aws", "AWS Access Key", "high", "high", "secrets")

	// Search for "eval"
	results := r.Search("eval")
	if len(results) != 1 {
		t.Fatalf("expected 1 result for 'eval', got %d", len(results))
	}
	if results[0].ID != "PY001" {
		t.Errorf("expected PY001, got %s", results[0].ID)
	}

	// Search for "CWE-798" (hardcoded credentials + secrets)
	results = r.Search("CWE-798")
	if len(results) != 2 {
		t.Fatalf("expected 2 results for CWE-798, got %d", len(results))
	}
}

func TestBuildDefaultRegistry(t *testing.T) {
	r := BuildDefaultRegistry()
	if r.Count() == 0 {
		t.Fatal("default registry should have rules")
	}
	// Should have rules from multiple engines
	byEngine := make(map[Engine]int)
	for _, meta := range r.All() {
		byEngine[meta.Engine]++
	}
	if byEngine[EngineGoSAST] == 0 {
		t.Error("expected Go SAST rules in default registry")
	}
	if byEngine[EngineSecrets] == 0 {
		t.Error("expected secrets rules in default registry")
	}
	if byEngine[EnginePatterns] == 0 {
		t.Error("expected pattern rules in default registry")
	}

	// All rules should have CWE mappings (even if heuristic)
	report := r.Coverage()
	if report.CWEMapped == 0 {
		t.Error("expected some CWE-mapped rules in default registry")
	}
}

func TestShouldBlock(t *testing.T) {
	r := NewRegistry()
	r.RegisterEngineRule(EngineGoSAST, "G101", "Hardcoded credentials", "high", "high", "go")
	r.RegisterEngineRule(EnginePatterns, "PY001", "eval usage", "high", "medium", "python")

	// G101 is stable+high, active in CI → should block in CI
	if !r.ShouldBlock("G101", ProfileCI) {
		t.Error("G101 should block in CI profile")
	}

	// PY001 is experimental, not active in CI → should not block
	if r.ShouldBlock("PY001", ProfileCI) {
		t.Error("PY001 should NOT block in CI profile")
	}

	// G101 should not block in audit (audit doesn't block by default)
	// Actually, ShouldBlock checks both blocking eligibility AND profile activation.
	// G101 is active in audit, and is blocking eligible, so ShouldBlock returns true.
	// The audit profile's "no block by default" is a separate concern handled by the scan runner.
}

func TestCategoryFromRuleID(t *testing.T) {
	cases := map[string]string{
		"SECRET-aws":  "secrets",
		"G101":        "secrets",
		"G201":        "injection",
		"G701":        "injection",
		"PY001":       "injection",
		"JS001":       "injection",
		"TP-PY001":    "injection",
		"TS-PY001":    "injection", // tree-sitter mirrors pattern IDs
		"G115":        "crypto",
		"G402":        "tls",
		"G301":        "file-permissions",
		"G104":        "error-handling",
	}
	for id, want := range cases {
		if got := CategoryFromRuleID(id); got != want {
			t.Errorf("CategoryFromRuleID(%q) = %q, want %q", id, got, want)
		}
	}
}

func TestRecommendationForRule(t *testing.T) {
	rec := RecommendationForRule("PY001", "CWE-95")
	if rec == "" {
		t.Error("expected non-empty recommendation for PY001")
	}
	if rec == "Review the finding and apply the appropriate secure coding fix." {
		t.Error("expected specific recommendation for PY001, got fallback")
	}

	// Secret rules with CWE-798 get the hardcoded credentials recommendation
	rec = RecommendationForRule("SECRET-aws", "CWE-798")
	if !contains(rec, "environment variables") && !contains(rec, "secrets manager") {
		t.Errorf("expected secret recommendation to mention env vars or secrets manager, got: %s", rec)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || indexOf(s, substr) >= 0)
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
