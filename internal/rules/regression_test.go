package rules

import (
	"strings"
	"testing"
)

// TestRuleRegressionCorpus validates that the most important rules have
// proper metadata for a regression corpus. This is the governance test:
// it verifies that blocking-eligible rules have CWE mappings, OWASP
// mappings, recommendations, and are assigned to the correct profiles.
//
// Per-rule positive/negative/FP test cases are in the individual scanner
// engine test files. This test focuses on the governance layer: ensuring
// that the metadata registry correctly classifies rules for production use.
func TestRuleRegressionCorpus(t *testing.T) {
	r := BuildDefaultRegistry()

	// Top rules that should be production-mature (stable or enterprise).
	// These are the rules that can block PRs in CI mode.
	// Note: blocking eligibility requires BOTH stable+ maturity AND high/critical severity.
	productionRules := []struct {
		id              string
		minMaturity     Maturity
		requireCWE      bool
		requireOWASP    bool
		requireBlocking bool
	}{
		// Go SAST rules — should be stable with CWE mapping
		{"G101", MaturityStable, true, true, true},   // Hardcoded credentials (high)
		{"G104", MaturityStable, true, true, false},  // Unhandled errors (medium)
		{"G115", MaturityStable, true, true, false},  // Integer overflow (medium)
		{"G116", MaturityStable, true, true, false},  // Trojan Source (medium)
		{"G201", MaturityStable, true, true, false},  // SQL injection concat (medium)
		{"G202", MaturityStable, true, true, false},  // SQL injection format (medium)
		{"G204", MaturityStable, true, true, false},  // Subprocess with variable (medium)
		{"G402", MaturityStable, true, true, false},  // TLS settings (medium)

		// Taint SSA rules — should be stable with CWE mapping
		{"G701", MaturityStable, true, true, false},  // SQL injection (medium)
		{"G702", MaturityStable, true, true, false},  // Command injection (medium)
		{"G703", MaturityStable, true, true, false},  // Path traversal (medium)
		{"G704", MaturityStable, true, true, false},  // SSRF (medium)

		// Secrets rules — should be stable (high severity = blocking)
		{"SECRET-AWS Access Key ID", MaturityStable, true, true, true},
		{"SECRET-GitHub Personal Access Token", MaturityStable, true, true, true},
		{"SECRET-RSA Private Key", MaturityStable, true, true, true},
	}

	for _, tc := range productionRules {
		t.Run(tc.id, func(t *testing.T) {
			meta, ok := r.Get(tc.id)
			if !ok {
				t.Fatalf("rule %s not found in registry", tc.id)
			}

			if meta.Maturity < tc.minMaturity {
				t.Errorf("rule %s: maturity %s < expected %s", tc.id, meta.Maturity, tc.minMaturity)
			}

			if tc.requireCWE && meta.CWE == "" {
				t.Errorf("rule %s: expected CWE mapping, got empty", tc.id)
			}

			if tc.requireOWASP && meta.OWASP == "" {
				t.Errorf("rule %s: expected OWASP mapping, got empty", tc.id)
			}

			if tc.requireBlocking && !meta.BlockingEligible {
				t.Errorf("rule %s: expected blocking eligible, got false", tc.id)
			}

			// All production rules should have a recommendation
			if meta.Recommendation == "" {
				t.Errorf("rule %s: expected non-empty recommendation", tc.id)
			}

			// All production rules should have a category
			if meta.Category == "" {
				t.Errorf("rule %s: expected non-empty category", tc.id)
			}

			// All production rules should be active in CI profile
			if !r.IsRuleActiveInProfile(tc.id, ProfileCI) {
				t.Errorf("rule %s: expected to be active in CI profile", tc.id)
			}
		})
	}
}

// TestExperimentalRulesNotBlocking verifies that experimental-maturity rules
// (pattern regex rules) are NOT blocking eligible and are NOT active in
// dev/pr/ci profiles — only in audit.
func TestExperimentalRulesNotBlocking(t *testing.T) {
	r := BuildDefaultRegistry()

	// Pattern rules should be experimental maturity
	patternRules := r.ByEngine(EnginePatterns)
	if len(patternRules) == 0 {
		t.Fatal("expected pattern rules in registry")
	}

	for _, meta := range patternRules {
		t.Run(meta.ID, func(t *testing.T) {
			if meta.Maturity != MaturityBeta {
				t.Errorf("pattern rule %s: expected maturity beta, got %s", meta.ID, meta.Maturity)
			}
			if meta.BlockingEligible {
				t.Errorf("pattern rule %s: should NOT be blocking eligible", meta.ID)
			}
			// Should NOT be active in dev profile
			if r.IsRuleActiveInProfile(meta.ID, ProfileDev) {
				t.Errorf("pattern rule %s: should NOT be active in dev profile", meta.ID)
			}
			// SHOULD be active in ci profile (beta maturity, non-blocking)
			if !r.IsRuleActiveInProfile(meta.ID, ProfileCI) {
				t.Errorf("pattern rule %s: should be active in ci profile", meta.ID)
			}
			// SHOULD be active in audit profile
			if !r.IsRuleActiveInProfile(meta.ID, ProfileAudit) {
				t.Errorf("pattern rule %s: should be active in audit profile", meta.ID)
			}
		})
	}
}

// TestBetaRulesInCI verifies that beta-maturity rules (tree-sitter, taint
// patterns) are active in CI profile (as warnings) but NOT blocking eligible.
func TestBetaRulesInCI(t *testing.T) {
	r := BuildDefaultRegistry()

	betaEngines := []Engine{EngineTreeSitter, EngineTaintPatterns}
	for _, engine := range betaEngines {
		engineRules := r.ByEngine(engine)
		if len(engineRules) == 0 {
			continue
		}

		for _, meta := range engineRules {
			t.Run(string(engine)+"_"+meta.ID, func(t *testing.T) {
				if meta.Maturity != MaturityBeta {
					t.Errorf("rule %s: expected maturity beta, got %s", meta.ID, meta.Maturity)
				}
				// Beta rules should NOT be blocking eligible
				if meta.BlockingEligible {
					t.Errorf("rule %s: beta rules should NOT be blocking eligible", meta.ID)
				}
				// Should be active in CI profile (as warnings)
				if !r.IsRuleActiveInProfile(meta.ID, ProfileCI) {
					t.Errorf("rule %s: beta rules should be active in CI profile", meta.ID)
				}
				// Should be active in audit profile
				if !r.IsRuleActiveInProfile(meta.ID, ProfileAudit) {
					t.Errorf("rule %s: should be active in audit profile", meta.ID)
				}
			})
		}
	}
}

// TestStableRulesInAllProfiles verifies that stable-maturity rules (Go SAST,
// taint SSA, secrets) are active in all profiles including dev.
func TestStableRulesInAllProfiles(t *testing.T) {
	r := BuildDefaultRegistry()

	stableEngines := []Engine{EngineGoSAST, EngineTaintSSA, EngineSecrets}
	for _, engine := range stableEngines {
		engineRules := r.ByEngine(engine)
		if len(engineRules) == 0 {
			continue
		}

		for _, meta := range engineRules {
			t.Run(string(engine)+"_"+meta.ID, func(t *testing.T) {
				if meta.Maturity != MaturityStable {
					t.Errorf("rule %s: expected maturity stable, got %s", meta.ID, meta.Maturity)
				}
				// Should be active in dev profile
				if !r.IsRuleActiveInProfile(meta.ID, ProfileDev) {
					t.Errorf("rule %s: stable rules should be active in dev profile", meta.ID)
				}
				// Should be active in CI profile
				if !r.IsRuleActiveInProfile(meta.ID, ProfileCI) {
					t.Errorf("rule %s: stable rules should be active in CI profile", meta.ID)
				}
			})
		}
	}
}

// TestCoverageReportConsistency verifies that the coverage report numbers
// are internally consistent.
func TestCoverageReportConsistency(t *testing.T) {
	r := BuildDefaultRegistry()
	report := r.Coverage()

	// Total rules should equal sum of maturity counts
	totalMaturity := 0
	for _, count := range report.MaturityCounts {
		totalMaturity += count
	}
	if totalMaturity != report.TotalRules {
		t.Errorf("maturity counts sum (%d) != total rules (%d)", totalMaturity, report.TotalRules)
	}

	// Blocking eligible + excluded should equal total
	if report.BlockingEligible+report.BlockingExcluded != report.TotalRules {
		t.Errorf("blocking eligible (%d) + excluded (%d) != total (%d)",
			report.BlockingEligible, report.BlockingExcluded, report.TotalRules)
	}

	// CWE mapped + missing should equal total
	if report.CWEMapped+report.CWEMissing != report.TotalRules {
		t.Errorf("CWE mapped (%d) + missing (%d) != total (%d)",
			report.CWEMapped, report.CWEMissing, report.TotalRules)
	}

	// By engine counts should sum to total
	totalEngine := 0
	for _, count := range report.ByEngine {
		totalEngine += count
	}
	if totalEngine != report.TotalRules {
		t.Errorf("engine counts sum (%d) != total rules (%d)", totalEngine, report.TotalRules)
	}

	// Audit profile should include ALL rules (it's the most permissive)
	if report.ProfilesActive["audit"] != report.TotalRules {
		t.Errorf("audit profile should include all %d rules, got %d",
			report.TotalRules, report.ProfilesActive["audit"])
	}

	// Dev profile should have the fewest rules
	if report.ProfilesActive["dev"] > report.ProfilesActive["pr"] {
		t.Errorf("dev profile (%d) should have fewer rules than pr (%d)",
			report.ProfilesActive["dev"], report.ProfilesActive["pr"])
	}
}

// TestRuleDocsData verifies that the registry data needed for documentation
// generation is complete and well-formed.
func TestRuleDocsData(t *testing.T) {
	r := BuildDefaultRegistry()
	allRules := r.All()

	if len(allRules) == 0 {
		t.Fatal("registry should have rules for docs generation")
	}

	// Every rule should have an ID, title, engine, severity, and maturity
	for _, meta := range allRules {
		if meta.ID == "" {
			t.Error("found rule with empty ID")
		}
		if meta.Title == "" {
			t.Errorf("rule %s: empty title", meta.ID)
		}
		if meta.Engine == "" {
			t.Errorf("rule %s: empty engine", meta.ID)
		}
		if meta.Severity == "" {
			t.Errorf("rule %s: empty severity", meta.ID)
		}
		if meta.Maturity.String() == "unknown" {
			t.Errorf("rule %s: unknown maturity", meta.ID)
		}
	}

	// At least some rules should have CWE mappings for docs
	cweCount := 0
	for _, meta := range allRules {
		if meta.CWE != "" {
			cweCount++
		}
	}
	if cweCount == 0 {
		t.Error("expected at least some rules with CWE mappings for docs")
	}
}

// TestRegistrySearchByCWE verifies that searching by CWE returns all rules
// with that CWE mapping.
func TestRegistrySearchByCWE(t *testing.T) {
	r := BuildDefaultRegistry()

	// CWE-89 is SQL injection — should match G201, G202, G701, TP-PY001, TP-JS001
	results := r.Search("CWE-89")
	if len(results) == 0 {
		t.Fatal("expected results for CWE-89")
	}

	// All results should have CWE-89
	for _, meta := range results {
		if meta.CWE != "CWE-89" {
			t.Errorf("search result %s has CWE %s, expected CWE-89", meta.ID, meta.CWE)
		}
	}
}

// TestRegistrySearchByCategory verifies category-based search.
func TestRegistrySearchByCategory(t *testing.T) {
	r := BuildDefaultRegistry()

	// Search for injection rules — Search matches across ID, title, CWE,
	// category, and OWASP, so results may include rules whose title
	// contains "injection" even if their category is "general".
	results := r.Search("injection")
	if len(results) == 0 {
		t.Fatal("expected results for 'injection' search")
	}

	// Every result should contain "injection" in at least one searchable field
	for _, meta := range results {
		matched := strings.Contains(strings.ToLower(meta.Title), "injection") ||
			strings.Contains(strings.ToLower(meta.Category), "injection") ||
			strings.Contains(strings.ToLower(meta.CWE), "injection") ||
			strings.Contains(strings.ToLower(meta.OWASP), "injection")
		if !matched {
			t.Errorf("search result %s does not contain 'injection' in any searchable field (title=%s, cat=%s, cwe=%s, owasp=%s)",
				meta.ID, meta.Title, meta.Category, meta.CWE, meta.OWASP)
		}
	}
}

// TestInactiveRulesForProfile verifies that inactive rules are correctly
// identified for each profile.
func TestInactiveRulesForProfile(t *testing.T) {
	r := BuildDefaultRegistry()

	// Dev profile should have inactive rules (experimental + beta)
	inactiveDev := r.InactiveRulesForProfile(ProfileDev)
	if len(inactiveDev) == 0 {
		t.Error("expected inactive rules for dev profile")
	}

	// Audit profile should have NO inactive rules
	inactiveAudit := r.InactiveRulesForProfile(ProfileAudit)
	if len(inactiveAudit) != 0 {
		t.Errorf("expected 0 inactive rules for audit profile, got %d", len(inactiveAudit))
	}

	// CI profile may have inactive rules (experimental only). With all engines
	// at beta or higher, CI may have 0 inactive rules — just verify dev has
	// at least as many inactive as CI.
	inactiveCI := r.InactiveRulesForProfile(ProfileCI)

	// Dev should have at least as many inactive as CI
	if len(inactiveDev) < len(inactiveCI) {
		t.Errorf("dev should have at least as many inactive rules as ci (dev=%d, ci=%d)",
			len(inactiveDev), len(inactiveCI))
	}
}

// TestFilterFindingsByProfile verifies the finding filter API used by
// the scan runner.
func TestFilterFindingsByProfile(t *testing.T) {
	r := BuildDefaultRegistry()

	// Mix of rule IDs from different engines/maturities
	ruleIDs := []string{
		"G101",       // stable, Go SAST — active in dev
		"G701",       // stable, taint SSA — active in dev
		"PY001",      // beta, patterns — NOT active in dev (beta requires PR+)
		"TS-PY001",   // beta, tree-sitter — NOT active in dev
		"SECRET-AWS Access Key ID", // stable, secrets — active in dev
	}

	// Dev profile: should keep G101, G701, SECRET-* but not PY001 or TS-PY001
	filtered := r.FilterFindingsByProfile(ruleIDs, ProfileDev)
	if len(filtered) != 3 {
		t.Errorf("dev profile: expected 3 active rules, got %d (%v)", len(filtered), filtered)
	}

	// Audit profile: should keep all
	filtered = r.FilterFindingsByProfile(ruleIDs, ProfileAudit)
	if len(filtered) != 5 {
		t.Errorf("audit profile: expected 5 active rules, got %d (%v)", len(filtered), filtered)
	}

	// CI profile: should keep stable + beta (all 5 now that patterns are beta)
	filtered = r.FilterFindingsByProfile(ruleIDs, ProfileCI)
	if len(filtered) != 5 {
		t.Errorf("ci profile: expected 5 active rules, got %d (%v)", len(filtered), filtered)
	}
}
