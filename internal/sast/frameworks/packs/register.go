package packs

import (
	"github.com/Patchflow-security/patchflow-cli/internal/rules"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

// RegisterFrameworkRules registers all framework pack rules into the
// governance registry. Each rule is registered under the EngineFrameworks
// engine with its typed maturity (converted to rules.Maturity).
//
// This is called by the CLI when building the governance registry so
// framework rules appear in `rules list`, `rules maturity`, and
// `rules docs` alongside the core scanner rules.
func RegisterFrameworkRules(reg *rules.Registry) {
	fwReg := BuildDefaultRegistry()
	for _, p := range fwReg.All() {
		for _, r := range p.Rules() {
			maturity := ToRulesMaturity(r.Maturity)
			reg.Register(rules.RuleMetadata{
				ID:               r.ID,
				Engine:           rules.EngineFrameworks,
				Title:            r.Title,
				Description:      r.Recommendation,
				Severity:         string(r.Severity),
				Confidence:       string(r.Confidence),
				Language:         r.Language,
				CWE:              r.CWE,
				Maturity:         maturity,
				Profiles:         rules.ProfilesForMaturity(maturity),
				BlockingEligible: rules.IsBlockingEligible(maturity, string(r.Severity)),
				Recommendation:   r.Recommendation,
				Category:         rules.CategoryFromRuleID(r.ID),
			})
		}
	}
}

// FrameworkRuleCount returns the total number of framework rules across all
// registered packs. Used for reporting.
func FrameworkRuleCount() int {
	fwReg := BuildDefaultRegistry()
	count := 0
	for _, p := range fwReg.All() {
		count += len(p.Rules())
	}
	return count
}

// FrameworkPackNames returns the names of all registered framework packs.
func FrameworkPackNames() []string {
	return BuildDefaultRegistry().Names()
}

// _ keeps the frameworks import referenced even if future edits remove
// inline uses.
var _ = frameworks.MaturityExperimental
