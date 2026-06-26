package rules

import (
	"github.com/patchflow/patchflow-cli/internal/sast"
	"github.com/patchflow/patchflow-cli/internal/sast/gosast"
	"github.com/patchflow/patchflow-cli/internal/sast/patterns"
	"github.com/patchflow/patchflow-cli/internal/sast/secrets"
	"github.com/patchflow/patchflow-cli/internal/sast/taint"
	"github.com/patchflow/patchflow-cli/internal/sast/taintpatterns"
	"github.com/patchflow/patchflow-cli/internal/sast/treesitter"
)

// BuildDefaultRegistry creates a Registry populated with metadata for all
// rules from all embedded scanner engines. This is the canonical registry
// used by the CLI for governance, display, and profile filtering.
func BuildDefaultRegistry() *Registry {
	r := NewRegistry()

	// 1. Go SAST rules (gosast-embedded) — default maturity: stable
	for _, ri := range gosast.NewAnalyzer().Rules() {
		r.RegisterEngineRule(
			EngineGoSAST,
			ri.ID,
			ri.What,
			ri.Severity,
			"", // gosast RuleInfo doesn't expose confidence
			"go",
		)
	}

	// 2. Secrets rules (secrets-embedded) — default maturity: stable
	for _, si := range secrets.NewScanner().Rules() {
		r.RegisterEngineRule(
			EngineSecrets,
			"SECRET-"+si.Name,
			si.Name,
			string(si.Severity),
			string(si.Confidence),
			"secrets",
		)
	}

	// 3. Pattern rules (patterns-embedded) — default maturity: experimental
	for _, pr := range patterns.NewScanner().Rules() {
		r.RegisterEngineRule(
			EnginePatterns,
			pr.ID,
			pr.Title,
			string(pr.Severity),
			string(pr.Confidence),
			"multi",
		)
	}

	// 4. Tree-sitter rules (treesitter-ast) — default maturity: beta
	for _, tr := range treesitter.NewAnalyzer().Rules() {
		r.RegisterEngineRule(
			EngineTreeSitter,
			tr.ID,
			tr.Title,
			tr.Severity,
			"", // treesitter RuleInfo doesn't expose confidence
			tr.Language,
		)
	}

	// 5. Taint SSA rules (taint-ssa) — default maturity: stable
	for _, tr := range taint.NewAnalyzer().Rules() {
		r.RegisterEngineRule(
			EngineTaintSSA,
			tr.ID,
			tr.Title,
			tr.Severity,
			"", // taint RuleInfo doesn't expose confidence
			"go",
		)
	}

	// 6. Taint patterns rules (taint-patterns) — default maturity: beta
	for _, tr := range taintpatterns.NewAnalyzer().Rules() {
		r.RegisterEngineRule(
			EngineTaintPatterns,
			tr.ID,
			tr.Title,
			string(tr.Severity),
			string(tr.Confidence),
			tr.Language,
		)
	}

	return r
}

// BuildRegistryFromRunner creates a Registry from a specific SAST runner
// instance. This is used when custom rules are loaded, so the registry
// reflects the actual rules that will run in a scan.
func BuildRegistryFromRunner(runner *sast.Runner) *Registry {
	r := NewRegistry()

	for _, group := range runner.AllRules() {
		engine := Engine(group.Scanner)
		for _, entry := range group.Rules {
			r.RegisterEngineRule(
				engine,
				entry.ID,
				entry.Title,
				entry.Severity,
				"", // confidence not exposed in RuleEntry
				group.Language,
			)
		}
	}

	return r
}
