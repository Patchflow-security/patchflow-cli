// Package rules provides a unified rule governance system for PatchFlow's
// embedded scanners. It defines maturity levels, scan profiles, CWE/OWASP
// mappings, and a centralized metadata registry that tags every rule across
// all five scanner engines.
//
// The registry is the single source of truth for rule governance: maturity
// level, CWE/OWASP classification, profile eligibility, and blocking
// eligibility. Individual scanner engines remain responsible for detection
// logic; this package governs how rules are presented, filtered, and
// trusted.
package rules

// Maturity represents the governance maturity level of a rule.
//
// The maturity model has four levels, from experimental to enterprise-grade.
// It controls whether a rule is enabled by default, whether it can block
// PRs, and which scan profiles include it.
type Maturity int

const (
	// MaturityExperimental is a new rule with few or no tests. It appears
	// only in audit/deep profiles and never blocks PRs.
	MaturityExperimental Maturity = 0

	// MaturityBeta has positive and negative tests plus basic metadata.
	// It is enabled in audit and standard scans but does not block by default.
	MaturityBeta Maturity = 1

	// MaturityStable has positive, negative, and false-positive tests,
	// CWE/OWASP mapping, and good fix guidance. It can block PRs when
	// severity is high or critical.
	MaturityStable Maturity = 2

	// MaturityEnterprise has a large regression corpus, framework awareness,
	// low false-positive rate, strong docs, and stable fingerprinting. It is
	// used in the default CI profile and blocks PRs.
	MaturityEnterprise Maturity = 3
)

// String returns the human-readable name of the maturity level.
func (m Maturity) String() string {
	switch m {
	case MaturityExperimental:
		return "experimental"
	case MaturityBeta:
		return "beta"
	case MaturityStable:
		return "stable"
	case MaturityEnterprise:
		return "enterprise"
	default:
		return "unknown"
	}
}

// CanBlock returns true if a rule at this maturity level is eligible to
// block PRs (i.e., contribute to a non-zero exit code in CI mode).
func (m Maturity) CanBlock() bool {
	return m >= MaturityStable
}

// Profile represents a scan profile that controls which rules are active.
type Profile string

const (
	// ProfileDev is for local development: fast, high-confidence rules only.
	// Secrets (stable), fast AST rules, no regex patterns, no taint.
	ProfileDev Profile = "dev"

	// ProfilePR is for pull-request checks: stable secrets + AST + high-confidence
	// patterns. Blocks on high/critical findings from stable rules.
	ProfilePR Profile = "pr"

	// ProfileCI is for CI pipelines: all stable rules + beta as warnings.
	// Blocks on high/critical findings from stable rules.
	ProfileCI Profile = "ci"

	// ProfileAudit is for security audits: all rules including experimental.
	// Does not block by default — produces a full report for manual review.
	ProfileAudit Profile = "audit"
)

// AllProfiles returns all defined scan profiles in order from most restrictive
// to most permissive.
func AllProfiles() []Profile {
	return []Profile{ProfileDev, ProfilePR, ProfileCI, ProfileAudit}
}

// String returns the profile name as a string.
func (p Profile) String() string {
	return string(p)
}

// IncludesMaturity returns true if the profile includes rules at the given
// maturity level.
func (p Profile) IncludesMaturity(m Maturity) bool {
	switch p {
	case ProfileDev:
		// Dev: only enterprise and stable rules, and only from specific engines.
		return m >= MaturityStable
	case ProfilePR:
		// PR: stable and enterprise rules.
		return m >= MaturityStable
	case ProfileCI:
		// CI: stable and enterprise rules block; beta rules appear as warnings.
		return m >= MaturityBeta
	case ProfileAudit:
		// Audit: everything.
		return true
	default:
		return true
	}
}

// Engine identifies which scanner engine produced a rule.
type Engine string

const (
	EnginePatterns     Engine = "patterns-embedded"
	EngineTreeSitter   Engine = "treesitter-ast"
	EngineGoSAST       Engine = "gosast-embedded"
	EngineSecrets      Engine = "secrets-embedded"
	EngineTaintSSA     Engine = "taint-ssa"
	EngineTaintPatterns Engine = "taint-patterns"
)

// String returns the engine name.
func (e Engine) String() string {
	return string(e)
}

// DefaultMaturityForEngine returns the default maturity level for rules
// produced by the given engine. Individual rules can override this via
// the registry.
func DefaultMaturityForEngine(e Engine) Maturity {
	switch e {
	case EngineGoSAST:
		// Go AST rules use real semantic analysis — high confidence.
		return MaturityStable
	case EngineTaintSSA:
		// SSA-based taint analysis is the strongest signal.
		return MaturityStable
	case EngineSecrets:
		// Secret patterns are well-curated with FP filtering.
		return MaturityStable
	case EngineTreeSitter:
		// AST-based rules are better than regex but still maturing.
		return MaturityBeta
	case EngineTaintPatterns:
		// Tree-sitter taint patterns are newer.
		return MaturityBeta
	case EnginePatterns:
		// Regex patterns have the highest false-positive risk.
		return MaturityExperimental
	default:
		return MaturityExperimental
	}
}

// DefaultProfilesForEngine returns the default set of scan profiles that
// include rules from the given engine (at the engine's default maturity).
func DefaultProfilesForEngine(e Engine) []Profile {
	switch e {
	case EngineGoSAST, EngineTaintSSA, EngineSecrets:
		// High-confidence engines: included in all profiles.
		return []Profile{ProfileDev, ProfilePR, ProfileCI, ProfileAudit}
	case EngineTreeSitter, EngineTaintPatterns:
		// AST engines: included in PR, CI, and audit (not dev for speed).
		return []Profile{ProfilePR, ProfileCI, ProfileAudit}
	case EnginePatterns:
		// Regex patterns: audit-only by default (too noisy for CI blocking).
		return []Profile{ProfileAudit}
	default:
		return []Profile{ProfileAudit}
	}
}
