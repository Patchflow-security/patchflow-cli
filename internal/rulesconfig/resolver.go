package rulesconfig

import (
	"github.com/Patchflow-security/patchflow-cli/internal/rules"
)

// Resolver determines the effective mode for each rule by combining the
// user's explicit config (block/inform/off) with the governance registry's
// maturity-based defaults.
//
// Resolution order (first match wins):
//  1. Explicit mode from project config (.patchflow/rules.yaml)
//  2. Explicit mode from CLI override
//  3. Maturity-based default from the governance registry
//  4. ModeInform (safe fallback for unknown rules)
type Resolver struct {
	config    *Config
	registry  *rules.Registry
	cliOverrides map[string]Mode
}

// NewResolver creates a resolver from a config and governance registry.
// Either may be nil — nil config means all modes come from registry defaults.
func NewResolver(cfg *Config, reg *rules.Registry) *Resolver {
	r := &Resolver{
		config:       cfg,
		registry:     reg,
		cliOverrides: make(map[string]Mode),
	}
	return r
}

// SetCLIOverride sets a mode override from a CLI flag. CLI overrides take
// precedence over project config.
func (r *Resolver) SetCLIOverride(ruleID string, mode Mode) {
	r.cliOverrides[ruleID] = mode
}

// Resolve returns the effective mode, blocking status, and source for a rule.
func (r *Resolver) Resolve(ruleID string) RuleModeEntry {
	// 1. CLI override (highest priority)
	if mode, ok := r.cliOverrides[ruleID]; ok && mode != ModeDefault {
		return RuleModeEntry{
			RuleID:   ruleID,
			Mode:     mode,
			Blocking: mode == ModeBlock,
			Source:   ModeSourceCLI,
		}
	}

	// 2. Project config
	if r.config != nil {
		if mode := r.config.GetMode(ruleID); mode != ModeDefault {
			return RuleModeEntry{
				RuleID:   ruleID,
				Mode:     mode,
				Blocking: mode == ModeBlock,
				Source:   ModeSourceProjectConfig,
			}
		}
	}

	// 3. Maturity-based default from registry
	if r.registry != nil {
		meta, ok := r.registry.Get(ruleID)
		if ok {
			mode := maturityDefaultMode(meta)
			return RuleModeEntry{
				RuleID:   ruleID,
				Mode:     mode,
				Blocking: mode == ModeBlock,
				Source:   ModeSourceDefault,
				Maturity: meta.Maturity.String(),
			}
		}
	}

	// 4. Unknown rule: default to inform (safe — reports but doesn't block)
	return RuleModeEntry{
		RuleID:   ruleID,
		Mode:     ModeInform,
		Blocking: false,
		Source:   ModeSourceDefault,
	}
}

// ResolveMany resolves modes for multiple rule IDs at once.
func (r *Resolver) ResolveMany(ruleIDs []string) []RuleModeEntry {
	entries := make([]RuleModeEntry, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		entries = append(entries, r.Resolve(id))
	}
	return entries
}

// IsOff returns true if the rule is suppressed (mode=off).
func (r *Resolver) IsOff(ruleID string) bool {
	return r.Resolve(ruleID).Mode == ModeOff
}

// IsBlocking returns true if the rule should contribute to a non-zero exit code.
func (r *Resolver) IsBlocking(ruleID string) bool {
	return r.Resolve(ruleID).Blocking
}

// FilterFindings filters out findings whose rule is in "off" mode.
// Findings without a rule ID are always kept.
func (r *Resolver) FilterFindings(findings []FindingLike) (kept, suppressed []FindingLike) {
	for _, f := range findings {
		ruleID := f.GetRuleID()
		if ruleID == "" {
			kept = append(kept, f)
			continue
		}
		if r.IsOff(ruleID) {
			suppressed = append(suppressed, f)
		} else {
			kept = append(kept, f)
		}
	}
	return kept, suppressed
}

// FindingLike is a minimal interface for findings so the resolver doesn't
// depend on the analysis package (avoiding import cycles).
type FindingLike interface {
	GetRuleID() string
}

// maturityDefaultMode computes the default mode for a rule based on its
// maturity and severity, following the reviewer's recommended behavior:
//
//   - stable + high/critical severity → block
//   - stable + medium/low severity → inform
//   - beta → inform
//   - experimental → inform (never block unless user explicitly sets block)
func maturityDefaultMode(meta rules.RuleMetadata) Mode {
	// Experimental rules never block by default.
	if meta.Maturity < rules.MaturityStable {
		return ModeInform
	}

	// Stable+ rules: block only if high/critical severity AND blocking eligible.
	if meta.BlockingEligible {
		return ModeBlock
	}

	// Stable+ but medium/low severity: inform.
	return ModeInform
}
