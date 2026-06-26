package rules

import (
	"sort"
	"strings"
)

// Registry holds governance metadata for all rules across all scanner engines.
// It is the single source of truth for maturity, CWE/OWASP, profiles, and
// blocking eligibility.
type Registry struct {
	entries map[string]RuleMetadata // keyed by rule ID
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{entries: make(map[string]RuleMetadata)}
}

// Register adds or updates a rule's metadata in the registry. If the rule
// already exists, its metadata is merged (non-empty fields from the new
// entry override the old one; empty fields fall back to computed defaults).
func (r *Registry) Register(meta RuleMetadata) {
	if meta.CWE == "" {
		meta.CWE = CWEFromRuleID(meta.ID)
	}
	if meta.OWASP == "" {
		meta.OWASP = OWASPFromCWE(meta.CWE)
	}
	if meta.Category == "" {
		meta.Category = CategoryFromRuleID(meta.ID)
	}
	if meta.Recommendation == "" {
		meta.Recommendation = RecommendationForRule(meta.ID, meta.CWE)
	}
	if len(meta.Profiles) == 0 {
		meta.Profiles = DefaultProfilesForEngine(meta.Engine)
	}
	if !meta.BlockingEligible {
		meta.BlockingEligible = IsBlockingEligible(meta.Maturity, meta.Severity)
	}
	r.entries[meta.ID] = meta
}

// RegisterEngineRule registers a rule from a specific engine with default
// metadata. This is the convenience method used by scanner engines that
// only have basic rule info (ID, title, severity, confidence, language).
func (r *Registry) RegisterEngineRule(
	engine Engine,
	id, title, severity, confidence, language string,
) {
	maturity := DefaultMaturityForEngine(engine)
	r.Register(RuleMetadata{
		ID:               id,
		Engine:           engine,
		Title:            title,
		Severity:         severity,
		Confidence:       confidence,
		Language:         language,
		Maturity:         maturity,
		Profiles:         DefaultProfilesForEngine(engine),
		BlockingEligible: IsBlockingEligible(maturity, severity),
	})
}

// RegisterEngineRuleWithMaturity registers a rule with an explicit maturity
// override (used when a specific rule is more or less mature than its
// engine's default).
func (r *Registry) RegisterEngineRuleWithMaturity(
	engine Engine,
	id, title, severity, confidence, language string,
	maturity Maturity,
) {
	r.Register(RuleMetadata{
		ID:               id,
		Engine:           engine,
		Title:            title,
		Severity:         severity,
		Confidence:       confidence,
		Language:         language,
		Maturity:         maturity,
		Profiles:         DefaultProfilesForEngine(engine),
		BlockingEligible: IsBlockingEligible(maturity, severity),
	})
}

// Get returns the metadata for a rule by ID. Returns ok=false if not found.
func (r *Registry) Get(id string) (RuleMetadata, bool) {
	meta, ok := r.entries[id]
	return meta, ok
}

// All returns all registered rule metadata, sorted by engine then ID.
func (r *Registry) All() []RuleMetadata {
	result := make([]RuleMetadata, 0, len(r.entries))
	for _, meta := range r.entries {
		result = append(result, meta)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Engine != result[j].Engine {
			return result[i].Engine < result[j].Engine
		}
		return result[i].ID < result[j].ID
	})
	return result
}

// ByEngine returns all rules from a specific engine, sorted by ID.
func (r *Registry) ByEngine(engine Engine) []RuleMetadata {
	var result []RuleMetadata
	for _, meta := range r.entries {
		if meta.Engine == engine {
			result = append(result, meta)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})
	return result
}

// Count returns the total number of registered rules.
func (r *Registry) Count() int {
	return len(r.entries)
}

// MaturityCounts returns a map of maturity level -> count of rules.
func (r *Registry) MaturityCounts() map[Maturity]int {
	counts := make(map[Maturity]int)
	for _, meta := range r.entries {
		counts[meta.Maturity]++
	}
	return counts
}

// CoverageReport computes governance coverage metrics across all rules.
type CoverageReport struct {
	TotalRules       int            `json:"total_rules"`
	MaturityCounts   map[string]int `json:"maturity_counts"`
	BlockingEligible int            `json:"blocking_eligible"`
	BlockingExcluded int            `json:"blocking_excluded"`
	CWEMapped        int            `json:"cwe_mapped"`
	CWEMissing       int            `json:"cwe_missing"`
	OWASPMapped      int            `json:"owasp_mapped"`
	ProfilesActive   map[string]int `json:"profiles_active"`
	ByEngine         map[string]int `json:"by_engine"`
}

// Coverage computes a governance coverage report.
func (r *Registry) Coverage() CoverageReport {
	report := CoverageReport{
		TotalRules:     r.Count(),
		MaturityCounts: make(map[string]int),
		ProfilesActive: make(map[string]int),
		ByEngine:       make(map[string]int),
	}

	mc := r.MaturityCounts()
	for m, count := range mc {
		report.MaturityCounts[m.String()] = count
	}

	for _, meta := range r.entries {
		if meta.BlockingEligible {
			report.BlockingEligible++
		} else {
			report.BlockingExcluded++
		}
		if meta.CWE != "" {
			report.CWEMapped++
		} else {
			report.CWEMissing++
		}
		if meta.OWASP != "" {
			report.OWASPMapped++
		}
		report.ByEngine[meta.Engine.String()]++
		for _, p := range meta.Profiles {
			report.ProfilesActive[p.String()]++
		}
	}

	return report
}

// IsRuleActiveInProfile returns true if a rule is active in the given profile.
// A rule is active if:
// 1. Its maturity level is included in the profile, AND
// 2. The profile is in the rule's profiles list.
func (r *Registry) IsRuleActiveInProfile(id string, profile Profile) bool {
	meta, ok := r.Get(id)
	if !ok {
		// Unknown rule: only active in audit profile.
		return profile == ProfileAudit
	}
	if !profile.IncludesMaturity(meta.Maturity) {
		return false
	}
	for _, p := range meta.Profiles {
		if p == profile {
			return true
		}
	}
	return false
}

// ActiveRulesForProfile returns the IDs of all rules active in the given profile.
func (r *Registry) ActiveRulesForProfile(profile Profile) []string {
	var ids []string
	for _, meta := range r.entries {
		if r.IsRuleActiveInProfile(meta.ID, profile) {
			ids = append(ids, meta.ID)
		}
	}
	sort.Strings(ids)
	return ids
}

// InactiveRulesForProfile returns the IDs of all rules NOT active in the given profile.
func (r *Registry) InactiveRulesForProfile(profile Profile) []string {
	var ids []string
	for _, meta := range r.entries {
		if !r.IsRuleActiveInProfile(meta.ID, profile) {
			ids = append(ids, meta.ID)
		}
	}
	sort.Strings(ids)
	return ids
}

// FilterFindingsByProfile filters a list of finding rule IDs, keeping only
// those that are active in the given profile. This is used by the scan runner
// to apply profile-based rule filtering after scanning.
func (r *Registry) FilterFindingsByProfile(ruleIDs []string, profile Profile) []string {
	var active []string
	for _, id := range ruleIDs {
		if r.IsRuleActiveInProfile(id, profile) {
			active = append(active, id)
		}
	}
	return active
}

// ShouldBlock returns true if a finding from this rule should contribute to
// a non-zero exit code in CI mode. This requires both blocking eligibility
// and activation in the CI profile.
func (r *Registry) ShouldBlock(id string, profile Profile) bool {
	meta, ok := r.Get(id)
	if !ok {
		return false
	}
	if !meta.BlockingEligible {
		return false
	}
	return r.IsRuleActiveInProfile(id, profile)
}

// Search returns rules matching a search query (by ID, title, CWE, or category).
func (r *Registry) Search(query string) []RuleMetadata {
	query = strings.ToLower(query)
	var result []RuleMetadata
	for _, meta := range r.entries {
		if strings.Contains(strings.ToLower(meta.ID), query) ||
			strings.Contains(strings.ToLower(meta.Title), query) ||
			strings.Contains(strings.ToLower(meta.CWE), query) ||
			strings.Contains(strings.ToLower(meta.Category), query) ||
			strings.Contains(strings.ToLower(meta.OWASP), query) {
			result = append(result, meta)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})
	return result
}
