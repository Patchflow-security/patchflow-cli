package frameworks

import "github.com/Patchflow-security/patchflow-cli/internal/analysis"

// PackOverride extends an official pack with user-defined semantics without
// replacing the embedded pack as the source of truth.
type PackOverride struct {
	Sources           []SourcePattern
	Sinks             []SinkPattern
	Sanitizers        []SanitizerPattern
	SafePatterns      []SafePattern
	SeverityOverrides map[string]analysis.Severity
}

type overriddenPack struct {
	base        Pack
	rules       []FrameworkRule
	sources     []SourcePattern
	sinks       []SinkPattern
	sanitizers  []SanitizerPattern
	safePatterns []SafePattern
}

// ApplyPackOverride returns a pack view with user overrides merged on top of
// the official pack.
func ApplyPackOverride(base Pack, override PackOverride) Pack {
	if len(override.Sources) == 0 &&
		len(override.Sinks) == 0 &&
		len(override.Sanitizers) == 0 &&
		len(override.SafePatterns) == 0 &&
		len(override.SeverityOverrides) == 0 {
		return base
	}

	mergedSources := append(cloneSources(base.Sources()), override.Sources...)
	mergedSinks := append(cloneSinks(base.Sinks()), override.Sinks...)
	mergedSanitizers := append(cloneSanitizers(base.Sanitizers()), override.Sanitizers...)
	// Safe patterns are per-rule, not per-pack. We collect them here for
	// explain output but they are merged into each rule below.
	mergedSafePatterns := cloneSafePatterns(override.SafePatterns)

	baseRules := base.Rules()
	rules := make([]FrameworkRule, 0, len(baseRules))
	for _, rule := range baseRules {
		cp := rule
		// Scope custom sources: only attach to rules whose category matches
		// (or all rules if source has no category restriction).
		for _, src := range override.Sources {
			if sourceMatchesRule(src, rule) {
				cp.Sources = append(cp.Sources, src)
			}
		}
		// Scope custom sinks: only attach to rules whose CWE/category matches.
		// This prevents a SQL sink from firing on SSRF/redirect/deser rules.
		for _, sink := range override.Sinks {
			if sinkMatchesRule(sink, rule) {
				cp.Sinks = append(cp.Sinks, sink)
			}
		}
		cp.Sanitizers = append(cloneSanitizers(rule.Sanitizers), override.Sanitizers...)
		cp.SafePatterns = append(cloneSafePatterns(rule.SafePatterns), override.SafePatterns...)
		if sev, ok := override.SeverityOverrides[rule.ID]; ok {
			cp.Severity = sev
		}
		rules = append(rules, cp)
	}

	return &overriddenPack{
		base:         base,
		rules:        rules,
		sources:      mergedSources,
		sinks:        mergedSinks,
		sanitizers:   mergedSanitizers,
		safePatterns: mergedSafePatterns,
	}
}

func (p *overriddenPack) Name() string     { return p.base.Name() }
func (p *overriddenPack) Language() string { return p.base.Language() }
func (p *overriddenPack) FileExtensions() []string {
	return append([]string(nil), p.base.FileExtensions()...)
}
func (p *overriddenPack) TemplateExtensions() []string {
	return append([]string(nil), p.base.TemplateExtensions()...)
}
func (p *overriddenPack) Rules() []FrameworkRule   { return cloneRules(p.rules) }
func (p *overriddenPack) Sources() []SourcePattern { return cloneSources(p.sources) }
func (p *overriddenPack) Sinks() []SinkPattern     { return cloneSinks(p.sinks) }
func (p *overriddenPack) Sanitizers() []SanitizerPattern {
	return cloneSanitizers(p.sanitizers)
}

// SafePatterns returns the merged safe patterns (pack + extension).
// This is not part of the Pack interface but is used internally for explain.
func (p *overriddenPack) SafePatterns() []SafePattern {
	return cloneSafePatterns(p.safePatterns)
}

func cloneRules(in []FrameworkRule) []FrameworkRule {
	if len(in) == 0 {
		return nil
	}
	out := make([]FrameworkRule, 0, len(in))
	for _, rule := range in {
		cp := rule
		cp.FileTypes = append([]string(nil), rule.FileTypes...)
		cp.TemplateTypes = append([]string(nil), rule.TemplateTypes...)
		cp.Sources = cloneSources(rule.Sources)
		cp.Sinks = cloneSinks(rule.Sinks)
		cp.Sanitizers = cloneSanitizers(rule.Sanitizers)
		cp.SafePatterns = append([]SafePattern(nil), rule.SafePatterns...)
		cp.Exclusions = append([]PathPattern(nil), rule.Exclusions...)
		out = append(out, cp)
	}
	return out
}

func cloneSources(in []SourcePattern) []SourcePattern {
	return append([]SourcePattern(nil), in...)
}

func cloneSinks(in []SinkPattern) []SinkPattern {
	return append([]SinkPattern(nil), in...)
}

func cloneSanitizers(in []SanitizerPattern) []SanitizerPattern {
	return append([]SanitizerPattern(nil), in...)
}

func cloneSafePatterns(in []SafePattern) []SafePattern {
	return append([]SafePattern(nil), in...)
}
