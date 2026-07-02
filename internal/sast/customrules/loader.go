// Package customrules provides loading and validation of user-defined
// security rules from YAML files. Users can create custom rules in
// `.patchflow/rules.yaml` or specify a path with `--rules <path>`.
//
// Example rules.yaml:
//
//	rules:
//	  - id: CUSTOM-001
//	    title: No console.log in production
//	    description: console.log should not be used in production code
//	    languages: [javascript, typescript]
//	    pattern: 'console\.log\s*\('
//	    severity: low
//	    confidence: high
//
//	  - id: CUSTOM-002
//	    title: Must use parameterized queries
//	    description: Raw SQL with string interpolation is vulnerable to SQL injection
//	    languages: [python]
//	    pattern: 'cursor\.execute\(.*%.*'
//	    severity: high
//	    confidence: medium
package customrules

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	fwpatterns "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/patterns"
	"gopkg.in/yaml.v3"
)

// RuleFile represents the YAML structure of a custom rules file.
type RuleFile struct {
	Rules              []YAMLRule                           `yaml:"rules"`
	TaintRules         []YAMLTaintRule                      `yaml:"taint_rules"`
	Frameworks         YAMLFrameworkSelection               `yaml:"frameworks"`
	FrameworkOverrides map[string]YAMLFrameworkPackOverride `yaml:"framework_overrides"`
}

// YAMLRule represents a single regex pattern rule definition in the YAML file.
type YAMLRule struct {
	ID          string   `yaml:"id"`
	Title       string   `yaml:"title"`
	Description string   `yaml:"description"`
	Languages   []string `yaml:"languages"`
	Pattern     string   `yaml:"pattern"`
	Severity    string   `yaml:"severity"`
	Confidence  string   `yaml:"confidence"`
}

// YAMLTaintRule represents a taint source-sink rule definition in YAML.
// Unlike regex rules, taint rules track data flow from sources to sinks.
type YAMLTaintRule struct {
	ID          string             `yaml:"id"`
	Title       string             `yaml:"title"`
	Description string             `yaml:"description"`
	Language    string             `yaml:"language"`
	Severity    string             `yaml:"severity"`
	Confidence  string             `yaml:"confidence"`
	CWE         string             `yaml:"cwe"`
	Taint       YAMLTaintDefinition `yaml:"taint"`
}

// YAMLTaintDefinition holds the source/sink/sanitizer definitions for a taint rule.
type YAMLTaintDefinition struct {
	Sources    []YAMLTaintSource    `yaml:"sources"`
	Sinks      []YAMLTaintSink      `yaml:"sinks"`
	Sanitizers []YAMLTaintSanitizer `yaml:"sanitizers"`
}

type YAMLTaintSource struct {
	Func       string `yaml:"func"`
	Subscript  bool   `yaml:"subscript"`
}

type YAMLTaintSink struct {
	Func string `yaml:"func"`
	Arg  int    `yaml:"arg"`
}

type YAMLTaintSanitizer struct {
	Func string `yaml:"func"`
}

// YAMLFrameworkSelection controls framework-pack activation from YAML.
type YAMLFrameworkSelection struct {
	AutoDetect *bool    `yaml:"auto_detect"`
	Enabled    []string `yaml:"enabled"`
	Disabled   []string `yaml:"disabled"`
}

// YAMLFrameworkPackOverride extends an official framework pack.
type YAMLFrameworkPackOverride struct {
	CustomSources     []YAMLFrameworkSource    `yaml:"custom_sources"`
	CustomSinks       []YAMLFrameworkSink      `yaml:"custom_sinks"`
	CustomSanitizers  []YAMLFrameworkSanitizer `yaml:"custom_sanitizers"`
	SeverityOverrides map[string]string        `yaml:"severity_overrides"`
}

type YAMLFrameworkSource struct {
	Func        string `yaml:"func"`
	IsSubscript bool   `yaml:"is_subscript"`
	Annotation  string `yaml:"annotation"`
}

type YAMLFrameworkSink struct {
	Func     string `yaml:"func"`
	ArgIndex int    `yaml:"arg_index"`
}

type YAMLFrameworkSanitizer struct {
	Func  string `yaml:"func"`
	Regex string `yaml:"regex"`
}

// Policy is the fully parsed user YAML policy.
type Policy struct {
	PatternRules       []patterns.PatternRule
	TaintRules         []TaintRuleSpec
	FrameworkSelection fwpatterns.SelectionConfig
	FrameworkOverrides map[string]fwpatterns.PackOverride
}

// TaintRuleSpec is a validated custom taint rule ready for the taintpatterns engine.
type TaintRuleSpec struct {
	ID          string
	Title       string
	Description string
	Language    string
	Severity    analysis.Severity
	Confidence  analysis.Confidence
	CWEID       string
	Sources     []TaintSourceSpec
	Sinks       []TaintSinkSpec
	Sanitizers  []TaintSanitizerSpec
}

type TaintSourceSpec struct {
	FuncName    string
	IsSubscript bool
}

type TaintSinkSpec struct {
	FuncName string
	ArgIndex int
}

type TaintSanitizerSpec struct {
	FuncName string
}

// LoadFromFile loads custom rules from a YAML file.
// Returns a slice of PatternRule that can be added to the patterns.Scanner.
func LoadFromFile(path string) ([]patterns.PatternRule, error) {
	policy, err := LoadPolicyFromFile(path)
	if err != nil {
		return nil, err
	}
	return policy.PatternRules, nil
}

// LoadFromBytes loads custom rules from YAML bytes.
func LoadFromBytes(data []byte) ([]patterns.PatternRule, error) {
	policy, err := LoadPolicyFromBytes(data)
	if err != nil {
		return nil, err
	}
	return policy.PatternRules, nil
}

// LoadFromDir loads custom rules from `.patchflow/rules.yaml` in the given directory.
// Returns empty slice if the file doesn't exist (not an error).
func LoadFromDir(dir string) ([]patterns.PatternRule, error) {
	policy, err := LoadPolicyFromDir(dir)
	if err != nil {
		return nil, err
	}
	return policy.PatternRules, nil
}

// LoadPolicyFromFile loads the full user policy from a YAML file.
func LoadPolicyFromFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file: %w", err)
	}
	return LoadPolicyFromBytes(data)
}

// LoadPolicyFromBytes loads the full user policy from YAML bytes.
func LoadPolicyFromBytes(data []byte) (*Policy, error) {
	var ruleFile RuleFile
	if err := yaml.Unmarshal(data, &ruleFile); err != nil {
		return nil, fmt.Errorf("failed to parse rules YAML: %w", err)
	}

	policy := &Policy{
		FrameworkSelection: fwpatterns.SelectionConfig{},
		FrameworkOverrides: make(map[string]fwpatterns.PackOverride),
	}

	for i, yr := range ruleFile.Rules {
		rule, err := convertRule(yr, i)
		if err != nil {
			return nil, err
		}
		policy.PatternRules = append(policy.PatternRules, rule)
	}

	for i, yr := range ruleFile.TaintRules {
		rule, err := convertTaintRule(yr, i)
		if err != nil {
			return nil, err
		}
		policy.TaintRules = append(policy.TaintRules, rule)
	}

	policy.FrameworkSelection = convertFrameworkSelection(ruleFile.Frameworks)

	overrides, err := convertFrameworkOverrides(ruleFile.FrameworkOverrides)
	if err != nil {
		return nil, err
	}
	policy.FrameworkOverrides = overrides

	return policy, nil
}

// LoadPolicyFromDir loads `.patchflow/rules.yaml` from the given directory.
// Returns an empty policy if the file does not exist.
func LoadPolicyFromDir(dir string) (*Policy, error) {
	path := filepath.Join(dir, ".patchflow", "rules.yaml")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return &Policy{
			FrameworkOverrides: make(map[string]fwpatterns.PackOverride),
		}, nil
	}
	return LoadPolicyFromFile(path)
}

// convertRule converts a YAMLRule to a patterns.PatternRule, validating fields.
func convertRule(yr YAMLRule, index int) (patterns.PatternRule, error) {
	if yr.ID == "" {
		return patterns.PatternRule{}, fmt.Errorf("rule at index %d: missing required field 'id'", index)
	}
	if yr.Pattern == "" {
		return patterns.PatternRule{}, fmt.Errorf("rule %s: missing required field 'pattern'", yr.ID)
	}
	if yr.Title == "" {
		return patterns.PatternRule{}, fmt.Errorf("rule %s: missing required field 'title'", yr.ID)
	}

	// Compile and validate the regex pattern
	re, err := regexp.Compile(yr.Pattern)
	if err != nil {
		return patterns.PatternRule{}, fmt.Errorf("rule %s: invalid regex pattern: %w", yr.ID, err)
	}

	// Parse languages
	var langs []patterns.Language
	for _, l := range yr.Languages {
		lang, err := parseLanguage(l)
		if err != nil {
			return patterns.PatternRule{}, fmt.Errorf("rule %s: %w", yr.ID, err)
		}
		langs = append(langs, lang)
	}
	if len(langs) == 0 {
		return patterns.PatternRule{}, fmt.Errorf("rule %s: must specify at least one language", yr.ID)
	}

	// Parse severity (default to medium)
	sev := parseSeverity(yr.Severity)

	// Parse confidence (default to medium)
	conf := parseConfidence(yr.Confidence)

	return patterns.PatternRule{
		ID:          yr.ID,
		Title:       yr.Title,
		Description: yr.Description,
		Severity:    sev,
		Confidence:  conf,
		Languages:   langs,
		Pattern:     re,
	}, nil
}

// convertTaintRule converts a YAMLTaintRule to a validated TaintRuleSpec.
func convertTaintRule(yr YAMLTaintRule, index int) (TaintRuleSpec, error) {
	if yr.ID == "" {
		return TaintRuleSpec{}, fmt.Errorf("taint rule at index %d: missing required field 'id'", index)
	}
	if yr.Title == "" {
		return TaintRuleSpec{}, fmt.Errorf("taint rule %s: missing required field 'title'", yr.ID)
	}
	if yr.Language == "" {
		return TaintRuleSpec{}, fmt.Errorf("taint rule %s: missing required field 'language'", yr.ID)
	}
	if !isSupportedTaintLanguage(yr.Language) {
		return TaintRuleSpec{}, fmt.Errorf("taint rule %s: unsupported language %q (supported: python, javascript, typescript, ruby, php, java, c_sharp)", yr.ID, yr.Language)
	}
	if len(yr.Taint.Sources) == 0 {
		return TaintRuleSpec{}, fmt.Errorf("taint rule %s: must define at least one source", yr.ID)
	}
	if len(yr.Taint.Sinks) == 0 {
		return TaintRuleSpec{}, fmt.Errorf("taint rule %s: must define at least one sink", yr.ID)
	}

	spec := TaintRuleSpec{
		ID:          yr.ID,
		Title:       yr.Title,
		Description: yr.Description,
		Language:    yr.Language,
		Severity:    parseSeverity(yr.Severity),
		Confidence:  parseConfidence(yr.Confidence),
		CWEID:       yr.CWE,
	}

	for _, src := range yr.Taint.Sources {
		if src.Func == "" {
			return TaintRuleSpec{}, fmt.Errorf("taint rule %s: source must define 'func'", yr.ID)
		}
		// Reject regex-injection patterns in source names for safety.
		if strings.ContainsAny(src.Func, `()[]{}*+?|^$\`) {
			return TaintRuleSpec{}, fmt.Errorf("taint rule %s: source func %q contains invalid characters", yr.ID, src.Func)
		}
		spec.Sources = append(spec.Sources, TaintSourceSpec{
			FuncName:    src.Func,
			IsSubscript: src.Subscript,
		})
	}

	for _, sink := range yr.Taint.Sinks {
		if sink.Func == "" {
			return TaintRuleSpec{}, fmt.Errorf("taint rule %s: sink must define 'func'", yr.ID)
		}
		if strings.ContainsAny(sink.Func, `()[]{}*+?|^$\`) {
			return TaintRuleSpec{}, fmt.Errorf("taint rule %s: sink func %q contains invalid characters", yr.ID, sink.Func)
		}
		spec.Sinks = append(spec.Sinks, TaintSinkSpec{
			FuncName: sink.Func,
			ArgIndex: sink.Arg,
		})
	}

	for _, san := range yr.Taint.Sanitizers {
		if san.Func == "" {
			return TaintRuleSpec{}, fmt.Errorf("taint rule %s: sanitizer must define 'func'", yr.ID)
		}
		spec.Sanitizers = append(spec.Sanitizers, TaintSanitizerSpec{
			FuncName: san.Func,
		})
	}

	return spec, nil
}

// isSupportedTaintLanguage checks if the language is supported by the taint engine.
func isSupportedTaintLanguage(lang string) bool {
	switch lang {
	case "python", "javascript", "typescript", "ruby", "php", "java", "c_sharp":
		return true
	default:
		return false
	}
}

func convertFrameworkSelection(sel YAMLFrameworkSelection) fwpatterns.SelectionConfig {
	cfg := fwpatterns.SelectionConfig{
		Enabled:  append([]string(nil), sel.Enabled...),
		Disabled: append([]string(nil), sel.Disabled...),
	}
	if sel.AutoDetect != nil {
		cfg.AutoDetect = *sel.AutoDetect
		cfg.AutoDetectSet = true
	}
	return cfg
}

func convertFrameworkOverrides(raw map[string]YAMLFrameworkPackOverride) (map[string]fwpatterns.PackOverride, error) {
	if len(raw) == 0 {
		return map[string]fwpatterns.PackOverride{}, nil
	}
	out := make(map[string]fwpatterns.PackOverride, len(raw))
	for frameworkName, override := range raw {
		name := strings.TrimSpace(frameworkName)
		if name == "" {
			return nil, fmt.Errorf("framework override name cannot be empty")
		}

		packOverride := fwpatterns.PackOverride{
			SeverityOverrides: make(map[string]analysis.Severity),
		}

		for _, src := range override.CustomSources {
			if src.Func == "" && src.Annotation == "" {
				return nil, fmt.Errorf("framework %s: custom source must set func or annotation", name)
			}
			packOverride.Sources = append(packOverride.Sources, fwpatterns.SourcePattern{
				FuncName:    src.Func,
				IsSubscript: src.IsSubscript,
				Annotation:  src.Annotation,
			})
		}
		for _, sink := range override.CustomSinks {
			if sink.Func == "" {
				return nil, fmt.Errorf("framework %s: custom sink must set func", name)
			}
			packOverride.Sinks = append(packOverride.Sinks, fwpatterns.SinkPattern{
				FuncName: sink.Func,
				ArgIndex: sink.ArgIndex,
			})
		}
		for _, sanitizer := range override.CustomSanitizers {
			if sanitizer.Func == "" && sanitizer.Regex == "" {
				return nil, fmt.Errorf("framework %s: custom sanitizer must set func or regex", name)
			}
			sp := fwpatterns.SanitizerPattern{FuncName: sanitizer.Func}
			if sanitizer.Regex != "" {
				re, err := regexp.Compile(sanitizer.Regex)
				if err != nil {
					return nil, fmt.Errorf("framework %s: invalid sanitizer regex %q: %w", name, sanitizer.Regex, err)
				}
				sp.Regex = re
			}
			packOverride.Sanitizers = append(packOverride.Sanitizers, sp)
		}
		for ruleID, severity := range override.SeverityOverrides {
			sev, err := parseSeverityStrict(severity)
			if err != nil {
				return nil, fmt.Errorf("framework %s rule %s: %w", name, ruleID, err)
			}
			packOverride.SeverityOverrides[ruleID] = sev
		}

		out[name] = packOverride
	}
	return out, nil
}

// parseLanguage converts a string language name to a patterns.Language.
func parseLanguage(s string) (patterns.Language, error) {
	switch s {
	case "python", "py":
		return patterns.LangPython, nil
	case "javascript", "js":
		return patterns.LangJavaScript, nil
	case "typescript", "ts":
		return patterns.LangTypeScript, nil
	case "ruby", "rb":
		return patterns.LangRuby, nil
	case "php":
		return patterns.LangPHP, nil
	default:
		return "", fmt.Errorf("unsupported language: %s (supported: python, javascript, typescript, ruby, php)", s)
	}
}

// parseSeverity converts a string to an analysis.Severity.
func parseSeverity(s string) analysis.Severity {
	switch s {
	case "critical":
		return analysis.SeverityCritical
	case "high":
		return analysis.SeverityHigh
	case "medium":
		return analysis.SeverityMedium
	case "low":
		return analysis.SeverityLow
	case "info":
		return analysis.SeverityInfo
	default:
		return analysis.SeverityMedium // default
	}
}

func parseSeverityStrict(s string) (analysis.Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return analysis.SeverityCritical, nil
	case "high":
		return analysis.SeverityHigh, nil
	case "medium":
		return analysis.SeverityMedium, nil
	case "low":
		return analysis.SeverityLow, nil
	case "info":
		return analysis.SeverityInfo, nil
	default:
		return "", fmt.Errorf("invalid severity %q (must be one of: info, low, medium, high, critical)", s)
	}
}

// parseConfidence converts a string to an analysis.Confidence.
func parseConfidence(s string) analysis.Confidence {
	switch s {
	case "high":
		return analysis.ConfidenceHigh
	case "medium":
		return analysis.ConfidenceMedium
	case "low":
		return analysis.ConfidenceLow
	default:
		return analysis.ConfidenceMedium // default
	}
}
