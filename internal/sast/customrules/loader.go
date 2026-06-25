// Package customrules provides loading and validation of user-defined
// security rules from YAML files. Users can create custom rules in
// `.patchflow/rules.yaml` or specify a path with `--rules <path>`.
//
// Example rules.yaml:
//
//   rules:
//     - id: CUSTOM-001
//       title: No console.log in production
//       description: console.log should not be used in production code
//       languages: [javascript, typescript]
//       pattern: 'console\.log\s*\('
//       severity: low
//       confidence: high
//
//     - id: CUSTOM-002
//       title: Must use parameterized queries
//       description: Raw SQL with string interpolation is vulnerable to SQL injection
//       languages: [python]
//       pattern: 'cursor\.execute\(.*%.*'
//       severity: high
//       confidence: medium
package customrules

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/patchflow/patchflow-cli/internal/analysis"
	"github.com/patchflow/patchflow-cli/internal/sast/patterns"
	"gopkg.in/yaml.v3"
)

// RuleFile represents the YAML structure of a custom rules file.
type RuleFile struct {
	Rules []YAMLRule `yaml:"rules"`
}

// YAMLRule represents a single rule definition in the YAML file.
type YAMLRule struct {
	ID          string   `yaml:"id"`
	Title       string   `yaml:"title"`
	Description string   `yaml:"description"`
	Languages   []string `yaml:"languages"`
	Pattern     string   `yaml:"pattern"`
	Severity    string   `yaml:"severity"`
	Confidence  string   `yaml:"confidence"`
}

// LoadFromFile loads custom rules from a YAML file.
// Returns a slice of PatternRule that can be added to the patterns.Scanner.
func LoadFromFile(path string) ([]patterns.PatternRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file: %w", err)
	}

	return LoadFromBytes(data)
}

// LoadFromBytes loads custom rules from YAML bytes.
func LoadFromBytes(data []byte) ([]patterns.PatternRule, error) {
	var ruleFile RuleFile
	if err := yaml.Unmarshal(data, &ruleFile); err != nil {
		return nil, fmt.Errorf("failed to parse rules YAML: %w", err)
	}

	var rules []patterns.PatternRule
	for i, yr := range ruleFile.Rules {
		rule, err := convertRule(yr, i)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}

	return rules, nil
}

// LoadFromDir loads custom rules from `.patchflow/rules.yaml` in the given directory.
// Returns empty slice if the file doesn't exist (not an error).
func LoadFromDir(dir string) ([]patterns.PatternRule, error) {
	path := filepath.Join(dir, ".patchflow", "rules.yaml")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	}
	return LoadFromFile(path)
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
