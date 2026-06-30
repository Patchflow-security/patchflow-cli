package frameworks

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
)

// MatchableRule is a FrameworkRule narrowed to the pattern/template match
// modes that this matcher evaluates. Taint and AST rules are handled by the
// taint engine and tree-sitter respectively; the matcher skips them.
type MatchableRule struct {
	FrameworkRule
}

// IsMatchable returns true if the rule can be evaluated by the line matcher
// (MatchPattern or MatchTemplate).
func (r FrameworkRule) IsMatchable() bool {
	return r.MatchMode == MatchPattern || r.MatchMode == MatchTemplate
}

// Matcher evaluates MatchPattern and MatchTemplate framework rules against
// files. It is line-oriented and applies safe-pattern and sanitizer checks
// before emitting a finding, which keeps false positives down without needing
// a full AST.
type Matcher struct {
	rules []FrameworkRule
}

// NewMatcher builds a matcher from a set of framework rules. Only matchable
// rules (pattern/template) are retained; taint and AST rules are ignored.
func NewMatcher(rules []FrameworkRule) *Matcher {
	var keep []FrameworkRule
	for _, r := range rules {
		if r.IsMatchable() {
			keep = append(keep, r)
		}
	}
	return &Matcher{rules: keep}
}

// Rules returns the matchable rules this matcher will evaluate.
func (m *Matcher) Rules() []FrameworkRule {
	return m.rules
}

// ScanFile evaluates all matchable rules against a single file. The language
// hint is used to skip comment lines for languages the matcher knows about.
func (m *Matcher) ScanFile(absPath, root string) ([]analysis.Finding, error) {
	relPath, _ := filepath.Rel(root, absPath)
	ext := DetectTemplateExtension(absPath)

	var findings []analysis.Finding
	for _, rule := range m.rules {
		if !ruleAppliesToExt(rule, ext) {
			continue
		}
		if isExcluded(rule, relPath) {
			continue
		}
		fs, err := scanFileForRule(rule, absPath, relPath)
		if err != nil {
			return findings, err
		}
		findings = append(findings, fs...)
	}
	return findings, nil
}

func ruleAppliesToExt(rule FrameworkRule, ext string) bool {
	if len(rule.FileTypes) == 0 && len(rule.TemplateTypes) == 0 {
		return true
	}
	for _, e := range rule.FileTypes {
		if strings.EqualFold(e, ext) {
			return true
		}
	}
	for _, e := range rule.TemplateTypes {
		if strings.EqualFold(e, ext) {
			return true
		}
	}
	return false
}

func isExcluded(rule FrameworkRule, relPath string) bool {
	rel := filepath.ToSlash(relPath)
	for _, ex := range rule.Exclusions {
		if ex.Glob == "" {
			continue
		}
		if ok, _ := filepath.Match(ex.Glob, filepath.Base(rel)); ok {
			return true
		}
		if ok, _ := filepath.Match(ex.Glob, rel); ok {
			return true
		}
	}
	return false
}

func scanFileForRule(rule FrameworkRule, absPath, relPath string) ([]analysis.Finding, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var findings []analysis.Finding
	scanner := bufio.NewScanner(f)
	// Allow long lines (templates/HTML can be wide).
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if rule.Pattern == nil {
			continue
		}
		loc := rule.Pattern.FindStringIndex(line)
		if loc == nil {
			continue
		}
		if hasSafePattern(rule, line) {
			continue
		}
		if hasSanitizer(rule, line) {
			continue
		}
		findings = append(findings, makeFrameworkFinding(rule, relPath, lineNum, line))
	}
	return findings, scanner.Err()
}

func hasSafePattern(rule FrameworkRule, line string) bool {
	for _, sp := range rule.SafePatterns {
		if sp.Regex != nil && sp.Regex.MatchString(line) {
			return true
		}
	}
	return false
}

func hasSanitizer(rule FrameworkRule, line string) bool {
	for _, s := range rule.Sanitizers {
		if s.Regex != nil && s.Regex.MatchString(line) {
			return true
		}
		if s.FuncName != "" && strings.Contains(line, s.FuncName) {
			return true
		}
	}
	return false
}

func makeFrameworkFinding(rule FrameworkRule, relPath string, lineNum int, line string) analysis.Finding {
	return analysis.Finding{
		ID:             fmtFrameworkFindingID(rule, relPath, lineNum),
		Type:           analysis.TypeSAST,
		Analyzer:       "framework-" + rule.Framework,
		Severity:       rule.Severity,
		Confidence:     rule.Confidence,
		Title:          rule.Title,
		Description:    rule.Recommendation,
		FilePath:       relPath,
		LineStart:      lineNum,
		RuleID:         rule.ID,
		CWEID:          rule.CWE,
		Evidence:       strings.TrimSpace(line),
		Recommendation: rule.Recommendation,
		DetectedAt:     time.Now(),
	}
}

func fmtFrameworkFindingID(rule FrameworkRule, relPath string, lineNum int) string {
	base := filepath.Base(relPath)
	return "framework-" + rule.Framework + "-" + rule.ID + "-" + base + "-" + itoa(lineNum)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// TaintRules extracts the MatchTaint rules from a set of framework rules.
// These are registered into the taint engine so it can track the framework's
// sources/sinks/sanitizers. Non-taint rules are ignored.
func TaintRules(rules []FrameworkRule) []FrameworkRule {
	var out []FrameworkRule
	for _, r := range rules {
		if r.MatchMode == MatchTaint {
			out = append(out, r)
		}
	}
	return out
}

// CompileRegex is a small helper used by pack definitions to build a regex
// that panics on error at init time. Pack regexes are static and vetted, so a
// bad pattern is a programmer error, not a runtime condition.
func CompileRegex(pattern string) *regexp.Regexp {
	return regexp.MustCompile(pattern)
}
