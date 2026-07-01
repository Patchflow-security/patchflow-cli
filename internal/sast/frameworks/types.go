// Package frameworks holds the framework-aware SAST rule model and the
// registry/loader that activates official embedded framework packs based on
// project framework detection.
//
// A framework rule is typed Go data (not loose YAML): it declares a match
// mode, language, framework, file/template extensions, sources, sinks,
// sanitizers, safe patterns, exclusions, and governance metadata. Rules are
// compiled into the binary and versioned with PatchFlow releases.
//
// Match modes:
//   - MatchPattern:  simple dangerous-API regex (fast, line-oriented)
//   - MatchAST:      framework-specific call structures (tree-sitter)
//   - MatchTaint:    user input -> dangerous sink (feeds the taint engine)
//   - MatchTemplate: ERB/Jinja/Razor/Blade/JSX output issues
package frameworks

import (
	"regexp"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
)

// MatchMode declares how a framework rule is evaluated.
type MatchMode int

const (
	// MatchPattern matches a compiled regex against source lines. Used for
	// simple dangerous APIs (e.g. Rails html_safe, Spring permitAll).
	MatchPattern MatchMode = iota
	// MatchAST matches framework-specific call structures via tree-sitter.
	// Reserved for packs that need structural matching beyond regex.
	MatchAST
	// MatchTaint declares a source->sink taint rule. The framework pack
	// supplies sources/sinks/sanitizers; the existing taintpatterns engine
	// performs the actual taint tracking and reports findings under this
	// rule's ID.
	MatchTaint
	// MatchTemplate matches template-engine output issues (ERB raw output,
	// Jinja |safe, Razor @Html.Raw, Blade {!! !!}, JSX dangerouslySetInnerHTML).
	MatchTemplate
)

// Maturity is the governance maturity level of a framework rule. It mirrors
// rules.Maturity but is declared here to avoid an import cycle between
// internal/sast/frameworks and internal/rules. Conversion to rules.Maturity
// happens at the governance registration boundary (see ToRulesMaturity).
type Maturity int

const (
	MaturityExperimental Maturity = 0
	MaturityBeta         Maturity = 1
	MaturityStable       Maturity = 2
	MaturityEnterprise   Maturity = 3
)

// String returns the human-readable maturity name.
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
	}
	return "unknown"
}

// String returns the human-readable match mode name.
func (m MatchMode) String() string {
	switch m {
	case MatchPattern:
		return "pattern"
	case MatchAST:
		return "ast"
	case MatchTaint:
		return "taint"
	case MatchTemplate:
		return "template"
	}
	return "unknown"
}

// SourcePattern declares where tainted data enters a framework flow.
type SourcePattern struct {
	// FuncName is the receiver-qualified name (e.g. "params", "request.GET",
	// "@RequestParam", "Request.Query").
	FuncName string
	// IsSubscript indicates subscript access (e.g. params[:id], request.GET["x"]).
	IsSubscript bool
	// Annotation matches a Java/C# attribute source (e.g. "@RequestParam",
	// "@PathVariable", "[FromQuery]").
	Annotation string
}

// SinkPattern declares where tainted data should not flow.
type SinkPattern struct {
	// FuncName is the receiver-qualified sink name (e.g. "redirect_to",
	// "cursor.execute", "Html.Raw", "RestTemplate").
	FuncName string
	// ArgIndex is the 0-based argument index that must be tainted; -1 = any.
	ArgIndex int
}

// SanitizerPattern declares a function/pattern that clears taint.
type SanitizerPattern struct {
	// FuncName is the sanitizer name (e.g. "sanitize", "html_escape",
	// "Url.IsLocalUrl", "parameterized query").
	FuncName string
	// Regex is an optional regex that, when matched on the same line as the
	// sink, suppresses the finding (e.g. a prepared-statement indicator).
	Regex *regexp.Regexp
}

// SafePattern declares a regex that, if present, marks a would-be match as
// safe (no finding). Safe patterns are checked after a sink/source match and
// before emitting a finding.
type SafePattern struct {
	// Regex matched against the candidate line.
	Regex *regexp.Regexp
	// Reason is surfaced in explain output.
	Reason string
}

// PathPattern declares a path glob to exclude from a rule.
type PathPattern struct {
	// Glob matched against the file path relative to root.
	Glob string
	// Reason is surfaced in explain output.
	Reason string
}

// FrameworkRule is a typed, framework-scoped security rule.
type FrameworkRule struct {
	ID         string
	Framework  string // canonical framework name (e.g. "rails", "spring")
	Language   string // primary language
	CWE        string
	Title      string
	Severity   analysis.Severity
	Confidence analysis.Confidence
	// Maturity governs profile activation and CI blocking eligibility.
	Maturity Maturity

	// FileTypes are the file extensions this rule applies to (e.g. ".rb",
	// ".erb"). Empty means all files owned by the pack.
	FileTypes []string
	// TemplateTypes are template extensions this rule applies to (template
	// rules only).
	TemplateTypes []string

	MatchMode MatchMode

	// Pattern is the regex for MatchPattern and MatchTemplate rules.
	Pattern *regexp.Regexp

	// Sources/Sinks/Sanitizers are used by MatchTaint rules (and may be
	// referenced by MatchPattern rules for context in explain output).
	Sources     []SourcePattern
	Sinks       []SinkPattern
	Sanitizers  []SanitizerPattern
	SafePatterns []SafePattern
	Exclusions  []PathPattern

	// Recommendation is the fix guidance surfaced by `patchflow rules explain`.
	Recommendation string
}

// Pack is a framework rule pack: the official, embedded, tested set of rules,
// sources, sinks, sanitizers, and template metadata for one framework.
type Pack interface {
	// Name returns the canonical framework name (must match a frameworks.Name).
	Name() string
	// Language returns the primary language.
	Language() string
	// FileExtensions returns source file extensions owned by the pack.
	FileExtensions() []string
	// TemplateExtensions returns template extensions owned by the pack.
	TemplateExtensions() []string
	// Rules returns the pack's typed framework rules.
	Rules() []FrameworkRule
	// Sources returns the pack's taint source catalog (used to register
	// sources into the taint engine for MatchTaint rules).
	Sources() []SourcePattern
	// Sinks returns the pack's taint sink catalog.
	Sinks() []SinkPattern
	// Sanitizers returns the pack's sanitizer catalog.
	Sanitizers() []SanitizerPattern
}
