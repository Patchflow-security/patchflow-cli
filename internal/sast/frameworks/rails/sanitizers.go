package rails

import (
	"regexp"

	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

// Sanitizers are the Rails functions/patterns that clear taint or render
// output safe. When a sink match line also contains a sanitizer, the matcher
// suppresses the finding.
var Sanitizers = []frameworks.SanitizerPattern{
	{FuncName: "sanitize"},
	{FuncName: "html_escape"},
	{FuncName: "ERB::Util.html_escape"},
	{FuncName: "ERB::Util.h"},
	{FuncName: "h("},
	// permit with an explicit field allowlist clears mass-assignment taint.
	{Regex: regexp.MustCompile(`\.permit\(([^*!)]+)\)`)},
	// Parameterized query indicators.
	{FuncName: "where("},
	{FuncName: "find_by("},
	{FuncName: "sanitize_sql"},
	{FuncName: "sanitize_sql_array"},
	{FuncName: "sanitize_sql_for"},
	// Allowlisted redirect target.
	{FuncName: "url_for"},
}
