package graphql

import (
	"regexp"

	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

var Sanitizers = []frameworks.SanitizerPattern{
	// SQL parameterization
	{FuncName: "bindparam"},
	{Regex: regexp.MustCompile(`execute\s*\([^,]+,\s*\{[^}]+\}\)`)}, // parameterized execute

	// URL validation
	{FuncName: "url_has_allowed_host_and_scheme"},
	{FuncName: "is_safe_url"},

	// Path sanitization
	{FuncName: "secure_filename"},
	{FuncName: "safe_join"},

	// HTML escaping
	{FuncName: "escape"},
	{FuncName: "markupsafe.escape"},
	{FuncName: "html.escape"},
}
