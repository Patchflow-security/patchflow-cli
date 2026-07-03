package angular

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sanitizers = []frameworks.SanitizerPattern{
	// Angular's built-in DOM sanitizer
	{FuncName: "DomSanitizer.sanitize"},
	{FuncName: "sanitizer.sanitize"},

	// Third-party sanitizers
	{FuncName: "DOMPurify.sanitize"},
	{FuncName: "sanitizeHtml"},

	// URL encoding / validation
	{FuncName: "encodeURIComponent"},
	{FuncName: "isSafeUrl"},
	{FuncName: "validateUrl"},

	// Angular interpolation {{ value }} is safe by default —
	// the template engine auto-escapes. No sanitizer needed for interpolation.
}
