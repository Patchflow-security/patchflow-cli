package react

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sanitizers = []frameworks.SanitizerPattern{
	{FuncName: "DOMPurify.sanitize"},
	{FuncName: "sanitizeHtml"},
	{FuncName: "encodeURIComponent"},
	{FuncName: "isSafeRedirect"},
}
