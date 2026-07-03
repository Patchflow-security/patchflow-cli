package express

import (
	"regexp"

	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

var Sanitizers = []frameworks.SanitizerPattern{
	{FuncName: "escapeHtml"},
	{FuncName: "validator.escape"},
	{FuncName: "DOMPurify.sanitize"},
	{FuncName: "express-validator"},
	{FuncName: "encodeURIComponent"},
	{FuncName: "isSafeRedirect"},
	{FuncName: "allowlistedHost"},
	{FuncName: "path.resolve"},
	{Regex: regexp.MustCompile(`\.query\s*\([^,]+,\s*\[[^\]]+\]`)},
}
