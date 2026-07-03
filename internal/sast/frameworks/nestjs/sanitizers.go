package nestjs

import (
	"regexp"

	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

var Sanitizers = []frameworks.SanitizerPattern{
	{FuncName: "encodeURIComponent"},
	{FuncName: "isSafeRedirect"},
	{FuncName: "allowlistedHost"},
	{FuncName: "ValidationPipe"},
	{FuncName: "Passport"},
	{Regex: regexp.MustCompile(`\.query\s*\([^,]+,\s*\[[^\]]+\]`)},
}
