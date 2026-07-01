package fastapi

import (
	"regexp"

	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

// Sanitizers are the FastAPI/Python helpers that reduce or clear risk on the
// same line as a sink match.
var Sanitizers = []frameworks.SanitizerPattern{
	{FuncName: "html.escape"},
	{FuncName: "markupsafe.escape"},
	{FuncName: "urllib.parse.quote"},
	{FuncName: "is_safe_url"},
	{FuncName: "allow_redirect_host"},
	{FuncName: "Path.resolve"},
	{FuncName: "Path.is_relative_to"},
	{Regex: regexp.MustCompile(`execute\s*\([^,]+,\s*[^)]+\)`)},
}
