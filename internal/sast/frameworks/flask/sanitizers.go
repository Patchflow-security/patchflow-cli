package flask

import (
	"regexp"

	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

var Sanitizers = []frameworks.SanitizerPattern{
	{FuncName: "escape"},
	{FuncName: "markupsafe.escape"},
	{FuncName: "html.escape"},
	{FuncName: "url_has_allowed_host_and_scheme"},
	{FuncName: "is_safe_url"},
	{Regex: regexp.MustCompile(`execute\s*\([^,]+,\s*[^)]+\)`)},
}
