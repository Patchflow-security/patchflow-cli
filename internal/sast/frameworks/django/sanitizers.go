package django

import (
	"regexp"

	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

var Sanitizers = []frameworks.SanitizerPattern{
	{FuncName: "escape"},
	{FuncName: "conditional_escape"},
	{FuncName: "format_html"},
	{FuncName: "url_has_allowed_host_and_scheme"},
	{FuncName: "bleach.clean"},
	{FuncName: "yaml.safe_load"},
	{Regex: regexp.MustCompile(`execute\s*\([^,]+,\s*\[[^\]]+\]`)},
	{Regex: regexp.MustCompile(`RawSQL\s*\([^,]+,\s*\[`)},
}
