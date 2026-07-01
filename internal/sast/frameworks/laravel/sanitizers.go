package laravel

import (
	"regexp"

	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

var Sanitizers = []frameworks.SanitizerPattern{
	{FuncName: "e("},
	{FuncName: "htmlspecialchars"},
	{FuncName: "strip_tags"},
	{FuncName: "route("},
	{FuncName: "url("},
	{FuncName: "Validator::make"},
	{Regex: regexp.MustCompile(`DB::select\s*\([^,]+,\s*\[[^\]]+\]`)},
}
