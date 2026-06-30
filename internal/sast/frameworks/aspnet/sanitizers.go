package aspnet

import (
	"regexp"

	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

var Sanitizers = []frameworks.SanitizerPattern{
	{FuncName: "HtmlEncoder.Default.Encode"},
	{FuncName: "WebUtility.HtmlEncode"},
	{FuncName: "Url.IsLocalUrl"},
	{FuncName: "LocalRedirect"},
	{Regex: regexp.MustCompile(`FromSqlInterpolated|ExecuteSqlInterpolated`)},
	{Regex: regexp.MustCompile(`new\s+SqlParameter`)},
}
