package razor

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sanitizers = []frameworks.SanitizerPattern{
	{FuncName: "Html.Encode"},
	{FuncName: "WebUtility.HtmlEncode"},
	{FuncName: "HtmlEncoder.Default.Encode"},
}
