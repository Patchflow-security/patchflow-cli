package echo

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sanitizers = []frameworks.SanitizerPattern{
	{FuncName: "html.EscapeString"},
	{FuncName: "url.QueryEscape"},
	{FuncName: "filepath.Clean"},
	{FuncName: "isSafeRedirect"},
}
