package symfony

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sanitizers = []frameworks.SanitizerPattern{
	{FuncName: "setParameter"},
	{FuncName: "escape"},
	{FuncName: "htmlspecialchars"},
	{FuncName: "UrlHelper"},
	{FuncName: "isSafeRedirect"},
}
