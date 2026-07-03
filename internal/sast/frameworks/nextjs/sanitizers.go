package nextjs

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sanitizers = []frameworks.SanitizerPattern{
	{FuncName: "encodeURIComponent"},
	{FuncName: "isSafeRedirect"},
	{FuncName: "allowlistedHost"},
	{FuncName: "new URL"},
	{FuncName: "server-only"},
}
