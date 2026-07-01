package springsecurity

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sanitizers = []frameworks.SanitizerPattern{
	{FuncName: "hasRole"},
	{FuncName: "hasAuthority"},
	{FuncName: "authenticated"},
	{FuncName: "@PreAuthorize"},
}
