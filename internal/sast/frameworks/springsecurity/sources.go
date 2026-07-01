package springsecurity

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sources = []frameworks.SourcePattern{
	{FuncName: "HttpSecurity"},
	{FuncName: "SecurityFilterChain"},
	{FuncName: "@RequestMapping", Annotation: "@RequestMapping"},
}
