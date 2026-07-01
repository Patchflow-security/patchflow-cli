package rails

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

// Sources are the Rails taint entry points: request data that an attacker
// controls. These feed the taint engine for MatchTaint rules.
var Sources = []frameworks.SourcePattern{
	{FuncName: "params", IsSubscript: true},
	{FuncName: "cookies", IsSubscript: true},
	{FuncName: "request.headers", IsSubscript: true},
	{FuncName: "request.query_parameters"},
	{FuncName: "request.request_parameters"},
	{FuncName: "request.GET"},
	{FuncName: "request.POST"},
}
