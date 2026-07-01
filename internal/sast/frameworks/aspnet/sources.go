package aspnet

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sources = []frameworks.SourcePattern{
	{FuncName: "Request.Query", IsSubscript: true},
	{FuncName: "Request.Form", IsSubscript: true},
	{FuncName: "Request.Headers", IsSubscript: true},
	{FuncName: "HttpContext.Request.Query", IsSubscript: true},
	{FuncName: "[FromQuery]", Annotation: "[FromQuery]"},
	{FuncName: "[FromBody]", Annotation: "[FromBody]"},
}
