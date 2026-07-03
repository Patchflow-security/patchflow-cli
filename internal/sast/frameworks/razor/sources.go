package razor

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sources = []frameworks.SourcePattern{
	{FuncName: "Request.Query", IsSubscript: true},
	{FuncName: "Model", IsSubscript: true},
	{FuncName: "ViewBag", IsSubscript: true},
	{FuncName: "ViewData", IsSubscript: true},
}
