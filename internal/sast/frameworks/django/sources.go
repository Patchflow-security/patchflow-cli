package django

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sources = []frameworks.SourcePattern{
	{FuncName: "request.GET", IsSubscript: true},
	{FuncName: "request.POST", IsSubscript: true},
	{FuncName: "request.COOKIES", IsSubscript: true},
	{FuncName: "request.headers", IsSubscript: true},
	{FuncName: "request.body"},
	{FuncName: "request.data"},
	{FuncName: "request.FILES", IsSubscript: true},
	{FuncName: "request.META", IsSubscript: true},
}
