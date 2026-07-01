package laravel

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sources = []frameworks.SourcePattern{
	{FuncName: "request"},
	{FuncName: "$request->input"},
	{FuncName: "$request->query"},
	{FuncName: "$request->all"},
	{FuncName: "$_GET", IsSubscript: true},
	{FuncName: "$_POST", IsSubscript: true},
	{FuncName: "$_REQUEST", IsSubscript: true},
}
