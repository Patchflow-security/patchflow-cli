package laravel

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sources = []frameworks.SourcePattern{
	{FuncName: "request"},
	{FuncName: "request()"},
	{FuncName: "$request->input"},
	{FuncName: "$request->query"},
	{FuncName: "$request->get"},
	{FuncName: "$request->all"},
	{FuncName: "Input::get"},
	{FuncName: "$_GET", IsSubscript: true},
	{FuncName: "$_POST", IsSubscript: true},
	{FuncName: "$_REQUEST", IsSubscript: true},
	{FuncName: "$_COOKIE", IsSubscript: true},
}
