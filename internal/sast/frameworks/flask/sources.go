package flask

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sources = []frameworks.SourcePattern{
	{FuncName: "request.args", IsSubscript: true},
	{FuncName: "request.form", IsSubscript: true},
	{FuncName: "request.values", IsSubscript: true},
	{FuncName: "request.headers", IsSubscript: true},
	{FuncName: "request.cookies", IsSubscript: true},
	{FuncName: "request.get_json"},
}
