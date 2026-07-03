package express

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sources = []frameworks.SourcePattern{
	{FuncName: "req.query", IsSubscript: true},
	{FuncName: "req.params", IsSubscript: true},
	{FuncName: "req.body", IsSubscript: true},
	{FuncName: "req.headers", IsSubscript: true},
	{FuncName: "req.cookies", IsSubscript: true},
}
