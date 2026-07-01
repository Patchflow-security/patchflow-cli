package fastapi

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

// Sources are the FastAPI request-derived taint entry points.
var Sources = []frameworks.SourcePattern{
	{FuncName: "request.query_params", IsSubscript: true},
	{FuncName: "request.path_params", IsSubscript: true},
	{FuncName: "request.headers", IsSubscript: true},
	{FuncName: "request.cookies", IsSubscript: true},
	{FuncName: "request.json"},
	{FuncName: "request.form"},
	{FuncName: "Query"},
	{FuncName: "Path"},
	{FuncName: "Header"},
	{FuncName: "Cookie"},
	{FuncName: "Body"},
}
