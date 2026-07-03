package nextjs

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sources = []frameworks.SourcePattern{
	{FuncName: "req.query", IsSubscript: true},
	{FuncName: "searchParams", IsSubscript: true},
	{FuncName: "params", IsSubscript: true},
	{FuncName: "cookies"},
	{FuncName: "headers"},
	{FuncName: "request.nextUrl.searchParams"},
	{FuncName: "request.nextUrl"},
	{FuncName: "NextRequest"},
	{FuncName: "formData"},
}
