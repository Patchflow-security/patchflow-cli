package gin

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sources = []frameworks.SourcePattern{
	{FuncName: "c.Query"},
	{FuncName: "c.Param"},
	{FuncName: "c.PostForm"},
	{FuncName: "c.GetHeader"},
	{FuncName: "c.Request.URL.Query", IsSubscript: true},
}
