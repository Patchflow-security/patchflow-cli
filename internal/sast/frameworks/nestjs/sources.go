package nestjs

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sources = []frameworks.SourcePattern{
	{FuncName: "@Query", Annotation: "@Query"},
	{FuncName: "@Param", Annotation: "@Param"},
	{FuncName: "@Body", Annotation: "@Body"},
	{FuncName: "@Headers", Annotation: "@Headers"},
	{FuncName: "req.query", IsSubscript: true},
	{FuncName: "req.body", IsSubscript: true},
}
