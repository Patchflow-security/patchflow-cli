package echo

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sources = []frameworks.SourcePattern{
	{FuncName: "c.QueryParam"},
	{FuncName: "c.Param"},
	{FuncName: "c.FormValue"},
	{FuncName: "c.Request().Header.Get"},
}
