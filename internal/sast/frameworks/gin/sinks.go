package gin

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sinks = []frameworks.SinkPattern{
	{FuncName: "db.Raw", ArgIndex: 0},
	{FuncName: "db.Exec", ArgIndex: 0},
	{FuncName: "c.Redirect", ArgIndex: 1},
	{FuncName: "c.String", ArgIndex: 1},
	{FuncName: "exec.Command", ArgIndex: -1},
	{FuncName: "c.File", ArgIndex: 0},
}
