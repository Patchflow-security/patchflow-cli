package django

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sinks = []frameworks.SinkPattern{
	{FuncName: "raw", ArgIndex: 0},
	{FuncName: "extra", ArgIndex: -1},
	{FuncName: "cursor.execute", ArgIndex: 0},
	{FuncName: "redirect", ArgIndex: 0},
	{FuncName: "mark_safe", ArgIndex: 0},
	{FuncName: "pickle.loads", ArgIndex: 0},
}
