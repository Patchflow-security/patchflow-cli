package symfony

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sinks = []frameworks.SinkPattern{
	{FuncName: "createQuery", ArgIndex: 0},
	{FuncName: "executeQuery", ArgIndex: 0},
	{FuncName: "RedirectResponse", ArgIndex: 0},
	{FuncName: "Response", ArgIndex: 0},
}
