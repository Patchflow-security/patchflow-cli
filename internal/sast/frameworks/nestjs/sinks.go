package nestjs

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sinks = []frameworks.SinkPattern{
	{FuncName: "query", ArgIndex: 0},
	{FuncName: "redirect", ArgIndex: 0},
	{FuncName: "HttpService.get", ArgIndex: 0},
	{FuncName: "axios.get", ArgIndex: 0},
	{FuncName: "exec", ArgIndex: 0},
}
