package express

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sinks = []frameworks.SinkPattern{
	{FuncName: "query", ArgIndex: 0},
	{FuncName: "res.redirect", ArgIndex: 0},
	{FuncName: "res.send", ArgIndex: 0},
	{FuncName: "res.render", ArgIndex: 1},
	{FuncName: "child_process.exec", ArgIndex: 0},
	{FuncName: "fs.readFile", ArgIndex: 0},
	{FuncName: "fs.createReadStream", ArgIndex: 0},
}
