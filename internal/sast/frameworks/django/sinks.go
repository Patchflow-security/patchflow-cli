package django

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sinks = []frameworks.SinkPattern{
	{FuncName: "raw", ArgIndex: 0},
	{FuncName: "extra", ArgIndex: -1},
	{FuncName: "cursor.execute", ArgIndex: 0},
	{FuncName: "RawSQL", ArgIndex: 0},
	{FuncName: "redirect", ArgIndex: 0},
	{FuncName: "mark_safe", ArgIndex: 0},
	{FuncName: "pickle.loads", ArgIndex: 0},
	{FuncName: "yaml.load", ArgIndex: 0},
	{FuncName: "requests.get", ArgIndex: 0},
	{FuncName: "httpx.get", ArgIndex: 0},
	{FuncName: "subprocess.run", ArgIndex: 0},
}
