package fastapi

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

// Sinks are the FastAPI/Python dangerous APIs that tainted data must not reach.
var Sinks = []frameworks.SinkPattern{
	{FuncName: "execute", ArgIndex: 0},
	{FuncName: "executemany", ArgIndex: 0},
	{FuncName: "text", ArgIndex: 0},
	{FuncName: "session.execute", ArgIndex: 0},
	{FuncName: "requests.get", ArgIndex: 0},
	{FuncName: "requests.post", ArgIndex: 0},
	{FuncName: "httpx.get", ArgIndex: 0},
	{FuncName: "httpx.post", ArgIndex: 0},
	{FuncName: "RedirectResponse", ArgIndex: 0},
	{FuncName: "subprocess.run", ArgIndex: 0},
	{FuncName: "subprocess.Popen", ArgIndex: 0},
	{FuncName: "subprocess.call", ArgIndex: 0},
	{FuncName: "subprocess.check_output", ArgIndex: 0},
	{FuncName: "FileResponse", ArgIndex: 0},
	{FuncName: "open", ArgIndex: 0},
}
