package flask

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sinks = []frameworks.SinkPattern{
	// SQL
	{FuncName: "cursor.execute", ArgIndex: 0},
	{FuncName: "session.execute", ArgIndex: 0},
	{FuncName: "db.session.execute", ArgIndex: 0},
	{FuncName: "text", ArgIndex: 0},
	{FuncName: "execute", ArgIndex: 0},

	// HTTP (SSRF)
	{FuncName: "requests.get", ArgIndex: 0},
	{FuncName: "requests.post", ArgIndex: 0},
	{FuncName: "httpx.get", ArgIndex: 0},
	{FuncName: "httpx.post", ArgIndex: 0},

	// Redirect
	{FuncName: "redirect", ArgIndex: 0},

	// Template injection
	{FuncName: "Markup", ArgIndex: 0},
	{FuncName: "render_template_string", ArgIndex: 0},

	// File system (path traversal)
	{FuncName: "send_file", ArgIndex: 0},
	{FuncName: "send_from_directory", ArgIndex: 0},
	{FuncName: "open", ArgIndex: 0},

	// Command injection
	{FuncName: "subprocess.run", ArgIndex: 0},
	{FuncName: "os.system", ArgIndex: 0},
}
