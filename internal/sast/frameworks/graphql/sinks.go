package graphql

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sinks = []frameworks.SinkPattern{
	// SQLAlchemy raw SQL
	{FuncName: "text", ArgIndex: 0},
	{FuncName: "execute", ArgIndex: 0},
	{FuncName: "session.execute", ArgIndex: 0},
	{FuncName: "db.session.execute", ArgIndex: 0},

	// HTTP client — SSRF
	{FuncName: "requests.get", ArgIndex: 0},
	{FuncName: "requests.post", ArgIndex: 0},
	{FuncName: "httpx.get", ArgIndex: 0},
	{FuncName: "httpx.post", ArgIndex: 0},

	// File system — path traversal
	{FuncName: "open", ArgIndex: 0},
	{FuncName: "send_file", ArgIndex: 0},
	{FuncName: "send_from_directory", ArgIndex: 0},
}
