package flask

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sinks = []frameworks.SinkPattern{
	{FuncName: "cursor.execute", ArgIndex: 0},
	{FuncName: "db.session.execute", ArgIndex: 0},
	{FuncName: "requests.get", ArgIndex: 0},
	{FuncName: "redirect", ArgIndex: 0},
	{FuncName: "Markup", ArgIndex: 0},
	{FuncName: "render_template_string", ArgIndex: 0},
	{FuncName: "send_file", ArgIndex: 0},
}
