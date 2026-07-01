package rails

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

// Sinks are the Rails dangerous APIs that tainted data must not reach.
var Sinks = []frameworks.SinkPattern{
	{FuncName: "raw", ArgIndex: -1},
	{FuncName: "html_safe", ArgIndex: -1},
	{FuncName: "redirect_to", ArgIndex: 0},
	{FuncName: "send_file", ArgIndex: 0},
	{FuncName: "send_data", ArgIndex: -1},
	{FuncName: "find_by_sql", ArgIndex: 0},
	{FuncName: "constantize", ArgIndex: -1},
	{FuncName: "public_send", ArgIndex: -1},
	{FuncName: "render", ArgIndex: -1},
	{FuncName: "system", ArgIndex: 0},
}
