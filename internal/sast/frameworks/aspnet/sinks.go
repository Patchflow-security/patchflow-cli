package aspnet

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sinks = []frameworks.SinkPattern{
	{FuncName: "FromSqlRaw", ArgIndex: 0},
	{FuncName: "ExecuteSqlRaw", ArgIndex: 0},
	{FuncName: "SqlCommand", ArgIndex: 0},
	{FuncName: "Redirect", ArgIndex: 0},
	{FuncName: "HtmlString", ArgIndex: 0},
	{FuncName: "Content", ArgIndex: 0},
	{FuncName: "BinaryFormatter.Deserialize", ArgIndex: 0},
	{FuncName: "Process.Start", ArgIndex: 0},
	{FuncName: "Path.Combine", ArgIndex: 1},
}
