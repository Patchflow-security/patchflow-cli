package razor

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sinks = []frameworks.SinkPattern{
	{FuncName: "Html.Raw", ArgIndex: 0},
	{FuncName: "MarkupString", ArgIndex: 0},
}
