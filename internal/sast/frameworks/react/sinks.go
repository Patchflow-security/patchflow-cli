package react

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sinks = []frameworks.SinkPattern{
	{FuncName: "dangerouslySetInnerHTML", ArgIndex: -1},
	{FuncName: "window.location", ArgIndex: -1},
	{FuncName: "router.push", ArgIndex: 0},
}
