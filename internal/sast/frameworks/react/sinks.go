package react

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sinks = []frameworks.SinkPattern{
	{FuncName: "dangerouslySetInnerHTML", ArgIndex: -1},
	{FuncName: "window.location", ArgIndex: -1},
	{FuncName: "router.push", ArgIndex: 0},
	{FuncName: "innerHTML", ArgIndex: -1},
	{FuncName: "insertAdjacentHTML", ArgIndex: -1},
	{FuncName: "localStorage.setItem", ArgIndex: -1},
	{FuncName: "sessionStorage.setItem", ArgIndex: -1},
}
