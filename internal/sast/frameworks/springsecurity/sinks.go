package springsecurity

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sinks = []frameworks.SinkPattern{
	{FuncName: "permitAll", ArgIndex: -1},
	{FuncName: "csrf.disable", ArgIndex: -1},
	{FuncName: "web.ignoring", ArgIndex: -1},
	{FuncName: "@PermitAll", ArgIndex: -1},
}
