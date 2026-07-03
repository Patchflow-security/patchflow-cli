package nextjs

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sinks = []frameworks.SinkPattern{
	{FuncName: "fetch", ArgIndex: 0},
	{FuncName: "redirect", ArgIndex: 0},
	{FuncName: "NextResponse.redirect", ArgIndex: 0},
	{FuncName: "router.push", ArgIndex: 0},
	{FuncName: "axios.get", ArgIndex: 0},
	{FuncName: "process.env.NEXT_PUBLIC_", ArgIndex: -1},
}
