package angular

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sinks = []frameworks.SinkPattern{
	{FuncName: "bypassSecurityTrustHtml", ArgIndex: 0},
	{FuncName: "bypassSecurityTrustUrl", ArgIndex: 0},
	{FuncName: "innerHTML", ArgIndex: -1},
	{FuncName: "router.navigateByUrl", ArgIndex: 0},
}
