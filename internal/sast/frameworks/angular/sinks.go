package angular

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sinks = []frameworks.SinkPattern{
	// Angular DomSanitizer bypass methods — these disable Angular's built-in
	// XSS protections, making any input trusted.
	{FuncName: "bypassSecurityTrustHtml", ArgIndex: 0},
	{FuncName: "bypassSecurityTrustUrl", ArgIndex: 0},
	{FuncName: "bypassSecurityTrustResourceUrl", ArgIndex: 0},
	{FuncName: "bypassSecurityTrustScript", ArgIndex: 0},

	// Direct DOM manipulation — bypasses Angular's template sanitization.
	{FuncName: "innerHTML", ArgIndex: -1},
	{FuncName: "nativeElement.innerHTML", ArgIndex: -1},
	{FuncName: "insertAdjacentHTML", ArgIndex: -1},
	{FuncName: "outerHTML", ArgIndex: -1},

	// Client-side navigation — open redirect risk.
	{FuncName: "navigateByUrl", ArgIndex: 0},
	{FuncName: "navigate", ArgIndex: 0},
	{FuncName: "window.location", ArgIndex: -1},
	{FuncName: "document.location", ArgIndex: -1},

	// Dynamic component/template creation — can inject untrusted content.
	{FuncName: "createComponent", ArgIndex: -1},
	{FuncName: "ViewContainerRef.createComponent", ArgIndex: -1},
}
