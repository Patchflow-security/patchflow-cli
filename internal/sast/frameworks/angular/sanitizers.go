package angular

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sanitizers = []frameworks.SanitizerPattern{
	{FuncName: "DomSanitizer.sanitize"},
	{FuncName: "encodeURIComponent"},
	{FuncName: "isSafeUrl"},
}
