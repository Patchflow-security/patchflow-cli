package angular

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sources = []frameworks.SourcePattern{
	{FuncName: "ActivatedRoute"},
	{FuncName: "queryParams"},
	{FuncName: "paramMap"},
	{FuncName: "location.search"},
}
