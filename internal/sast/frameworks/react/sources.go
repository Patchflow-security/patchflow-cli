package react

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sources = []frameworks.SourcePattern{
	{FuncName: "props", IsSubscript: true},
	{FuncName: "state", IsSubscript: true},
	{FuncName: "location.search"},
	{FuncName: "URLSearchParams"},
	{FuncName: "useSearchParams"},
	{FuncName: "useParams"},
	{FuncName: "useLocation"},
	{FuncName: "response", IsSubscript: true},
	{FuncName: "data", IsSubscript: true},
}
