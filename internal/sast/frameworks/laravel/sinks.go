package laravel

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sinks = []frameworks.SinkPattern{
	{FuncName: "DB::raw", ArgIndex: 0},
	{FuncName: "DB::select", ArgIndex: 0},
	{FuncName: "DB::statement", ArgIndex: 0},
	{FuncName: "redirect()->away", ArgIndex: 0},
	{FuncName: "View::make", ArgIndex: -1},
	{FuncName: "create", ArgIndex: 0},
}
