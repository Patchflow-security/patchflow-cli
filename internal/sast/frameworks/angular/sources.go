package angular

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

// Sources defines Angular-specific taint entry points.
//
// These patterns match how Angular code actually appears in practice:
// - `this.route.queryParams` (injected ActivatedRoute service)
// - `this.route.snapshot.paramMap` (snapshot access)
// - `this.route.snapshot.queryParams`
// - `activatedRoute.queryParams` (constructor parameter name)
//
// We include both the class-name pattern (ActivatedRoute.queryParams) and
// the instance-variable patterns (route.queryParams, activatedRoute.queryParams)
// because the taint engine uses string containment on AST node text.
var Sources = []frameworks.SourcePattern{
	// ActivatedRoute — instance variable patterns (most common in real code)
	{FuncName: "route.queryParams", IsSubscript: true},
	{FuncName: "route.params", IsSubscript: true},
	{FuncName: "route.paramMap", IsSubscript: true},
	{FuncName: "route.snapshot.paramMap", IsSubscript: true},
	{FuncName: "route.snapshot.params", IsSubscript: true},
	{FuncName: "route.snapshot.queryParams", IsSubscript: true},
	{FuncName: "route.snapshot.url", IsSubscript: true},
	{FuncName: "route.data", IsSubscript: true},
	{FuncName: "route.fragment", IsSubscript: true},

	// ActivatedRoute — class name patterns (less common but valid)
	{FuncName: "ActivatedRoute.queryParams", IsSubscript: true},
	{FuncName: "ActivatedRoute.params", IsSubscript: true},
	{FuncName: "ActivatedRoute.paramMap", IsSubscript: true},
	{FuncName: "ActivatedRoute.snapshot", IsSubscript: true},

	// Generic property names (matched via string containment)
	{FuncName: "queryParams"},
	{FuncName: "paramMap"},
	{FuncName: "location.search"},

	// FormControl / FormGroup — form user input
	{FuncName: "FormControl.value", IsSubscript: true},
	{FuncName: "FormGroup.value", IsSubscript: true},
	{FuncName: "formControl.value", IsSubscript: true},
	{FuncName: "formGroup.value", IsSubscript: true},
	{FuncName: ".value", IsSubscript: true},

	// HttpClient — response data from external APIs
	{FuncName: "HttpClient", IsSubscript: true},
	{FuncName: "http.get", IsSubscript: true},
	{FuncName: "http.post", IsSubscript: true},

	// @Input() decorator — component input binding
	{FuncName: "@Input", Annotation: "@Input"},

	// ElementRef — direct DOM access
	{FuncName: "ElementRef.nativeElement", IsSubscript: true},
	{FuncName: "elementRef.nativeElement", IsSubscript: true},
}
