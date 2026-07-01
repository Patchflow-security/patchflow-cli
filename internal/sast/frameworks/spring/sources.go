package spring

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

// Sources are the Spring taint entry points: request data that an attacker
// controls. These feed the taint engine for MatchTaint rules.
//
// Spring binds request data via annotations (@RequestParam, @PathVariable,
// @RequestBody, @RequestHeader, @CookieValue) and via HttpServletRequest
// accessors (getParameter, getHeader, getQueryString, getCookies).
var Sources = []frameworks.SourcePattern{
	// Annotation-based binding (Spring MVC)
	{FuncName: "@RequestParam", Annotation: "@RequestParam"},
	{FuncName: "@PathVariable", Annotation: "@PathVariable"},
	{FuncName: "@RequestBody", Annotation: "@RequestBody"},
	{FuncName: "@RequestHeader", Annotation: "@RequestHeader"},
	{FuncName: "@CookieValue", Annotation: "@CookieValue"},
	{FuncName: "@ModelAttribute", Annotation: "@ModelAttribute"},
	// HttpServletRequest accessors
	{FuncName: "getParameter", IsSubscript: false},
	{FuncName: "getParameterValues", IsSubscript: false},
	{FuncName: "getHeader", IsSubscript: false},
	{FuncName: "getHeaders", IsSubscript: false},
	{FuncName: "getQueryString", IsSubscript: false},
	{FuncName: "getCookies", IsSubscript: false},
	{FuncName: "getRequestURI", IsSubscript: false},
	{FuncName: "getPathInfo", IsSubscript: false},
	// Spring WebFlux
	{FuncName: "ServerHttpRequest", IsSubscript: false},
}
