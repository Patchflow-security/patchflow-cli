// Package spring is the official embedded PatchFlow framework pack for
// Spring Boot and Spring MVC. It declares detection-owned sources/sinks/
// sanitizers and a typed set of framework rules covering the OWASP Top 10
// categories most relevant to Spring applications: SQL injection, SSRF,
// open redirect, deserialization, XXE, auth bypass, XSS, command injection,
// and path traversal.
//
// Sources are Spring's request-binding annotations and HttpServletRequest
// accessors. Sinks are JdbcTemplate, RestTemplate/WebClient, ObjectInputStream,
// XStream, DocumentBuilderFactory, sendRedirect, and ProcessBuilder. Rules
// are versioned with PatchFlow releases and tested via fixtures under tests/.
// User YAML may extend (not replace) this pack.
package spring

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

// Pack is the Spring Boot framework rule pack.
type Pack struct{}

// New returns a Spring pack instance.
func New() *Pack { return &Pack{} }

func (Pack) Name() string             { return "spring" }
func (Pack) Language() string         { return "java" }

func (Pack) FileExtensions() []string {
	return []string{".java"}
}

func (Pack) TemplateExtensions() []string {
	return []string{".jsp", ".jspx", ".ftl", ".vm", ".html", ".thymeleaf.html"}
}

func (Pack) Sources() []frameworks.SourcePattern     { return Sources }
func (Pack) Sinks() []frameworks.SinkPattern         { return Sinks }
func (Pack) Sanitizers() []frameworks.SanitizerPattern { return Sanitizers }
