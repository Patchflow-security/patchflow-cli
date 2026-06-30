// Package fastapi is the official embedded PatchFlow framework pack for
// FastAPI applications. It covers the common request-driven security failure
// modes seen in Python API services and Jinja2-backed FastAPI apps.
package fastapi

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

// Pack is the FastAPI framework rule pack.
type Pack struct{}

// New returns a FastAPI pack instance.
func New() *Pack { return &Pack{} }

func (Pack) Name() string     { return "fastapi" }
func (Pack) Language() string { return "python" }

func (Pack) FileExtensions() []string {
	return []string{".py"}
}

func (Pack) TemplateExtensions() []string {
	return []string{".html", ".jinja", ".jinja2"}
}

func (Pack) Rules() []frameworks.FrameworkRule         { return Rules() }
func (Pack) Sources() []frameworks.SourcePattern       { return Sources }
func (Pack) Sinks() []frameworks.SinkPattern           { return Sinks }
func (Pack) Sanitizers() []frameworks.SanitizerPattern { return Sanitizers }
