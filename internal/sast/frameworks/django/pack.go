// Package django is the official embedded PatchFlow framework pack for Django.
package django

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

type Pack struct{}

func New() *Pack { return &Pack{} }

func (Pack) Name() string     { return "django" }
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
