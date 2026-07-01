// Package gin is the official embedded PatchFlow framework pack for Gin.
package gin

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

type Pack struct{}

func New() *Pack { return &Pack{} }

func (Pack) Name() string     { return "gin" }
func (Pack) Language() string { return "go" }

func (Pack) FileExtensions() []string {
	return []string{".go"}
}

func (Pack) TemplateExtensions() []string {
	return []string{".tmpl", ".html"}
}

func (Pack) Rules() []frameworks.FrameworkRule         { return Rules() }
func (Pack) Sources() []frameworks.SourcePattern       { return Sources }
func (Pack) Sinks() []frameworks.SinkPattern           { return Sinks }
func (Pack) Sanitizers() []frameworks.SanitizerPattern { return Sanitizers }
