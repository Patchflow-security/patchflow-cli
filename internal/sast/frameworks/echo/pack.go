// Package echo is the official embedded PatchFlow framework pack for Echo.
package echo

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

type Pack struct{}

func New() *Pack { return &Pack{} }

func (Pack) Name() string     { return "echo" }
func (Pack) Language() string { return "go" }

func (Pack) FileExtensions() []string {
	return []string{".go"}
}

func (Pack) TemplateExtensions() []string {
	return []string{".html", ".tmpl"}
}

func (Pack) Rules() []frameworks.FrameworkRule         { return Rules() }
func (Pack) Sources() []frameworks.SourcePattern       { return Sources }
func (Pack) Sinks() []frameworks.SinkPattern           { return Sinks }
func (Pack) Sanitizers() []frameworks.SanitizerPattern { return Sanitizers }
