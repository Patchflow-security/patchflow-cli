// Package angular is the official embedded PatchFlow framework pack for Angular.
package angular

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

type Pack struct{}

func New() *Pack { return &Pack{} }

func (Pack) Name() string     { return "angular" }
func (Pack) Language() string { return "typescript" }

func (Pack) FileExtensions() []string {
	return []string{".ts"}
}

func (Pack) TemplateExtensions() []string {
	return []string{".html"}
}

func (Pack) Rules() []frameworks.FrameworkRule         { return Rules() }
func (Pack) Sources() []frameworks.SourcePattern       { return Sources }
func (Pack) Sinks() []frameworks.SinkPattern           { return Sinks }
func (Pack) Sanitizers() []frameworks.SanitizerPattern { return Sanitizers }
