// Package razor is the official embedded PatchFlow framework pack for Razor
// and Blazor template files.
package razor

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

type Pack struct{}

func New() *Pack { return &Pack{} }

func (Pack) Name() string     { return "razor" }
func (Pack) Language() string { return "csharp" }

func (Pack) FileExtensions() []string {
	return []string{".cshtml", ".razor"}
}

func (Pack) TemplateExtensions() []string {
	return []string{".cshtml", ".razor"}
}

func (Pack) Rules() []frameworks.FrameworkRule         { return Rules() }
func (Pack) Sources() []frameworks.SourcePattern       { return Sources }
func (Pack) Sinks() []frameworks.SinkPattern           { return Sinks }
func (Pack) Sanitizers() []frameworks.SanitizerPattern { return Sanitizers }
