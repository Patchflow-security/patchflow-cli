// Package react is the official embedded PatchFlow framework pack for React.
package react

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

type Pack struct{}

func New() *Pack { return &Pack{} }

func (Pack) Name() string     { return "react" }
func (Pack) Language() string { return "javascript" }

func (Pack) FileExtensions() []string {
	return []string{".jsx", ".tsx"}
}

func (Pack) TemplateExtensions() []string {
	return []string{".jsx", ".tsx"}
}

func (Pack) Rules() []frameworks.FrameworkRule         { return Rules() }
func (Pack) Sources() []frameworks.SourcePattern       { return Sources }
func (Pack) Sinks() []frameworks.SinkPattern           { return Sinks }
func (Pack) Sanitizers() []frameworks.SanitizerPattern { return Sanitizers }
