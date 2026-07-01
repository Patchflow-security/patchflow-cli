// Package symfony is the official embedded PatchFlow framework pack for Symfony.
package symfony

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

type Pack struct{}

func New() *Pack { return &Pack{} }

func (Pack) Name() string     { return "symfony" }
func (Pack) Language() string { return "php" }

func (Pack) FileExtensions() []string {
	return []string{".php"}
}

func (Pack) TemplateExtensions() []string {
	return []string{".twig", ".php"}
}

func (Pack) Rules() []frameworks.FrameworkRule         { return Rules() }
func (Pack) Sources() []frameworks.SourcePattern       { return Sources }
func (Pack) Sinks() []frameworks.SinkPattern           { return Sinks }
func (Pack) Sanitizers() []frameworks.SanitizerPattern { return Sanitizers }
