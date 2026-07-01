// Package express is the official embedded PatchFlow framework pack for
// Express applications.
package express

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

type Pack struct{}

func New() *Pack { return &Pack{} }

func (Pack) Name() string     { return "express" }
func (Pack) Language() string { return "javascript" }

func (Pack) FileExtensions() []string {
	return []string{".js", ".mjs", ".cjs", ".ts"}
}

func (Pack) TemplateExtensions() []string {
	return []string{".ejs", ".hbs", ".pug"}
}

func (Pack) Rules() []frameworks.FrameworkRule         { return Rules() }
func (Pack) Sources() []frameworks.SourcePattern       { return Sources }
func (Pack) Sinks() []frameworks.SinkPattern           { return Sinks }
func (Pack) Sanitizers() []frameworks.SanitizerPattern { return Sanitizers }
