// Package springsecurity is the official embedded PatchFlow pack for Spring
// Security configuration.
package springsecurity

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

type Pack struct{}

func New() *Pack { return &Pack{} }

func (Pack) Name() string     { return "spring-security" }
func (Pack) Language() string { return "java" }

func (Pack) FileExtensions() []string {
	return []string{".java"}
}

func (Pack) TemplateExtensions() []string {
	return nil
}

func (Pack) Rules() []frameworks.FrameworkRule         { return Rules() }
func (Pack) Sources() []frameworks.SourcePattern       { return Sources }
func (Pack) Sinks() []frameworks.SinkPattern           { return Sinks }
func (Pack) Sanitizers() []frameworks.SanitizerPattern { return Sanitizers }
