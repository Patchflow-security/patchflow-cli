// Package graphql is the official embedded PatchFlow framework pack for
// GraphQL servers (Graphene, Ariadne, Strawberry, graphql-python).
package graphql

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

type Pack struct{}

func New() *Pack { return &Pack{} }

func (Pack) Name() string     { return "graphql" }
func (Pack) Language() string { return "python" }

func (Pack) FileExtensions() []string {
	return []string{".py"}
}

func (Pack) TemplateExtensions() []string {
	return []string{}
}

func (Pack) Rules() []frameworks.FrameworkRule         { return Rules() }
func (Pack) Sources() []frameworks.SourcePattern       { return Sources }
func (Pack) Sinks() []frameworks.SinkPattern           { return Sinks }
func (Pack) Sanitizers() []frameworks.SanitizerPattern { return Sanitizers }
