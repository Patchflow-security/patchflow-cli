// Package rails is the official embedded PatchFlow framework pack for Ruby
// on Rails. It declares detection-owned sources/sinks/sanitizers and a
// starter set of typed framework rules.
//
// This pack is the reference implementation of the framework-pack contract.
// Additional packs (Spring, ASP.NET, Express, Django, ...) follow the same
// structure: sources.go, sinks.go, sanitizers.go, templates.go, rules.go.
//
// Rules here are versioned with PatchFlow releases and tested via the
// fixtures under tests/. User YAML may extend (not replace) these packs.
package rails

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

// Pack is the Rails framework rule pack.
type Pack struct{}

// New returns a Rails pack instance.
func New() *Pack { return &Pack{} }

func (Pack) Name() string             { return "rails" }
func (Pack) Language() string         { return "ruby" }

func (Pack) FileExtensions() []string {
	return []string{".rb"}
}

func (Pack) TemplateExtensions() []string {
	return []string{".erb", ".rhtml", ".haml", ".slim"}
}

func (Pack) Sources() []frameworks.SourcePattern     { return Sources }
func (Pack) Sinks() []frameworks.SinkPattern         { return Sinks }
func (Pack) Sanitizers() []frameworks.SanitizerPattern { return Sanitizers }
