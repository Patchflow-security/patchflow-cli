package frameworks

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	detfw "github.com/Patchflow-security/patchflow-cli/internal/frameworks"
)

func TestRegistryRegisterAndGet(t *testing.T) {
	reg := NewRegistry()
	pack := &stubPack{name: "testfw"}
	reg.Register(pack)

	if !reg.Has("testfw") {
		t.Fatal("Has should return true for registered pack")
	}
	if reg.Get("testfw") == nil {
		t.Fatal("Get should return the pack")
	}
	if reg.Get("nope") != nil {
		t.Fatal("Get should return nil for unknown pack")
	}
}

func TestRegistryAllSorted(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&stubPack{name: "zeta"})
	reg.Register(&stubPack{name: "alpha"})
	reg.Register(&stubPack{name: "mid"})

	names := reg.Names()
	want := []string{"alpha", "mid", "zeta"}
	if len(names) != len(want) {
		t.Fatalf("got %d names, want %d", len(names), len(want))
	}
	for i, n := range names {
		if n != want[i] {
			t.Fatalf("name %d = %s, want %s", i, n, want[i])
		}
	}
}

func TestLoaderAutoDetect(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&stubPack{name: "rails"})
	reg.Register(&stubPack{name: "express"})

	loader := NewLoader(reg)
	dets := detfw.Result{Frameworks: []detfw.Detection{
		{Name: detfw.NameRails, Confidence: 0.8},
	}}
	sel := loader.Select(dets, DefaultSelectionConfig())
	if len(sel.Packs) != 1 {
		t.Fatalf("expected 1 pack, got %d", len(sel.Packs))
	}
	if sel.Packs[0].Name() != "rails" {
		t.Fatalf("expected rails, got %s", sel.Packs[0].Name())
	}
}

func TestLoaderExplicitEnable(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&stubPack{name: "rails"})
	reg.Register(&stubPack{name: "express"})

	loader := NewLoader(reg)
	cfg := SelectionConfig{AutoDetect: false, Enabled: []string{"express"}}
	sel := loader.Select(detfw.Result{}, cfg)
	if len(sel.Packs) != 1 || sel.Packs[0].Name() != "express" {
		t.Fatalf("expected express only, got %+v", sel.Packs)
	}
}

func TestLoaderDisabledOverrides(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&stubPack{name: "rails"})
	reg.Register(&stubPack{name: "express"})

	loader := NewLoader(reg)
	cfg := SelectionConfig{
		AutoDetect: true,
		Disabled:   []string{"rails"},
	}
	dets := detfw.Result{Frameworks: []detfw.Detection{
		{Name: detfw.NameRails, Confidence: 0.8},
		{Name: detfw.NameExpress, Confidence: 0.8},
	}}
	sel := loader.Select(dets, cfg)
	if len(sel.Packs) != 1 || sel.Packs[0].Name() != "express" {
		t.Fatalf("disabled should remove rails; got %+v", sel.Packs)
	}
}

func TestMergeSelectionConfig(t *testing.T) {
	base := SelectionConfig{
		AutoDetect:    true,
		AutoDetectSet: true,
		Enabled:       []string{"rails"},
	}
	overlay := SelectionConfig{
		AutoDetect:    false,
		AutoDetectSet: true,
		Enabled:       []string{"express"},
		Disabled:      []string{"rails"},
	}

	merged := MergeSelectionConfig(base, overlay)
	if merged.AutoDetect {
		t.Fatal("expected auto-detect=false after overlay")
	}
	if len(merged.Enabled) != 2 {
		t.Fatalf("expected 2 enabled packs, got %d", len(merged.Enabled))
	}
	if len(merged.Disabled) != 1 || merged.Disabled[0] != "rails" {
		t.Fatalf("unexpected disabled list: %+v", merged.Disabled)
	}
}

func TestMatcherDetectsRailsHTMLSafe(t *testing.T) {
	rule := FrameworkRule{
		ID:        "PF-RAILS-XSS-TEST",
		Framework: "rails",
		Language:  "ruby",
		Severity:  analysis.SeverityHigh,
		MatchMode: MatchPattern,
		FileTypes: []string{".rb"},
		Pattern:   compileOrDie(`\.html_safe\b`),
	}
	m := NewMatcher([]FrameworkRule{rule})

	root := t.TempDir()
	target := filepath.Join(root, "app.rb")
	if err := os.WriteFile(target, []byte("x = params[:name].html_safe\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := m.ScanFile(target, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].RuleID != "PF-RAILS-XSS-TEST" {
		t.Fatalf("rule id = %s, want PF-RAILS-XSS-TEST", findings[0].RuleID)
	}
	if findings[0].Analyzer != "framework-rails" {
		t.Fatalf("analyzer = %s, want framework-rails", findings[0].Analyzer)
	}
}

func TestMatcherSanitizerSuppresses(t *testing.T) {
	rule := FrameworkRule{
		ID:        "PF-RAILS-XSS-TEST",
		Framework: "rails",
		Language:  "ruby",
		Severity:  analysis.SeverityHigh,
		MatchMode: MatchPattern,
		FileTypes: []string{".rb"},
		Pattern:   compileOrDie(`\.html_safe\b`),
		Sanitizers: []SanitizerPattern{
			{FuncName: "h("},
		},
	}
	m := NewMatcher([]FrameworkRule{rule})

	root := t.TempDir()
	target := filepath.Join(root, "app.rb")
	// h() wraps the value — sanitizer present on the line.
	if err := os.WriteFile(target, []byte("x = h(params[:name]).html_safe\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := m.ScanFile(target, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("sanitizer should suppress finding, got %d", len(findings))
	}
}

func TestMatcherSafePatternSuppresses(t *testing.T) {
	rule := FrameworkRule{
		ID:        "PF-RAILS-DESER-TEST",
		Framework: "rails",
		Language:  "ruby",
		Severity:  analysis.SeverityHigh,
		MatchMode: MatchPattern,
		FileTypes: []string{".rb"},
		Pattern:   compileOrDie(`YAML\.load\b`),
		SafePatterns: []SafePattern{
			{Regex: compileOrDie(`YAML\.safe_load`), Reason: "safe_load only permits simple types"},
		},
	}
	m := NewMatcher([]FrameworkRule{rule})

	root := t.TempDir()
	target := filepath.Join(root, "app.rb")
	if err := os.WriteFile(target, []byte("data = YAML.safe_load(payload)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := m.ScanFile(target, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("safe pattern should suppress finding, got %d", len(findings))
	}
}

func TestMatcherSkipsNonMatchingExtension(t *testing.T) {
	rule := FrameworkRule{
		ID:        "PF-RAILS-XSS-TEST",
		Framework: "rails",
		Language:  "ruby",
		MatchMode: MatchPattern,
		FileTypes: []string{".rb"},
		Pattern:   compileOrDie(`\.html_safe\b`),
	}
	m := NewMatcher([]FrameworkRule{rule})

	root := t.TempDir()
	target := filepath.Join(root, "app.py")
	if err := os.WriteFile(target, []byte("x = something.html_safe\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := m.ScanFile(target, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf(".py should not match .rb rule, got %d", len(findings))
	}
}

func TestTaintRulesExtraction(t *testing.T) {
	rules := []FrameworkRule{
		{ID: "P1", MatchMode: MatchPattern},
		{ID: "T1", MatchMode: MatchTaint},
		{ID: "T2", MatchMode: MatchTaint},
		{ID: "P2", MatchMode: MatchTemplate},
	}
	taint := TaintRules(rules)
	if len(taint) != 2 {
		t.Fatalf("expected 2 taint rules, got %d", len(taint))
	}
}

// stubPack is a minimal Pack for registry/loader tests.
type stubPack struct {
	name string
}

func (s *stubPack) Name() string                   { return s.name }
func (s *stubPack) Language() string               { return "test" }
func (s *stubPack) FileExtensions() []string       { return []string{".t"} }
func (s *stubPack) TemplateExtensions() []string   { return nil }
func (s *stubPack) Rules() []FrameworkRule         { return nil }
func (s *stubPack) Sources() []SourcePattern       { return nil }
func (s *stubPack) Sinks() []SinkPattern           { return nil }
func (s *stubPack) Sanitizers() []SanitizerPattern { return nil }

func compileOrDie(p string) *regexp.Regexp {
	return regexp.MustCompile(p)
}
