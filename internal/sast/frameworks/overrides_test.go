package frameworks

import (
	"regexp"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
)

func TestApplyPackOverride_SafePatterns(t *testing.T) {
	base := &mockPack{
		name: "test",
		rules: []FrameworkRule{
			{
				ID:        "TEST-001",
				MatchMode: MatchPattern,
				Pattern:   regexp.MustCompile(`dangerous\(`),
			},
		},
	}
	override := PackOverride{
		SafePatterns: []SafePattern{
			{Regex: regexp.MustCompile(`SafeGuard`), Reason: "Internal guard"},
		},
	}
	result := ApplyPackOverride(base, override)
	rules := result.Rules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if len(rules[0].SafePatterns) != 1 {
		t.Errorf("expected 1 safe pattern on rule, got %d", len(rules[0].SafePatterns))
	}
	if rules[0].SafePatterns[0].Reason != "Internal guard" {
		t.Errorf("unexpected reason: %s", rules[0].SafePatterns[0].Reason)
	}
}

func TestApplyPackOverride_MergesSourcesSinksSanitizersSafePatterns(t *testing.T) {
	base := &mockPack{
		name: "test",
		sources: []SourcePattern{{FuncName: "OfficialSource"}},
		sinks:   []SinkPattern{{FuncName: "OfficialSink", ArgIndex: 0}},
		sanitizers: []SanitizerPattern{{FuncName: "OfficialSanitizer"}},
		rules: []FrameworkRule{
			{
				ID:        "TEST-001",
				MatchMode: MatchTaint,
				Sources:   []SourcePattern{{FuncName: "OfficialSource"}},
				Sinks:     []SinkPattern{{FuncName: "OfficialSink", ArgIndex: 0}},
				Sanitizers: []SanitizerPattern{{FuncName: "OfficialSanitizer"}},
			},
		},
	}
	override := PackOverride{
		Sources:    []SourcePattern{{FuncName: "CustomSource"}},
		Sinks:      []SinkPattern{{FuncName: "CustomSink", ArgIndex: 0}},
		Sanitizers: []SanitizerPattern{{FuncName: "CustomSanitizer"}},
		SafePatterns: []SafePattern{
			{Regex: regexp.MustCompile(`SafeGuard`), Reason: "guard"},
		},
	}
	result := ApplyPackOverride(base, override)

	// Pack-level sources/sinks/sanitizers should be merged
	if len(result.Sources()) != 2 {
		t.Errorf("expected 2 pack sources, got %d", len(result.Sources()))
	}
	if len(result.Sinks()) != 2 {
		t.Errorf("expected 2 pack sinks, got %d", len(result.Sinks()))
	}
	if len(result.Sanitizers()) != 2 {
		t.Errorf("expected 2 pack sanitizers, got %d", len(result.Sanitizers()))
	}

	// Rule-level sources/sinks/sanitizers/safePatterns should be merged
	rules := result.Rules()
	if len(rules[0].Sources) != 2 {
		t.Errorf("expected 2 rule sources, got %d", len(rules[0].Sources))
	}
	if len(rules[0].Sinks) != 2 {
		t.Errorf("expected 2 rule sinks, got %d", len(rules[0].Sinks))
	}
	if len(rules[0].Sanitizers) != 2 {
		t.Errorf("expected 2 rule sanitizers, got %d", len(rules[0].Sanitizers))
	}
	if len(rules[0].SafePatterns) != 1 {
		t.Errorf("expected 1 rule safe pattern, got %d", len(rules[0].SafePatterns))
	}
}

func TestApplyPackOverride_SeverityOverrides(t *testing.T) {
	base := &mockPack{
		name: "test",
		rules: []FrameworkRule{
			{ID: "TEST-001", Severity: analysis.SeverityMedium},
		},
	}
	override := PackOverride{
		SeverityOverrides: map[string]analysis.Severity{
			"TEST-001": analysis.SeverityCritical,
		},
	}
	result := ApplyPackOverride(base, override)
	rules := result.Rules()
	if rules[0].Severity != analysis.SeverityCritical {
		t.Errorf("expected critical, got %s", rules[0].Severity)
	}
}

// mockPack implements Pack for testing
type mockPack struct {
	name      string
	language  string
	rules     []FrameworkRule
	sources   []SourcePattern
	sinks     []SinkPattern
	sanitizers []SanitizerPattern
}

func (m *mockPack) Name() string             { return m.name }
func (m *mockPack) Language() string         { return m.language }
func (m *mockPack) FileExtensions() []string { return []string{".test"} }
func (m *mockPack) TemplateExtensions() []string { return nil }
func (m *mockPack) Rules() []FrameworkRule   { return m.rules }
func (m *mockPack) Sources() []SourcePattern { return m.sources }
func (m *mockPack) Sinks() []SinkPattern     { return m.sinks }
func (m *mockPack) Sanitizers() []SanitizerPattern { return m.sanitizers }
