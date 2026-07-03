package frameworks

import (
	"regexp"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
)

func TestSinkMatchesRule_UnscopedSinkMatchesAll(t *testing.T) {
	sink := SinkPattern{FuncName: "GenericSink", ArgIndex: 0}
	rule := FrameworkRule{CWE: "CWE-89", Category: "sql_injection"}
	if !sinkMatchesRule(sink, rule) {
		t.Error("unscoped sink should match all rules")
	}
}

func TestSinkMatchesRule_CWEMatch(t *testing.T) {
	sink := SinkPattern{FuncName: "LegacySql.run", CWE: "CWE-89"}
	sqliRule := FrameworkRule{CWE: "CWE-89", Category: "sql_injection"}
	ssrfRule := FrameworkRule{CWE: "CWE-918", Category: "ssrf"}

	if !sinkMatchesRule(sink, sqliRule) {
		t.Error("sink with CWE-89 should match SQLi rule")
	}
	if sinkMatchesRule(sink, ssrfRule) {
		t.Error("sink with CWE-89 should NOT match SSRF rule")
	}
}

func TestSinkMatchesRule_CategoryMatch(t *testing.T) {
	sink := SinkPattern{FuncName: "LegacySql.run", Category: "sql_injection"}
	sqliRule := FrameworkRule{CWE: "CWE-89", Category: "sql_injection"}
	ssrfRule := FrameworkRule{CWE: "CWE-918", Category: "ssrf"}

	if !sinkMatchesRule(sink, sqliRule) {
		t.Error("sink with sql_injection category should match SQLi rule")
	}
	if sinkMatchesRule(sink, ssrfRule) {
		t.Error("sink with sql_injection category should NOT match SSRF rule")
	}
}

func TestSinkMatchesRule_CategoryFromCWEFallback(t *testing.T) {
	// Rule has CWE but no explicit Category — should use CategoryForCWE fallback
	sink := SinkPattern{FuncName: "LegacySql.run", Category: "sql_injection"}
	rule := FrameworkRule{CWE: "CWE-89"} // no Category field

	if !sinkMatchesRule(sink, rule) {
		t.Error("sink with sql_injection category should match rule with CWE-89 (via CategoryForCWE fallback)")
	}
}

func TestSinkMatchesRule_CWECaseInsensitive(t *testing.T) {
	sink := SinkPattern{FuncName: "LegacySql.run", CWE: "cwe-89"}
	rule := FrameworkRule{CWE: "CWE-89"}

	if !sinkMatchesRule(sink, rule) {
		t.Error("CWE matching should be case-insensitive")
	}
}

func TestSourceMatchesRule_UnscopedSourceMatchesAll(t *testing.T) {
	src := SourcePattern{FuncName: "getRequest"}
	sqliRule := FrameworkRule{CWE: "CWE-89", Category: "sql_injection"}
	ssrfRule := FrameworkRule{CWE: "CWE-918", Category: "ssrf"}

	if !sourceMatchesRule(src, sqliRule) {
		t.Error("unscoped source should match all rules")
	}
	if !sourceMatchesRule(src, ssrfRule) {
		t.Error("unscoped source should match all rules")
	}
}

func TestSourceMatchesRule_CategoryScoped(t *testing.T) {
	src := SourcePattern{
		FuncName:   "@TenantInput",
		Annotation: "@TenantInput",
		Categories: []string{"sql_injection", "path_traversal"},
	}
	sqliRule := FrameworkRule{CWE: "CWE-89", Category: "sql_injection"}
	ssrfRule := FrameworkRule{CWE: "CWE-918", Category: "ssrf"}
	pathTraversalRule := FrameworkRule{CWE: "CWE-22", Category: "path_traversal"}

	if !sourceMatchesRule(src, sqliRule) {
		t.Error("source scoped to sql_injection should match SQLi rule")
	}
	if sourceMatchesRule(src, ssrfRule) {
		t.Error("source scoped to sql_injection+path_traversal should NOT match SSRF rule")
	}
	if !sourceMatchesRule(src, pathTraversalRule) {
		t.Error("source scoped to path_traversal should match path traversal rule")
	}
}

func TestApplyPackOverride_SinkScopingByCWE(t *testing.T) {
	base := &mockPack{
		name: "test",
		rules: []FrameworkRule{
			{
				ID:       "TEST-SQLI",
				CWE:      "CWE-89",
				Category: "sql_injection",
				MatchMode: MatchTaint,
				Sinks: []SinkPattern{{FuncName: "officialSql", ArgIndex: 0}},
				Sources: []SourcePattern{{FuncName: "officialSource"}},
			},
			{
				ID:       "TEST-SSRF",
				CWE:      "CWE-918",
				Category: "ssrf",
				MatchMode: MatchTaint,
				Sinks: []SinkPattern{{FuncName: "officialHttp", ArgIndex: 0}},
				Sources: []SourcePattern{{FuncName: "officialSource"}},
			},
		},
	}
	override := PackOverride{
		Sinks: []SinkPattern{
			{FuncName: "LegacySql.run", CWE: "CWE-89"},
			{FuncName: "InternalHttp.fetch", CWE: "CWE-918"},
		},
	}
	result := ApplyPackOverride(base, override)
	rules := result.Rules()

	// SQLi rule should have officialSql + LegacySql.run
	if len(rules[0].Sinks) != 2 {
		t.Errorf("SQLi rule: expected 2 sinks, got %d", len(rules[0].Sinks))
	}
	sinkNames := []string{rules[0].Sinks[0].FuncName, rules[0].Sinks[1].FuncName}
	if !contains(sinkNames, "LegacySql.run") {
		t.Errorf("SQLi rule should contain LegacySql.run, got %v", sinkNames)
	}
	if contains(sinkNames, "InternalHttp.fetch") {
		t.Errorf("SQLi rule should NOT contain InternalHttp.fetch, got %v", sinkNames)
	}

	// SSRF rule should have officialHttp + InternalHttp.fetch
	if len(rules[1].Sinks) != 2 {
		t.Errorf("SSRF rule: expected 2 sinks, got %d", len(rules[1].Sinks))
	}
	sinkNames = []string{rules[1].Sinks[0].FuncName, rules[1].Sinks[1].FuncName}
	if !contains(sinkNames, "InternalHttp.fetch") {
		t.Errorf("SSRF rule should contain InternalHttp.fetch, got %v", sinkNames)
	}
	if contains(sinkNames, "LegacySql.run") {
		t.Errorf("SSRF rule should NOT contain LegacySql.run, got %v", sinkNames)
	}
}

func TestApplyPackOverride_SourceScopingByCategory(t *testing.T) {
	base := &mockPack{
		name: "test",
		rules: []FrameworkRule{
			{
				ID:       "TEST-SQLI",
				CWE:      "CWE-89",
				Category: "sql_injection",
				MatchMode: MatchTaint,
				Sources: []SourcePattern{{FuncName: "officialSource"}},
			},
			{
				ID:       "TEST-SSRF",
				CWE:      "CWE-918",
				Category: "ssrf",
				MatchMode: MatchTaint,
				Sources: []SourcePattern{{FuncName: "officialSource"}},
			},
		},
	}
	override := PackOverride{
		Sources: []SourcePattern{
			{Annotation: "@TenantInput", Categories: []string{"sql_injection"}},
		},
	}
	result := ApplyPackOverride(base, override)
	rules := result.Rules()

	// SQLi rule should have officialSource + @TenantInput
	if len(rules[0].Sources) != 2 {
		t.Errorf("SQLi rule: expected 2 sources, got %d", len(rules[0].Sources))
	}
	// SSRF rule should have only officialSource (no @TenantInput)
	if len(rules[1].Sources) != 1 {
		t.Errorf("SSRF rule: expected 1 source (no custom), got %d", len(rules[1].Sources))
	}
}

func TestCategoryForCWE(t *testing.T) {
	tests := []struct {
		cwe      string
		expected string
	}{
		{"CWE-89", "sql_injection"},
		{"CWE-918", "ssrf"},
		{"CWE-601", "open_redirect"},
		{"CWE-502", "deserialization"},
		{"CWE-79", "xss"},
		{"CWE-78", "command_injection"},
		{"CWE-22", "path_traversal"},
		{"CWE-639", "idor"},
		{"CWE-999", ""}, // unknown
	}
	for _, tt := range tests {
		got := CategoryForCWE(tt.cwe)
		if got != tt.expected {
			t.Errorf("CategoryForCWE(%s) = %q, want %q", tt.cwe, got, tt.expected)
		}
	}
}

func TestApplyPackOverride_UnscopedSinkAttachesToAll(t *testing.T) {
	base := &mockPack{
		name: "test",
		rules: []FrameworkRule{
			{ID: "TEST-SQLI", CWE: "CWE-89", Category: "sql_injection", MatchMode: MatchTaint,
				Sinks: []SinkPattern{{FuncName: "officialSql"}}},
			{ID: "TEST-SSRF", CWE: "CWE-918", Category: "ssrf", MatchMode: MatchTaint,
				Sinks: []SinkPattern{{FuncName: "officialHttp"}}},
		},
	}
	override := PackOverride{
		Sinks: []SinkPattern{{FuncName: "GenericDanger"}},
	}
	result := ApplyPackOverride(base, override)
	rules := result.Rules()

	// Unscoped sink should attach to both rules
	for i, r := range rules {
		if len(r.Sinks) != 2 {
			t.Errorf("rule %s: expected 2 sinks (unscoped), got %d", r.ID, len(r.Sinks))
		}
		_ = i
	}
}

func contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

// Ensure mockPack from overrides_test.go is available
var _ = regexp.MustCompile
var _ = analysis.SeverityHigh
