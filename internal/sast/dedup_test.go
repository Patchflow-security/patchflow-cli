package sast

import (
	"testing"

	"github.com/patchflow/patchflow-cli/internal/analysis"
)

func TestDedupFindings(t *testing.T) {
	findings := []analysis.Finding{
		{Analyzer: "treesitter-ast", FilePath: "/abs/path/components/analysis/dep.tsx", LineStart: 455, Confidence: analysis.ConfidenceHigh, RuleID: "TS-JS004", Title: "dangerouslySetInnerHTML (AST-confirmed)"},
		{Analyzer: "patterns-embedded", FilePath: "components/analysis/dep.tsx", LineStart: 455, Confidence: analysis.ConfidenceMedium, RuleID: "TS-JS004", Title: "dangerouslySetInnerHTML"},
		{Analyzer: "osv", FilePath: "package.json", LineStart: 0, Confidence: analysis.ConfidenceHigh, RuleID: "CVE-2024-1234", Title: "next@16.0.10"},
	}

	deduped := dedupFindings(findings)
	if len(deduped) != 2 {
		t.Errorf("expected 2 findings after dedup, got %d", len(deduped))
		for _, f := range deduped {
			t.Logf("  [%s] %s — %s:%d", f.Analyzer, f.Title, f.FilePath, f.LineStart)
		}
	}

	// The tree-sitter finding should win over the pattern finding
	for _, f := range deduped {
		if f.LineStart == 455 {
			if f.Analyzer != "treesitter-ast" {
				t.Errorf("expected treesitter-ast to win dedup, got %s", f.Analyzer)
			}
		}
	}
}

func TestDedupFindingsSameAnalyzer(t *testing.T) {
	// Same file+line+rule, same analyzer — should keep one
	findings := []analysis.Finding{
		{Analyzer: "gosast-embedded", FilePath: "/abs/path/main.go", LineStart: 10, Confidence: analysis.ConfidenceHigh, RuleID: "G104", Title: "G104"},
		{Analyzer: "gosast-embedded", FilePath: "/abs/path/main.go", LineStart: 10, Confidence: analysis.ConfidenceHigh, RuleID: "G104", Title: "G104"},
	}
	deduped := dedupFindings(findings)
	if len(deduped) != 1 {
		t.Errorf("expected 1 finding after dedup, got %d", len(deduped))
	}
}

func TestDedupFindingsDifferentLines(t *testing.T) {
	// Same file, different lines — should keep both
	findings := []analysis.Finding{
		{Analyzer: "gosast-embedded", FilePath: "/abs/path/main.go", LineStart: 10, Confidence: analysis.ConfidenceHigh, RuleID: "G104"},
		{Analyzer: "gosast-embedded", FilePath: "/abs/path/main.go", LineStart: 20, Confidence: analysis.ConfidenceHigh, RuleID: "G104"},
	}
	deduped := dedupFindings(findings)
	if len(deduped) != 2 {
		t.Errorf("expected 2 findings after dedup, got %d", len(deduped))
	}
}

func TestDedupFindingsDifferentRulesSameLine(t *testing.T) {
	// Same file+line but different rule IDs — should keep both
	// (e.g., SQL injection and hardcoded password on the same line)
	findings := []analysis.Finding{
		{Analyzer: "patterns-embedded", FilePath: "/abs/path/main.go", LineStart: 10, Confidence: analysis.ConfidenceHigh, RuleID: "PY001", Title: "eval() usage"},
		{Analyzer: "patterns-embedded", FilePath: "/abs/path/main.go", LineStart: 10, Confidence: analysis.ConfidenceHigh, RuleID: "GEN010", Title: "Hardcoded password"},
	}
	deduped := dedupFindings(findings)
	if len(deduped) != 2 {
		t.Errorf("expected 2 findings (different rules on same line), got %d", len(deduped))
		for _, f := range deduped {
			t.Logf("  [%s] %s — rule=%s", f.Analyzer, f.Title, f.RuleID)
		}
	}
}

func TestDedupFindingsSameRuleCrossScanner(t *testing.T) {
	// Same file+line+rule from different scanners — should dedup to one
	findings := []analysis.Finding{
		{Analyzer: "treesitter-ast", FilePath: "/abs/path/app.py", LineStart: 5, Confidence: analysis.ConfidenceHigh, RuleID: "TS-PY001", Title: "eval() (AST-confirmed)"},
		{Analyzer: "patterns-embedded", FilePath: "path/app.py", LineStart: 5, Confidence: analysis.ConfidenceMedium, RuleID: "TS-PY001", Title: "eval()"},
	}
	deduped := dedupFindings(findings)
	if len(deduped) != 1 {
		t.Errorf("expected 1 finding (same rule cross-scanner), got %d", len(deduped))
	}
	if deduped[0].Analyzer != "treesitter-ast" {
		t.Errorf("expected treesitter-ast to win, got %s", deduped[0].Analyzer)
	}
}
