package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/patchflow/patchflow-cli/internal/analysis"
	"github.com/patchflow/patchflow-cli/internal/risk"
)

func TestTerminalSummary(t *testing.T) {
	result := &analysis.AnalysisResult{
		ProjectRoot:  "/test/repo",
		Branch:       "main",
		CommitSHA:    "abc123def456",
		BaseBranch:   "develop",
		FilesChanged: 5,
		AddedLines:   100,
		DeletedLines: 20,
		Dependencies: []analysis.Dependency{{Name: "test-pkg", Version: "1.0.0"}},
		Manifests:    []string{"go.mod"},
		Analyzers:    []string{"osv"},
	}

	riskScore := &risk.ScoreOutput{
		Score:            45,
		Level:            "medium",
		FindingsBySeverity: map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 0},
		TopFindings: []analysis.Finding{
			{Title: "Test finding", Severity: analysis.SeverityHigh, PackageName: "test-pkg"},
		},
	}

	gen := NewGenerator(result, riskScore)
	summary := gen.TerminalSummary()

	if !strings.Contains(summary, "PatchFlow Analysis Report") {
		t.Error("summary should contain title")
	}
	if !strings.Contains(summary, "/test/repo") {
		t.Error("summary should contain repo root")
	}
	if !strings.Contains(summary, "45/100") {
		t.Error("summary should contain risk score")
	}
	if !strings.Contains(summary, "MEDIUM") {
		t.Error("summary should contain risk level")
	}
}

func TestMarkdown(t *testing.T) {
	result := &analysis.AnalysisResult{
		ProjectRoot:  "/test/repo",
		Branch:       "main",
		CommitSHA:    "abc123",
		Findings: []analysis.Finding{
			{
				Title:       "Test vulnerability",
				Type:        analysis.TypeSCA,
				Severity:    analysis.SeverityHigh,
				PackageName: "vuln-pkg",
				PackageVersion: "1.0.0",
				FixedVersion: "2.0.0",
				CVEID:       "CVE-2024-1234",
			},
		},
		Dependencies: []analysis.Dependency{{Name: "test-pkg", Version: "1.0.0"}},
	}

	riskScore := &risk.ScoreOutput{
		Score: 60,
		Level: "high",
		FindingsBySeverity: map[string]int{"high": 1},
	}

	gen := NewGenerator(result, riskScore)
	md := gen.Markdown()

	if !strings.Contains(md, "# PatchFlow Analysis Report") {
		t.Error("markdown should contain title")
	}
	if !strings.Contains(md, "Test vulnerability") {
		t.Error("markdown should contain finding title")
	}
	if !strings.Contains(md, "CVE-2024-1234") {
		t.Error("markdown should contain CVE ID")
	}
	if !strings.Contains(md, "vuln-pkg") {
		t.Error("markdown should contain package name")
	}
	if !strings.Contains(md, "2.0.0") {
		t.Error("markdown should contain fixed version")
	}
}

func TestJSON(t *testing.T) {
	result := &analysis.AnalysisResult{
		ProjectRoot: "/test/repo",
		Findings: []analysis.Finding{
			{Title: "Test", Severity: analysis.SeverityMedium},
		},
	}

	riskScore := &risk.ScoreOutput{Score: 30, Level: "low"}

	gen := NewGenerator(result, riskScore)
	data, err := gen.JSON()
	if err != nil {
		t.Fatalf("JSON failed: %v", err)
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	if parsed["generated"] == nil {
		t.Error("JSON should contain generated field")
	}
}

func TestSARIF(t *testing.T) {
	result := &analysis.AnalysisResult{
		Findings: []analysis.Finding{
			{
				Title:     "SQL injection",
				Severity:  analysis.SeverityHigh,
				FilePath:  "src/main.go",
				LineStart: 42,
				RuleID:    "GO-SQL-INJECTION",
			},
		},
	}

	gen := NewGenerator(result, nil)
	report := gen.SARIF("1.0.0")

	if report.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %s", report.Version)
	}
	if len(report.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(report.Runs))
	}
	if report.Runs[0].Tool.Driver.Name != "PatchFlow CLI" {
		t.Error("wrong tool name")
	}
	if len(report.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(report.Runs[0].Results))
	}

	r := report.Runs[0].Results[0]
	if r.RuleID != "GO-SQL-INJECTION" {
		t.Errorf("wrong rule ID: %s", r.RuleID)
	}
	if r.Level != "error" {
		t.Errorf("high severity should map to error level, got %s", r.Level)
	}
	if len(r.Locations) != 1 {
		t.Fatalf("expected 1 location, got %d", len(r.Locations))
	}
	if r.Locations[0].PhysicalLocation.ArtifactLocation.URI != "src/main.go" {
		t.Error("wrong file path in SARIF")
	}
}

func TestSeverityToSARIFLevel(t *testing.T) {
	tests := []struct {
		sev   analysis.Severity
		level string
	}{
		{analysis.SeverityCritical, "error"},
		{analysis.SeverityHigh, "error"},
		{analysis.SeverityMedium, "warning"},
		{analysis.SeverityLow, "note"},
		{analysis.SeverityInfo, "note"},
	}
	for _, tt := range tests {
		if got := severityToSARIFLevel(tt.sev); got != tt.level {
			t.Errorf("severityToSARIFLevel(%s) = %s, want %s", tt.sev, got, tt.level)
		}
	}
}
