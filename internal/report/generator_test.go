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
		Score:              45,
		Level:              "medium",
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
		ProjectRoot: "/test/repo",
		Branch:      "main",
		CommitSHA:   "abc123",
		Findings: []analysis.Finding{
			{
				Title:          "Test vulnerability",
				Type:           analysis.TypeSCA,
				Severity:       analysis.SeverityHigh,
				PackageName:    "vuln-pkg",
				PackageVersion: "1.0.0",
				FixedVersion:   "2.0.0",
				CVEID:          "CVE-2024-1234",
			},
		},
		Dependencies: []analysis.Dependency{{Name: "test-pkg", Version: "1.0.0"}},
	}

	riskScore := &risk.ScoreOutput{
		Score:              60,
		Level:              "high",
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
	if parsed["analysis"] == nil {
		t.Error("JSON should contain analysis field")
	}
	if parsed["result"] != nil {
		t.Error("JSON should not use legacy result field")
	}
}

func TestRecommendationsDoNotClaimSafeWhenHighFindingsExist(t *testing.T) {
	result := &analysis.AnalysisResult{
		Findings: []analysis.Finding{
			{Title: "High finding", Severity: analysis.SeverityHigh},
		},
	}
	riskScore := &risk.ScoreOutput{Score: 80, Level: "critical"}

	gen := NewGenerator(result, riskScore)
	recs := gen.GenerateRecommendationsPublic()

	joined := strings.Join(recs, "\n")
	if strings.Contains(joined, "No critical issues detected") {
		t.Fatalf("recommendations should not claim safe on blocking risk: %v", recs)
	}
	if !strings.Contains(joined, "high-severity") {
		t.Fatalf("expected high severity recommendation, got %v", recs)
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

func TestGroupSCAFindings(t *testing.T) {
	findings := []analysis.Finding{
		{
			ID:             "sca-npm-next-GHSA-1",
			Type:           analysis.TypeSCA,
			Severity:       analysis.SeverityMedium,
			Title:          "next@16.0.10: GHSA-1",
			PackageName:    "next",
			PackageVersion: "16.0.10",
			FilePath:       "package.json",
			Reachability:   analysis.ReachabilityHigh,
			ReachabilityConfidence: analysis.ConfidenceHigh,
		},
		{
			ID:             "sca-npm-next-GHSA-2",
			Type:           analysis.TypeSCA,
			Severity:       analysis.SeverityMedium,
			Title:          "next@16.0.10: GHSA-2",
			PackageName:    "next",
			PackageVersion: "16.0.10",
			FilePath:       "package.json",
			Reachability:   analysis.ReachabilityHigh,
			ReachabilityConfidence: analysis.ConfidenceHigh,
		},
		{
			ID:             "sca-npm-vite-GHSA-3",
			Type:           analysis.TypeSCA,
			Severity:       analysis.SeverityMedium,
			Title:          "vite@8.0.12: GHSA-3",
			PackageName:    "vite",
			PackageVersion: "8.0.12",
			FilePath:       "package.json",
			Reachability:   analysis.ReachabilityHigh,
			ReachabilityConfidence: analysis.ConfidenceHigh,
		},
		{
			ID:             "sast-1",
			Type:           analysis.TypeSAST,
			Severity:       analysis.SeverityHigh,
			Title:          "SQL injection",
			FilePath:       "src/main.go",
			LineStart:      42,
		},
	}

	grouped, groups := GroupSCAFindings(findings)
	if len(groups) != 2 {
		t.Fatalf("expected 2 package groups, got %d", len(groups))
	}
	if len(grouped) != 3 { // 2 SCA groups + 1 SAST
		t.Fatalf("expected 3 grouped findings, got %d", len(grouped))
	}

	// Verify next group collapsed two advisories into one finding.
	var nextGroup *analysis.Finding
	for i := range grouped {
		if grouped[i].PackageName == "next" {
			nextGroup = &grouped[i]
			break
		}
	}
	if nextGroup == nil {
		t.Fatal("expected a grouped next finding")
	}
	if !strings.Contains(nextGroup.Title, "2 advisories") {
		t.Errorf("expected grouped title to mention 2 advisories, got %q", nextGroup.Title)
	}
	if nextGroup.ReachabilityConfidence != analysis.ConfidenceHigh {
		t.Errorf("expected reachability confidence to be preserved, got %q", nextGroup.ReachabilityConfidence)
	}
	if !strings.Contains(nextGroup.Description, "GHSA-1") || !strings.Contains(nextGroup.Description, "GHSA-2") {
		t.Errorf("expected grouped description to list both advisories, got %q", nextGroup.Description)
	}

	// Verify package summary table contains the packages.
	table := packageSummaryTable(groups)
	if !strings.Contains(table, "next") {
		t.Error("package summary table should contain next")
	}
	if !strings.Contains(table, "vite") {
		t.Error("package summary table should contain vite")
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
