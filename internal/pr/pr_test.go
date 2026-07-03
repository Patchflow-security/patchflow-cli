package pr

import (
	"strings"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/risk"
)

func TestParseDiff(t *testing.T) {
	diffOutput := `diff --git a/app.js b/app.js
index 1234567..abcdefg 100644
--- a/app.js
+++ b/app.js
@@ -10,5 +10,8 @@
 const express = require('express');
 const app = express();
 app.get('/', (req, res) => {
-    const result = eval(req.query.input);
+    // Fixed: removed eval
+    const result = JSON.parse(req.query.input);
+    // New vulnerable line
+    const evil = eval("test");
     res.send(result);
diff --git a/package.json b/package.json
index 1234567..abcdefg 100644
--- a/package.json
+++ b/package.json
@@ -1,3 +1,4 @@
 {
   "name": "test",
-  "version": "1.0.0"
+  "version": "1.0.1",
+  "license": "MIT"
 }
`
	diffs := ParseDiff(diffOutput)
	if len(diffs) != 2 {
		t.Fatalf("expected 2 file diffs, got %d", len(diffs))
	}

	// Check first file
	if diffs[0].Path != "app.js" {
		t.Errorf("expected path=app.js, got %s", diffs[0].Path)
	}
	if len(diffs[0].Hunks) != 1 {
		t.Fatalf("expected 1 hunk in app.js, got %d", len(diffs[0].Hunks))
	}

	// Check hunk header
	hunk := diffs[0].Hunks[0]
	if hunk.OldStart != 10 {
		t.Errorf("expected oldStart=10, got %d", hunk.OldStart)
	}
	if hunk.NewStart != 10 {
		t.Errorf("expected newStart=10, got %d", hunk.NewStart)
	}

	// Check lines
	addLines := 0
	delLines := 0
	for _, line := range hunk.Lines {
		if line.Type == "add" {
			addLines++
		}
		if line.Type == "del" {
			delLines++
		}
	}
	if addLines != 4 {
		t.Errorf("expected 4 added lines, got %d", addLines)
	}
	if delLines != 1 {
		t.Errorf("expected 1 deleted line, got %d", delLines)
	}
}

func TestParseDiffEmpty(t *testing.T) {
	diffs := ParseDiff("")
	if len(diffs) != 0 {
		t.Errorf("expected 0 diffs from empty input, got %d", len(diffs))
	}
}

func TestPlaceFindings(t *testing.T) {
	diffs := []FileDiff{
		{
			Path: "app.js",
			Hunks: []DiffHunk{
				{
					FilePath: "app.js",
					NewStart: 10,
					NewCount: 5,
					Lines: []DiffLine{
						{Type: "add", Content: "const evil = eval('test');", NewNum: 13},
					},
				},
			},
		},
	}

	findings := []analysis.Finding{
		{
			ID:        "f1",
			Title:     "Use of eval()",
			Severity:  analysis.SeverityHigh,
			FilePath:  "app.js",
			LineStart: 13,
		},
		{
			ID:        "f2",
			Title:     "SQL Injection",
			Severity:  analysis.SeverityCritical,
			FilePath:  "db.js",
			LineStart: 5,
		},
	}

	placements := PlaceFindings(findings, diffs)
	if len(placements) != 2 {
		t.Fatalf("expected 2 placements, got %d", len(placements))
	}

	// First finding should be in diff
	if !placements[0].InDiff {
		t.Error("expected f1 to be in diff")
	}
	if placements[0].HunkIndex != 0 {
		t.Errorf("expected hunkIndex=0, got %d", placements[0].HunkIndex)
	}
	if placements[0].DiffLine != "const evil = eval('test');" {
		t.Errorf("unexpected diff line: %s", placements[0].DiffLine)
	}

	// Second finding should not be in diff
	if placements[1].InDiff {
		t.Error("expected f2 to NOT be in diff")
	}
}

func TestGeneratePRSummary(t *testing.T) {
	result := &analysis.AnalysisResult{
		Branch:       "feature",
		BaseBranch:   "main",
		CommitSHA:    "abc123",
		FilesChanged: 3,
		AddedLines:   20,
		DeletedLines: 5,
		Findings: []analysis.Finding{
			{ID: "f1", Type: analysis.TypeSAST, Severity: analysis.SeverityHigh, Title: "eval()"},
			{ID: "f2", Type: analysis.TypeSCA, Severity: analysis.SeverityMedium, Title: "vuln dep"},
		},
	}

	riskScore := &risk.ScoreOutput{
		Score: 65,
		Level: "high",
	}

	placements := []FindingPlacement{
		{Finding: result.Findings[0], InDiff: true},
		{Finding: result.Findings[1], InDiff: false},
	}

	summary := GeneratePRSummary(result, riskScore, placements)

	if summary.RiskScore != 65 {
		t.Errorf("expected riskScore=65, got %d", summary.RiskScore)
	}
	if summary.RiskLevel != "high" {
		t.Errorf("expected riskLevel=high, got %s", summary.RiskLevel)
	}
	if summary.TotalFindings != 2 {
		t.Errorf("expected totalFindings=2, got %d", summary.TotalFindings)
	}
	if summary.NewFindings != 1 {
		t.Errorf("expected newFindings=1, got %d", summary.NewFindings)
	}
	if summary.Status != "Warning" {
		t.Errorf("expected status=Warning, got %s", summary.Status)
	}
	if summary.BySeverity["high"] != 1 {
		t.Errorf("expected 1 high finding, got %d", summary.BySeverity["high"])
	}
	if summary.BySeverity["medium"] != 1 {
		t.Errorf("expected 1 medium finding, got %d", summary.BySeverity["medium"])
	}
	if len(summary.TopFindings) != 2 {
		t.Errorf("expected 2 top findings, got %d", len(summary.TopFindings))
	}
}

func TestGeneratePRSummaryCritical(t *testing.T) {
	result := &analysis.AnalysisResult{
		Findings: []analysis.Finding{
			{Severity: analysis.SeverityCritical, Title: "critical issue"},
		},
	}
	riskScore := &risk.ScoreOutput{Score: 85, Level: "critical"}

	summary := GeneratePRSummary(result, riskScore, nil)
	if summary.Status != "BLOCKING" {
		t.Errorf("expected status=BLOCKING, got %s", summary.Status)
	}
}

func TestRenderMarkdown(t *testing.T) {
	result := &analysis.AnalysisResult{
		Branch:       "feature",
		BaseBranch:   "main",
		FilesChanged: 2,
		AddedLines:   10,
		DeletedLines: 3,
		Findings: []analysis.Finding{
			{ID: "f1", Type: analysis.TypeSAST, Severity: analysis.SeverityHigh, Title: "eval()"},
		},
	}
	riskScore := &risk.ScoreOutput{Score: 50, Level: "medium"}

	placements := []FindingPlacement{
		{Finding: result.Findings[0], InDiff: true},
	}

	summary := GeneratePRSummary(result, riskScore, placements)
	md := RenderMarkdown(summary)

	if !strings.Contains(md, "PatchFlow PR Review") {
		t.Error("markdown should contain title")
	}
	if !strings.Contains(md, "50/100") {
		t.Error("markdown should contain risk score")
	}
	if !strings.Contains(md, "**[NEW]**") {
		t.Error("markdown should mark new findings")
	}
	if !strings.Contains(md, "eval()") {
		t.Error("markdown should contain finding title")
	}
}

func TestGenerateAnnotations(t *testing.T) {
	findings := []analysis.Finding{
		{
			ID:           "f1",
			Title:        "Use of eval()",
			Severity:     analysis.SeverityHigh,
			FilePath:     "app.js",
			LineStart:    13,
			LineEnd:      13,
			Description:  "eval() can execute arbitrary code",
			Recommendation: "Avoid eval()",
		},
	}

	placements := []FindingPlacement{
		{Finding: findings[0], InDiff: true},
		{Finding: findings[0], InDiff: false}, // not in diff
	}

	annotations := GenerateAnnotations(placements)
	if len(annotations) != 1 {
		t.Fatalf("expected 1 annotation, got %d", len(annotations))
	}

	ann := annotations[0]
	if ann.Path != "app.js" {
		t.Errorf("expected path=app.js, got %s", ann.Path)
	}
	if ann.Line != 13 {
		t.Errorf("expected line=13, got %d", ann.Line)
	}
	if ann.Severity != "high" {
		t.Errorf("expected severity=high, got %s", ann.Severity)
	}
	if !strings.Contains(ann.Message, "eval()") {
		t.Error("message should contain description")
	}
	if !strings.Contains(ann.Message, "Fix:") {
		t.Error("message should contain fix recommendation")
	}
}

func TestGenerateAnnotationsEmpty(t *testing.T) {
	annotations := GenerateAnnotations(nil)
	if len(annotations) != 0 {
		t.Errorf("expected 0 annotations, got %d", len(annotations))
	}
}

func TestToGitHubAnnotations(t *testing.T) {
	annotations := []Annotation{
		{Path: "app.js", Line: 13, Severity: "critical", Title: "eval", Message: "bad"},
		{Path: "db.js", Line: 5, Severity: "low", Title: "sql", Message: "bad"},
	}

	ghAnns := ToGitHubAnnotations(annotations)
	if len(ghAnns) != 2 {
		t.Fatalf("expected 2 GitHub annotations, got %d", len(ghAnns))
	}

	if ghAnns[0].AnnotationLevel != "failure" {
		t.Errorf("expected critical=failure, got %s", ghAnns[0].AnnotationLevel)
	}
	if ghAnns[1].AnnotationLevel != "notice" {
		t.Errorf("expected low=notice, got %s", ghAnns[1].AnnotationLevel)
	}
	if ghAnns[0].StartLine != 13 {
		t.Errorf("expected startLine=13, got %d", ghAnns[0].StartLine)
	}
}

func TestToGitLabAnnotations(t *testing.T) {
	annotations := []Annotation{
		{Path: "app.js", Line: 13, Severity: "high", Title: "eval", Message: "bad"},
	}

	glAnns := ToGitLabAnnotations(annotations, "base123", "head456", "start789")
	if len(glAnns) != 1 {
		t.Fatalf("expected 1 GitLab annotation, got %d", len(glAnns))
	}

	if glAnns[0].Position.BaseSHA != "base123" {
		t.Errorf("expected baseSHA=base123, got %s", glAnns[0].Position.BaseSHA)
	}
	if glAnns[0].Position.NewLine != 13 {
		t.Errorf("expected newLine=13, got %d", glAnns[0].Position.NewLine)
	}
}

func TestRenderAnnotationsMarkdown(t *testing.T) {
	annotations := []Annotation{
		{Path: "app.js", Line: 13, Severity: "high", Title: "eval()", Message: "bad code"},
	}

	md := RenderAnnotationsMarkdown(annotations)
	if !strings.Contains(md, "Inline Findings") {
		t.Error("should contain 'Inline Findings' header")
	}
	if !strings.Contains(md, "eval()") {
		t.Error("should contain annotation title")
	}
	if !strings.Contains(md, "app.js:13") {
		t.Error("should contain file:line reference")
	}
}

func TestRenderAnnotationsMarkdownEmpty(t *testing.T) {
	md := RenderAnnotationsMarkdown(nil)
	if md != "" {
		t.Errorf("expected empty string for no annotations, got %s", md)
	}
}

func TestCountBySeverity(t *testing.T) {
	annotations := []Annotation{
		{Severity: "critical"},
		{Severity: "high"},
		{Severity: "high"},
		{Severity: "medium"},
	}

	counts := CountBySeverity(annotations)
	if counts["critical"] != 1 {
		t.Errorf("expected 1 critical, got %d", counts["critical"])
	}
	if counts["high"] != 2 {
		t.Errorf("expected 2 high, got %d", counts["high"])
	}
	if counts["medium"] != 1 {
		t.Errorf("expected 1 medium, got %d", counts["medium"])
	}
}

func TestFilterByDiff(t *testing.T) {
	annotations := []Annotation{
		{Path: "app.js", Line: 1},
		{Path: "db.js", Line: 5},
		{Path: "config.yml", Line: 3},
	}
	diffs := []FileDiff{
		{Path: "app.js"},
		{Path: "config.yml"},
	}

	filtered := FilterByDiff(annotations, diffs)
	if len(filtered) != 2 {
		t.Fatalf("expected 2 filtered annotations, got %d", len(filtered))
	}
}

func TestFormatFindingForComment(t *testing.T) {
	tests := []struct {
		name    string
		finding analysis.Finding
		want    string
	}{
		{
			name:    "sca finding",
			finding: analysis.Finding{Severity: analysis.SeverityHigh, Title: "Vuln", PackageName: "express", PackageVersion: "4.0.0"},
			want:    "[HIGH] Vuln — express@4.0.0",
		},
		{
			name:    "sast finding",
			finding: analysis.Finding{Severity: analysis.SeverityCritical, Title: "eval()", FilePath: "app.js", LineStart: 10},
			want:    "[CRITICAL] eval() — app.js:10",
		},
		{
			name:    "generic finding",
			finding: analysis.Finding{Severity: analysis.SeverityLow, Title: "Info"},
			want:    "[LOW] Info",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatFindingForComment(tt.finding)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
