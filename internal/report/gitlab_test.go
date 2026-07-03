package report

import (
	"encoding/json"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/risk"
)

func TestGitLabCodeQuality(t *testing.T) {
	result := &analysis.AnalysisResult{
		Findings: []analysis.Finding{
			{
				ID:           "finding-001",
				RuleID:       "PY001",
				Title:        "Use of eval()",
				Description:  "eval() can execute arbitrary code",
				Severity:     analysis.SeverityHigh,
				FilePath:     "app.py",
				LineStart:    10,
				LineEnd:      10,
				Type:         analysis.TypeSAST,
				Recommendation: "Use JSON.parse() instead",
			},
			{
				ID:          "finding-002",
				RuleID:      "SCA-OSV",
				Title:       "Vulnerable dependency: lodash@4.17.20",
				Severity:    analysis.SeverityCritical,
				FilePath:    "package.json",
				LineStart:   5,
				Type:        analysis.TypeSCA,
				PackageName: "lodash",
			},
		},
	}

	riskScore := &risk.ScoreOutput{Score: 75, Level: "high"}
	gen := NewGenerator(result, riskScore)

	data, err := gen.GitLabCodeQuality()
	if err != nil {
		t.Fatalf("GitLabCodeQuality failed: %v", err)
	}

	var findings []GitLabCodeQualityFinding
	if err := json.Unmarshal(data, &findings); err != nil {
		t.Fatalf("failed to parse GitLab Code Quality JSON: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	// Check first finding (high severity SAST)
	f1 := findings[0]
	if f1.CheckName != "PY001" {
		t.Errorf("expected check name 'PY001', got '%s'", f1.CheckName)
	}
	if f1.Severity != "critical" {
		t.Errorf("expected severity 'critical' for high, got '%s'", f1.Severity)
	}
	if f1.Location.Path != "app.py" {
		t.Errorf("expected path 'app.py', got '%s'", f1.Location.Path)
	}
	if f1.Location.Lines.Begin != 10 {
		t.Errorf("expected begin line 10, got %d", f1.Location.Lines.Begin)
	}
	if f1.Fingerprint != "finding-001" {
		t.Errorf("expected fingerprint 'finding-001', got '%s'", f1.Fingerprint)
	}
	if len(f1.Categories) < 1 {
		t.Error("expected at least 1 category")
	}

	// Check second finding (critical severity SCA)
	f2 := findings[1]
	if f2.Severity != "blocker" {
		t.Errorf("expected severity 'blocker' for critical, got '%s'", f2.Severity)
	}
}

func TestSeverityToGitLab(t *testing.T) {
	tests := []struct {
		sev      analysis.Severity
		expected string
	}{
		{analysis.SeverityCritical, "blocker"},
		{analysis.SeverityHigh, "critical"},
		{analysis.SeverityMedium, "major"},
		{analysis.SeverityLow, "minor"},
		{analysis.SeverityInfo, "info"},
	}

	for _, tt := range tests {
		got := severityToGitLab(tt.sev)
		if got != tt.expected {
			t.Errorf("severityToGitLab(%s) = %s, want %s", tt.sev, got, tt.expected)
		}
	}
}

func TestGitLabCodeQuality_Empty(t *testing.T) {
	result := &analysis.AnalysisResult{
		Findings: []analysis.Finding{},
	}
	riskScore := &risk.ScoreOutput{Score: 0, Level: "low"}
	gen := NewGenerator(result, riskScore)

	data, err := gen.GitLabCodeQuality()
	if err != nil {
		t.Fatalf("GitLabCodeQuality failed: %v", err)
	}

	// Should produce valid JSON (empty array or null)
	var findings []GitLabCodeQualityFinding
	if err := json.Unmarshal(data, &findings); err != nil {
		t.Fatalf("failed to parse empty GitLab Code Quality JSON: %v", err)
	}
}

func TestGitLabCodeQuality_WriteFile(t *testing.T) {
	result := &analysis.AnalysisResult{
		Findings: []analysis.Finding{
			{
				ID:       "finding-001",
				RuleID:   "PY001",
				Title:    "eval()",
				Severity: analysis.SeverityHigh,
				FilePath: "app.py",
				LineStart: 10,
				Type:     analysis.TypeSAST,
			},
		},
	}
	riskScore := &risk.ScoreOutput{Score: 50, Level: "medium"}
	gen := NewGenerator(result, riskScore)

	// Test that gitlab format is accepted by WriteFile
	tmpDir := t.TempDir()
 outputPath := tmpDir + "/gl-code-quality.json"
	if err := gen.WriteFile("gitlab", outputPath); err != nil {
		t.Fatalf("WriteFile(gitlab) failed: %v", err)
	}

	// Also test "codequality" alias
	outputPath2 := tmpDir + "/gl-code-quality2.json"
	if err := gen.WriteFile("codequality", outputPath2); err != nil {
		t.Fatalf("WriteFile(codequality) failed: %v", err)
	}
}
