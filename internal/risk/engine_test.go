package risk

import (
	"testing"

	"github.com/patchflow/patchflow-cli/internal/analysis"
)

func TestComputeNoFindings(t *testing.T) {
	engine := NewEngine()
	score := engine.Compute(ScoreInput{
		Findings:     nil,
		FilesChanged: 1,
		AddedLines:   5,
		DeletedLines: 2,
	})

	if score.Score > 20 {
		t.Errorf("with no findings, score should be low, got %d", score.Score)
	}
	if score.Level != "minimal" && score.Level != "low" {
		t.Errorf("with no findings, level should be minimal/low, got %s", score.Level)
	}
}

func TestComputeCriticalReachable(t *testing.T) {
	engine := NewEngine()
	findings := []analysis.Finding{
		{
			Type:         analysis.TypeSCA,
			Severity:     analysis.SeverityCritical,
			Reachability: analysis.ReachabilityHigh,
		},
		{
			Type:         analysis.TypeSCA,
			Severity:     analysis.SeverityHigh,
			Reachability: analysis.ReachabilityHigh,
		},
	}

	score := engine.Compute(ScoreInput{
		Findings:     findings,
		FilesChanged: 10,
		AddedLines:   200,
		DeletedLines: 50,
	})

	if score.Score < 40 {
		t.Errorf("with critical+high reachable findings, score should be >= 40, got %d", score.Score)
	}
	if score.FindingsBySeverity["critical"] != 1 {
		t.Errorf("expected 1 critical, got %d", score.FindingsBySeverity["critical"])
	}
}

func TestComputeSecrets(t *testing.T) {
	engine := NewEngine()
	findings := []analysis.Finding{
		{Type: analysis.TypeSecret, Severity: analysis.SeverityHigh},
		{Type: analysis.TypeSecret, Severity: analysis.SeverityHigh},
	}

	score := engine.Compute(ScoreInput{
		Findings: findings,
	})

	if score.SecretPoints < 20 {
		t.Errorf("with 2 secrets, secret points should be high, got %d", score.SecretPoints)
	}
}

func TestComputeSensitivity(t *testing.T) {
	engine := NewEngine()

	// Auth files changed
	scoreAuth := engine.Compute(ScoreInput{
		AuthFilesChanged: true,
	})
	if scoreAuth.SensitivityPoints < 8 {
		t.Errorf("auth files changed should add >= 8 sensitivity points, got %d", scoreAuth.SensitivityPoints)
	}

	// CI workflow changed
	scoreCI := engine.Compute(ScoreInput{
		CIWorkflowChanged: true,
	})
	if scoreCI.SensitivityPoints < 5 {
		t.Errorf("CI workflow changed should add >= 5 sensitivity points, got %d", scoreCI.SensitivityPoints)
	}
}

func TestComputeMaxScore100(t *testing.T) {
	engine := NewEngine()
	findings := make([]analysis.Finding, 50)
	for i := range findings {
		findings[i] = analysis.Finding{
			Type:         analysis.TypeSCA,
			Severity:     analysis.SeverityCritical,
			Reachability: analysis.ReachabilityHigh,
		}
	}

	score := engine.Compute(ScoreInput{
		Findings:              findings,
		FilesChanged:          100,
		AddedLines:            5000,
		DeletedLines:          2000,
		AuthFilesChanged:      true,
		CIWorkflowChanged:     true,
		DependencyFilesChanged: true,
	})

	if score.Score > 100 {
		t.Errorf("score should be capped at 100, got %d", score.Score)
	}
	if score.Level != "critical" {
		t.Errorf("with max findings, level should be critical, got %s", score.Level)
	}
}

func TestScoreToLevel(t *testing.T) {
	tests := []struct {
		score int
		level string
	}{
		{0, "minimal"},
		{19, "minimal"},
		{20, "low"},
		{39, "low"},
		{40, "medium"},
		{59, "medium"},
		{60, "high"},
		{79, "high"},
		{80, "critical"},
		{100, "critical"},
	}
	for _, tt := range tests {
		if got := scoreToLevel(tt.score); got != tt.level {
			t.Errorf("scoreToLevel(%d) = %s, want %s", tt.score, got, tt.level)
		}
	}
}

func TestTopFindingsSorted(t *testing.T) {
	engine := NewEngine()
	findings := []analysis.Finding{
		{Type: analysis.TypeSCA, Severity: analysis.SeverityLow},
		{Type: analysis.TypeSCA, Severity: analysis.SeverityCritical, Reachability: analysis.ReachabilityHigh},
		{Type: analysis.TypeSCA, Severity: analysis.SeverityMedium},
		{Type: analysis.TypeSCA, Severity: analysis.SeverityHigh},
	}

	score := engine.Compute(ScoreInput{Findings: findings})

	if len(score.TopFindings) != 4 {
		t.Fatalf("expected 4 top findings, got %d", len(score.TopFindings))
	}

	// First should be critical
	if score.TopFindings[0].Severity != analysis.SeverityCritical {
		t.Errorf("first top finding should be critical, got %s", score.TopFindings[0].Severity)
	}
	// Second should be high
	if score.TopFindings[1].Severity != analysis.SeverityHigh {
		t.Errorf("second top finding should be high, got %s", score.TopFindings[1].Severity)
	}
}
