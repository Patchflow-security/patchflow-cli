// Package risk computes a risk score (0-100) from analysis findings,
// change metadata, and reachability data. The score represents the
// overall risk introduced by a code change.
package risk

import (
	"sort"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
)

// Engine computes risk scores from analysis results.
type Engine struct{}

// NewEngine creates a risk scoring engine.
func NewEngine() *Engine {
	return &Engine{}
}

// ScoreInput contains all the inputs needed to compute a risk score.
type ScoreInput struct {
	Findings              []analysis.Finding
	FilesChanged          int
	AddedLines            int
	DeletedLines          int
	DependencyFilesChanged bool
	CIWorkflowChanged     bool
	AuthFilesChanged      bool
}

// ScoreOutput contains the computed risk score and its breakdown.
type ScoreOutput struct {
	Score         int            `json:"score"`
	Level         string         `json:"level"`
	VulnerabilityPoints int      `json:"vulnerability_points"`
	SASTPoints    int            `json:"sast_points"`
	SecretPoints  int            `json:"secret_points"`
	ChangePoints  int            `json:"change_points"`
	SensitivityPoints int        `json:"sensitivity_points"`
	ReachabilityBonus int        `json:"reachability_bonus"`
	FindingsBySeverity map[string]int `json:"findings_by_severity"`
	TopFindings   []analysis.Finding `json:"top_findings"`
}

// Compute calculates the risk score from the given inputs.
// The score is a value from 0 to 100 where higher is riskier.
func (e *Engine) Compute(input ScoreInput) ScoreOutput {
	output := ScoreOutput{
		FindingsBySeverity: make(map[string]int),
	}

	// Count findings by severity
	for _, f := range input.Findings {
		sev := string(f.Severity)
		output.FindingsBySeverity[sev]++
	}

	// 1. Vulnerability points (SCA findings) — weighted by severity and reachability
	maxVulnPoints := 50
	vulnPoints := 0
	var scaFindings []analysis.Finding
	for _, f := range input.Findings {
		if f.Type == analysis.TypeSCA {
			scaFindings = append(scaFindings, f)
			base := analysis.SeverityWeight(f.Severity)
			reachMultiplier := analysis.ReachabilityWeight(f.Reachability)
			points := int(float64(base) * reachMultiplier * 0.3) // scale to max ~30 per critical reachable
			vulnPoints += points
		}
	}
	if vulnPoints > maxVulnPoints {
		vulnPoints = maxVulnPoints
	}
	output.VulnerabilityPoints = vulnPoints

	// 2. SAST points
	maxSASTPoints := 25
	sastPoints := 0
	for _, f := range input.Findings {
		if f.Type == analysis.TypeSAST {
			base := analysis.SeverityWeight(f.Severity)
			points := int(float64(base) * 0.15)
			sastPoints += points
		}
	}
	if sastPoints > maxSASTPoints {
		sastPoints = maxSASTPoints
	}
	output.SASTPoints = sastPoints

	// 3. Secret points — secrets are always high-impact
	maxSecretPoints := 20
	secretPoints := 0
	for _, f := range input.Findings {
		if f.Type == analysis.TypeSecret {
			secretPoints += 15
		}
	}
	if secretPoints > maxSecretPoints {
		secretPoints = maxSecretPoints
	}
	output.SecretPoints = secretPoints

	// 4. Change size points — larger changes carry more risk
	maxChangePoints := 15
	changePoints := 0
	totalLines := input.AddedLines + input.DeletedLines
	switch {
	case totalLines > 1000:
		changePoints = 15
	case totalLines > 500:
		changePoints = 12
	case totalLines > 200:
		changePoints = 8
	case totalLines > 50:
		changePoints = 5
	case totalLines > 10:
		changePoints = 3
	case totalLines > 0:
		changePoints = 1
	}
	// Many files changed also increases risk
	if input.FilesChanged > 20 {
		changePoints += 5
	} else if input.FilesChanged > 10 {
		changePoints += 3
	} else if input.FilesChanged > 5 {
		changePoints += 1
	}
	if changePoints > maxChangePoints {
		changePoints = maxChangePoints
	}
	output.ChangePoints = changePoints

	// 5. Sensitivity points — changes to sensitive areas
	maxSensitivityPoints := 15
	sensitivityPoints := 0
	if input.AuthFilesChanged {
		sensitivityPoints += 8
	}
	if input.CIWorkflowChanged {
		sensitivityPoints += 5
	}
	if input.DependencyFilesChanged {
		sensitivityPoints += 4
	}
	if sensitivityPoints > maxSensitivityPoints {
		sensitivityPoints = maxSensitivityPoints
	}
	output.SensitivityPoints = sensitivityPoints

	// 6. Reachability bonus — reachable vulnerabilities boost the score
	reachBonus := 0
	for _, f := range input.Findings {
		if f.Type == analysis.TypeSCA && f.Reachability == analysis.ReachabilityHigh {
			reachBonus += 3
		}
	}
	if reachBonus > 10 {
		reachBonus = 10
	}
	output.ReachabilityBonus = reachBonus

	// Total score (capped at 100)
	total := vulnPoints + sastPoints + secretPoints + changePoints + sensitivityPoints + reachBonus
	if total > 100 {
		total = 100
	}
	if total < 0 {
		total = 0
	}

	output.Score = total
	output.Level = scoreToLevel(total)

	// Top findings (sorted by severity, then reachability)
	allFindings := make([]analysis.Finding, len(input.Findings))
	copy(allFindings, input.Findings)
	sort.Slice(allFindings, func(i, j int) bool {
		si := analysis.SeverityOrder(allFindings[i].Severity)
		sj := analysis.SeverityOrder(allFindings[j].Severity)
		if si != sj {
			return si > sj
		}
		ri := analysis.ReachabilityWeight(allFindings[i].Reachability)
		rj := analysis.ReachabilityWeight(allFindings[j].Reachability)
		return ri > rj
	})
	if len(allFindings) > 10 {
		allFindings = allFindings[:10]
	}
	output.TopFindings = allFindings

	return output
}

// scoreToLevel converts a numeric score to a risk level label.
func scoreToLevel(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 40:
		return "medium"
	case score >= 20:
		return "low"
	default:
		return "minimal"
	}
}

// LevelColor returns an ANSI color code for a risk level (for terminal output).
func LevelColor(level string) string {
	switch level {
	case "critical":
		return "\033[31m" // red
	case "high":
		return "\033[33m" // yellow
	case "medium":
		return "\033[33m" // yellow
	case "low":
		return "\033[32m" // green
	default:
		return "\033[32m" // green
	}
}

// ResetColor is the ANSI reset code.
const ResetColor = "\033[0m"
