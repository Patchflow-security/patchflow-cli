// GitLab Code Quality report format implementation.
// See: https://docs.gitlab.com/ee/ci/testing/code_quality.html#implement-a-custom-tool
package report

import (
	"encoding/json"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
)

// GitLabCodeQualityFinding represents a single finding in GitLab Code Quality format.
// The format is documented at:
// https://github.com/codeclimate/spec/blob/master/SPEC.md
type GitLabCodeQualityFinding struct {
	Description   string `json:"description"`
	CheckName     string `json:"check_name"`
	Fingerprint   string `json:"fingerprint"`
	Severity      string `json:"severity"`
	Location      GitLabCQLocation `json:"location"`
	Categories    []string `json:"categories"`
	Content       GitLabContent `json:"content,omitempty"`
	Remediation   GitLabRemediation `json:"remediation_points,omitempty"`
	OtherLocations []GitLabCQLocation `json:"other_locations,omitempty"`
}

// GitLabCQLocation represents the location of a finding.
type GitLabCQLocation struct {
	Path  string `json:"path"`
	Lines GitLabCQLines `json:"lines"`
}

// GitLabCQLines represents line range information.
type GitLabCQLines struct {
	Begin int `json:"begin"`
	End   int `json:"end"`
}

// GitLabContent represents the code content around a finding.
type GitLabContent struct {
	Body string `json:"body"`
}

// GitLabRemediation represents the remediation effort.
type GitLabRemediation struct {
	Points int `json:"points"`
}

// severityToGitLab maps PatchFlow severity to GitLab Code Quality severity.
// GitLab uses: info, minor, major, critical, blocker
func severityToGitLab(sev analysis.Severity) string {
	switch sev {
	case analysis.SeverityCritical:
		return "blocker"
	case analysis.SeverityHigh:
		return "critical"
	case analysis.SeverityMedium:
		return "major"
	case analysis.SeverityLow:
		return "minor"
	default:
		return "info"
	}
}

// categoryForFinding determines the Code Climate category for a finding.
func categoryForFinding(f analysis.Finding) []string {
	switch {
	case f.Type == analysis.TypeSCA:
		return []string{"Security", "Dependency"}
	case f.Type == analysis.TypeSecret:
		return []string{"Security", "Secrets"}
	case f.Type == analysis.TypeSAST:
		return []string{"Security", "Style"}
	default:
		return []string{"Security"}
	}
}

// remediationPointsForSeverity estimates remediation effort based on severity.
// Code Climate uses remediation_points (higher = more effort, 1 point = 1 hour).
func remediationPointsForSeverity(sev analysis.Severity) int {
	switch sev {
	case analysis.SeverityCritical:
		return 100000 // ~1 hour
	case analysis.SeverityHigh:
		return 50000
	case analysis.SeverityMedium:
		return 20000
	case analysis.SeverityLow:
		return 10000
	default:
		return 5000
	}
}

// GitLabCodeQuality generates a GitLab Code Quality report from the analysis result.
// The output is a JSON array compatible with GitLab CI Code Quality reports.
func (g *Generator) GitLabCodeQuality() ([]byte, error) {
	var findings []GitLabCodeQualityFinding

	for _, f := range g.Result.Findings {
		lineStart := f.LineStart
		if lineStart == 0 {
			lineStart = 1
		}
		lineEnd := f.LineEnd
		if lineEnd == 0 {
			lineEnd = lineStart
		}

		description := f.Title
		if f.Description != "" {
			description = f.Description
		}

		finding := GitLabCodeQualityFinding{
			Description: description,
			CheckName:   f.RuleID,
			Fingerprint: f.ID,
			Severity:    severityToGitLab(f.Severity),
			Location: GitLabCQLocation{
				Path: f.FilePath,
				Lines: GitLabCQLines{
					Begin: lineStart,
					End:   lineEnd,
				},
			},
			Categories:  categoryForFinding(f),
			Remediation: GitLabRemediation{Points: remediationPointsForSeverity(f.Severity)},
		}

		if f.Recommendation != "" {
			finding.Content = GitLabContent{Body: f.Recommendation}
		}

		findings = append(findings, finding)
	}

	return json.MarshalIndent(findings, "", "  ")
}
