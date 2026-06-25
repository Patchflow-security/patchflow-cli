// Package report generates analysis reports in multiple formats:
// terminal summary, Markdown, JSON, and SARIF 2.1.0.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/patchflow/patchflow-cli/internal/analysis"
	"github.com/patchflow/patchflow-cli/internal/risk"
)

// Generator produces reports from analysis results.
type Generator struct {
	Result *analysis.AnalysisResult
	Risk   *risk.ScoreOutput
}

// NewGenerator creates a report generator.
func NewGenerator(result *analysis.AnalysisResult, riskScore *risk.ScoreOutput) *Generator {
	return &Generator{Result: result, Risk: riskScore}
}

// --- Terminal summary ---

// TerminalSummary returns a human-readable summary string for terminal output.
func (g *Generator) TerminalSummary() string {
	var sb strings.Builder

	sb.WriteString("\n")
	sb.WriteString("PatchFlow Analysis Report\n")
	sb.WriteString("=========================\n")
	sb.WriteString("\n")

	// Repository info
	if g.Result != nil {
		sb.WriteString(fmt.Sprintf("Repository:  %s\n", g.Result.ProjectRoot))
		sb.WriteString(fmt.Sprintf("Branch:      %s\n", g.Result.Branch))
		sb.WriteString(fmt.Sprintf("Commit:      %s\n", shortenSHA(g.Result.CommitSHA)))
		sb.WriteString(fmt.Sprintf("Base:        %s\n", g.Result.BaseBranch))
		sb.WriteString("\n")

		sb.WriteString(fmt.Sprintf("Files changed: %d  (+%d / -%d)\n",
			g.Result.FilesChanged, g.Result.AddedLines, g.Result.DeletedLines))
		sb.WriteString(fmt.Sprintf("Dependencies:  %d\n", len(g.Result.Dependencies)))
		sb.WriteString(fmt.Sprintf("Manifests:     %d\n", len(g.Result.Manifests)))
		sb.WriteString(fmt.Sprintf("Analyzers:     %s\n", strings.Join(g.Result.Analyzers, ", ")))
		sb.WriteString("\n")
	}

	// Risk score
	if g.Risk != nil {
		sb.WriteString(fmt.Sprintf("Risk Score: %d/100 (%s)\n", g.Risk.Score, strings.ToUpper(g.Risk.Level)))
		sb.WriteString("\n")

		// Severity breakdown
		if len(g.Risk.FindingsBySeverity) > 0 {
			sb.WriteString("Findings by severity:\n")
			severities := []string{"critical", "high", "medium", "low", "info"}
			for _, sev := range severities {
				if count, ok := g.Risk.FindingsBySeverity[sev]; ok && count > 0 {
					sb.WriteString(fmt.Sprintf("  %-10s  %d\n", sev, count))
				}
			}
			sb.WriteString("\n")
		}
	}

	// Top findings
	if g.Risk != nil && len(g.Risk.TopFindings) > 0 {
		sb.WriteString("Top findings:\n")
		for i, f := range g.Risk.TopFindings {
			sb.WriteString(fmt.Sprintf("  %d. [%s] %s\n", i+1, strings.ToUpper(string(f.Severity)), f.Title))
			if f.PackageName != "" {
				sb.WriteString(fmt.Sprintf("     Package: %s@%s\n", f.PackageName, f.PackageVersion))
			}
			if f.FilePath != "" {
				sb.WriteString(fmt.Sprintf("     File:    %s:%d\n", f.FilePath, f.LineStart))
			}
			if f.Recommendation != "" {
				sb.WriteString(fmt.Sprintf("     Fix:     %s\n", f.Recommendation))
			}
			if f.Reachability != "" {
				sb.WriteString(fmt.Sprintf("     Reach:   %s\n", f.Reachability))
			}
			sb.WriteString("\n")
		}
	}

	// Recommendations
	if g.Risk != nil {
		sb.WriteString("Recommendations:\n")
		recs := g.generateRecommendations()
		for i, rec := range recs {
			sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, rec))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func (g *Generator) generateRecommendations() []string {
	var recs []string

	if g.Risk == nil {
		return recs
	}

	// Critical/high reachable vulnerabilities
	criticalReachable := 0
	highReachable := 0
	secretsFound := 0
	for _, f := range g.Risk.TopFindings {
		if f.Type == analysis.TypeSecret {
			secretsFound++
		}
		if f.Severity == analysis.SeverityCritical && f.Reachability == analysis.ReachabilityHigh {
			criticalReachable++
		}
		if f.Severity == analysis.SeverityHigh && f.Reachability == analysis.ReachabilityHigh {
			highReachable++
		}
	}

	if secretsFound > 0 {
		recs = append(recs, fmt.Sprintf("Rotate and remove %d detected secret(s) immediately", secretsFound))
	}
	if criticalReachable > 0 {
		recs = append(recs, fmt.Sprintf("Fix %d critical reachable vulnerability(s) before opening a PR", criticalReachable))
	}
	if highReachable > 0 {
		recs = append(recs, fmt.Sprintf("Address %d high-severity reachable vulnerability(s)", highReachable))
	}

	// Check for upgradeable packages
	upgrades := 0
	for _, f := range g.Risk.TopFindings {
		if f.FixedVersion != "" {
			upgrades++
		}
	}
	if upgrades > 0 {
		recs = append(recs, fmt.Sprintf("Upgrade %d vulnerable package(s) to fixed versions", upgrades))
	}

	if len(recs) == 0 {
		recs = append(recs, "No critical issues detected — proceed with normal review")
	}

	return recs
}

// --- Markdown ---

// Markdown returns a full Markdown report.
func (g *Generator) Markdown() string {
	var sb strings.Builder

	sb.WriteString("# PatchFlow Analysis Report\n\n")
	sb.WriteString(fmt.Sprintf("**Generated:** %s\n\n", time.Now().UTC().Format(time.RFC3339)))

	// Summary
	sb.WriteString("## Summary\n\n")
	if g.Result != nil {
		sb.WriteString(fmt.Sprintf("| Field | Value |\n|-------|-------|\n"))
		sb.WriteString(fmt.Sprintf("| Repository | %s |\n", g.Result.ProjectRoot))
		sb.WriteString(fmt.Sprintf("| Branch | %s |\n", g.Result.Branch))
		sb.WriteString(fmt.Sprintf("| Commit | %s |\n", g.Result.CommitSHA))
		sb.WriteString(fmt.Sprintf("| Base | %s |\n", g.Result.BaseBranch))
		sb.WriteString(fmt.Sprintf("| Files changed | %d |\n", g.Result.FilesChanged))
		sb.WriteString(fmt.Sprintf("| Added lines | %d |\n", g.Result.AddedLines))
		sb.WriteString(fmt.Sprintf("| Deleted lines | %d |\n", g.Result.DeletedLines))
		sb.WriteString(fmt.Sprintf("| Dependencies | %d |\n", len(g.Result.Dependencies)))
		sb.WriteString(fmt.Sprintf("| Analyzers | %s |\n", strings.Join(g.Result.Analyzers, ", ")))
		sb.WriteString("\n")
	}

	// Risk score
	if g.Risk != nil {
		sb.WriteString("## Risk Score\n\n")
		sb.WriteString(fmt.Sprintf("**Score: %d/100 (%s)**\n\n", g.Risk.Score, strings.ToUpper(g.Risk.Level)))
		sb.WriteString("| Component | Points |\n|-----------|--------|\n")
		sb.WriteString(fmt.Sprintf("| Vulnerabilities (SCA) | %d |\n", g.Risk.VulnerabilityPoints))
		sb.WriteString(fmt.Sprintf("| SAST findings | %d |\n", g.Risk.SASTPoints))
		sb.WriteString(fmt.Sprintf("| Secrets | %d |\n", g.Risk.SecretPoints))
		sb.WriteString(fmt.Sprintf("| Change size | %d |\n", g.Risk.ChangePoints))
		sb.WriteString(fmt.Sprintf("| Sensitivity | %d |\n", g.Risk.SensitivityPoints))
		sb.WriteString(fmt.Sprintf("| Reachability bonus | %d |\n", g.Risk.ReachabilityBonus))
		sb.WriteString("\n")

		// Severity breakdown
		if len(g.Risk.FindingsBySeverity) > 0 {
			sb.WriteString("### Findings by Severity\n\n")
			sb.WriteString("| Severity | Count |\n|----------|-------|\n")
			severities := []string{"critical", "high", "medium", "low", "info"}
			for _, sev := range severities {
				if count, ok := g.Risk.FindingsBySeverity[sev]; ok && count > 0 {
					sb.WriteString(fmt.Sprintf("| %s | %d |\n", sev, count))
				}
			}
			sb.WriteString("\n")
		}
	}

	// Findings
	if g.Result != nil && len(g.Result.Findings) > 0 {
		sb.WriteString("## Findings\n\n")
		sortedFindings := sortFindings(g.Result.Findings)
		for i, f := range sortedFindings {
			sb.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, f.Title))
			sb.WriteString(fmt.Sprintf("- **Type:** %s\n", f.Type))
			sb.WriteString(fmt.Sprintf("- **Severity:** %s\n", f.Severity))
			sb.WriteString(fmt.Sprintf("- **Confidence:** %s\n", f.Confidence))
			sb.WriteString(fmt.Sprintf("- **Analyzer:** %s\n", f.Analyzer))
			if f.PackageName != "" {
				sb.WriteString(fmt.Sprintf("- **Package:** %s@%s\n", f.PackageName, f.PackageVersion))
			}
			if f.FixedVersion != "" {
				sb.WriteString(fmt.Sprintf("- **Fixed in:** %s\n", f.FixedVersion))
			}
			if f.CVEID != "" {
				sb.WriteString(fmt.Sprintf("- **CVE:** %s\n", f.CVEID))
			}
			if f.FilePath != "" {
				sb.WriteString(fmt.Sprintf("- **File:** %s:%d\n", f.FilePath, f.LineStart))
			}
			if f.RuleID != "" {
				sb.WriteString(fmt.Sprintf("- **Rule:** %s\n", f.RuleID))
			}
			if f.AdvisoryURL != "" {
				sb.WriteString(fmt.Sprintf("- **Advisory:** %s\n", f.AdvisoryURL))
			}
			if f.Reachability != "" {
				sb.WriteString(fmt.Sprintf("- **Reachability:** %s (confidence: %s)\n", f.Reachability, f.ReachabilityConfidence))
			}
			if len(f.ReachabilityEvidence) > 0 {
				sb.WriteString("- **Evidence:**\n")
				for _, e := range f.ReachabilityEvidence {
					sb.WriteString(fmt.Sprintf("  - %s\n", e))
				}
			}
			if f.Description != "" {
				sb.WriteString(fmt.Sprintf("\n%s\n", truncateForMarkdown(f.Description, 500)))
			}
			if f.Recommendation != "" {
				sb.WriteString(fmt.Sprintf("\n**Recommendation:** %s\n", f.Recommendation))
			}
			sb.WriteString("\n")
		}
	}

	// Dependencies
	if g.Result != nil && len(g.Result.Dependencies) > 0 {
		sb.WriteString("## Dependencies\n\n")
		sb.WriteString("| Package | Version | Ecosystem | Direct | Manifest |\n")
		sb.WriteString("|---------|---------|-----------|--------|----------|\n")
		for _, dep := range g.Result.Dependencies {
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %v | %s |\n",
				dep.Name, dep.Version, dep.Ecosystem, dep.IsDirect, dep.ManifestPath))
		}
		sb.WriteString("\n")
	}

	// Recommendations
	if g.Risk != nil {
		recs := g.generateRecommendations()
		if len(recs) > 0 {
			sb.WriteString("## Recommendations\n\n")
			for i, rec := range recs {
				sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec))
			}
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

// --- JSON ---

// JSON returns a full JSON report.
func (g *Generator) JSON() ([]byte, error) {
	report := struct {
		Generated    time.Time              `json:"generated"`
		Result       *analysis.AnalysisResult `json:"result"`
		Risk         *risk.ScoreOutput       `json:"risk"`
		Recommendations []string             `json:"recommendations"`
	}{
		Generated:       time.Now().UTC(),
		Result:          g.Result,
		Risk:            g.Risk,
		Recommendations: g.generateRecommendations(),
	}

	return json.MarshalIndent(report, "", "  ")
}

// --- SARIF 2.1.0 ---

// SARIFReport is a SARIF 2.1.0 report.
type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun is a single run in a SARIF report.
type SARIFRun struct {
	Tool    SARIFTool       `json:"tool"`
	Results []SARIFResult   `json:"results"`
}

// SARIFTool describes the tool that produced the report.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver is the tool driver component.
type SARIFDriver struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// SARIFResult is a single finding in SARIF format.
type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations,omitempty"`
}

// SARIFMessage is a SARIF message.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation is a SARIF location.
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation is a SARIF physical location.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

// SARIFArtifactLocation is a SARIF artifact location.
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFRegion is a SARIF region (line range).
type SARIFRegion struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine,omitempty"`
}

// SARIF returns a SARIF 2.1.0 report.
func (g *Generator) SARIF(toolVersion string) *SARIFReport {
	var results []SARIFResult

	if g.Result != nil {
		for _, f := range g.Result.Findings {
			result := SARIFResult{
				RuleID: f.RuleID,
				Level:  severityToSARIFLevel(f.Severity),
				Message: SARIFMessage{
					Text: f.Title,
				},
			}

			if f.FilePath != "" {
				loc := SARIFLocation{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: f.FilePath,
						},
					},
				}
				if f.LineStart > 0 {
					loc.PhysicalLocation.Region = &SARIFRegion{
						StartLine: f.LineStart,
						EndLine:   f.LineEnd,
					}
				}
				result.Locations = []SARIFLocation{loc}
			}

			if result.RuleID == "" {
				result.RuleID = string(f.Type) + "-" + f.Analyzer
			}

			results = append(results, result)
		}
	}

	return &SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:    "PatchFlow CLI",
						Version: toolVersion,
					},
				},
				Results: results,
			},
		},
	}
}

// --- File output ---

// WriteFile writes a report to a file in the specified format.
func (g *Generator) WriteFile(format, outputPath string) error {
	switch format {
	case "markdown", "md":
		content := g.Markdown()
		return os.WriteFile(outputPath, []byte(content), 0644)
	case "json":
		data, err := g.JSON()
		if err != nil {
			return err
		}
		return os.WriteFile(outputPath, data, 0644)
	case "sarif":
		report := g.SARIF("0.1.0")
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(outputPath, data, 0644)
	default:
		return fmt.Errorf("unsupported format: %s (supported: markdown, json, sarif)", format)
	}
}

// GenerateRecommendationsPublic exposes the recommendations for command use.
func (g *Generator) GenerateRecommendationsPublic() []string {
	return g.generateRecommendations()
}

// --- Helpers ---

func severityToSARIFLevel(s analysis.Severity) string {
	switch s {
	case analysis.SeverityCritical, analysis.SeverityHigh:
		return "error"
	case analysis.SeverityMedium:
		return "warning"
	case analysis.SeverityLow, analysis.SeverityInfo:
		return "note"
	default:
		return "none"
	}
}

func sortFindings(findings []analysis.Finding) []analysis.Finding {
	sorted := make([]analysis.Finding, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool {
		si := analysis.SeverityOrder(sorted[i].Severity)
		sj := analysis.SeverityOrder(sorted[j].Severity)
		if si != sj {
			return si > sj
		}
		ri := analysis.ReachabilityWeight(sorted[i].Reachability)
		rj := analysis.ReachabilityWeight(sorted[j].Reachability)
		return ri > rj
	})
	return sorted
}

func shortenSHA(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

func truncateForMarkdown(s string, maxLen int) string {
	// Strip HTML tags that might be in OSV details
	s = stripHTML(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func stripHTML(s string) string {
	var result strings.Builder
	inTag := false
	for _, c := range s {
		if c == '<' {
			inTag = true
			continue
		}
		if c == '>' {
			inTag = false
			continue
		}
		if !inTag {
			result.WriteRune(c)
		}
	}
	return result.String()
}

// WriteToReportsDir writes a report to the .patchflow/reports/ directory.
func (g *Generator) WriteToReportsDir(root, format string) (string, error) {
	reportsDir := filepath.Join(root, ".patchflow", "reports")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create reports directory: %w", err)
	}

	timestamp := time.Now().UTC().Format("20060102-150405")
	ext := "json"
	switch format {
	case "markdown", "md":
		ext = "md"
	case "sarif":
		ext = "sarif"
	}

	filename := fmt.Sprintf("patchflow-report-%s.%s", timestamp, ext)
	outputPath := filepath.Join(reportsDir, filename)

	if err := g.WriteFile(format, outputPath); err != nil {
		return "", err
	}

	return outputPath, nil
}
