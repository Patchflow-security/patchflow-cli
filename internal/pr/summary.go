// Package pr provides PR (Pull Request) intelligence features:
// summary generation, inline annotations, and diff-hunk-aware finding placement.
package pr

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/risk"
)

// DiffHunk represents a single hunk from a git diff.
type DiffHunk struct {
	FilePath   string
	OldStart   int
	OldCount   int
	NewStart   int
	NewCount   int
	Lines      []DiffLine
}

// DiffLine represents a single line in a diff hunk.
type DiffLine struct {
	Type    string // "add", "del", "ctx"
	Content string
	NewNum  int
	OldNum  int
}

// FileDiff represents the diff for a single file.
type FileDiff struct {
	Path     string
	OldPath  string
	NewPath  string
	IsNew    bool
	IsDeleted bool
	Hunks    []DiffHunk
}

// ParseDiff parses unified diff output into structured file diffs.
func ParseDiff(diffOutput string) []FileDiff {
	var files []FileDiff
	var currentFile *FileDiff
	var currentHunk *DiffHunk
	newLineNum := 0
	oldLineNum := 0

	lines := strings.Split(diffOutput, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "diff --git") {
			if currentFile != nil {
				if currentHunk != nil {
					currentFile.Hunks = append(currentFile.Hunks, *currentHunk)
					currentHunk = nil
				}
				files = append(files, *currentFile)
			}
			currentFile = &FileDiff{}
			currentHunk = nil
			continue
		}
		if currentFile == nil {
			continue
		}

		if strings.HasPrefix(line, "--- ") {
			currentFile.OldPath = strings.TrimPrefix(line, "--- ")
			if currentFile.OldPath == "/dev/null" {
				currentFile.IsNew = true
			}
			continue
		}
		if strings.HasPrefix(line, "+++ ") {
			currentFile.NewPath = strings.TrimPrefix(line, "+++ ")
			if currentFile.NewPath == "/dev/null" {
				currentFile.IsDeleted = true
			}
			// Extract the actual path (remove a/ or b/ prefix)
			if strings.HasPrefix(currentFile.NewPath, "b/") {
				currentFile.Path = strings.TrimPrefix(currentFile.NewPath, "b/")
			} else if strings.HasPrefix(currentFile.OldPath, "a/") {
				currentFile.Path = strings.TrimPrefix(currentFile.OldPath, "a/")
			} else {
				currentFile.Path = currentFile.NewPath
			}
			continue
		}

		if strings.HasPrefix(line, "@@ ") {
			if currentHunk != nil {
				currentFile.Hunks = append(currentFile.Hunks, *currentHunk)
			}
			currentHunk = parseHunkHeader(line)
			currentHunk.FilePath = currentFile.Path
			newLineNum = currentHunk.NewStart
			oldLineNum = currentHunk.OldStart
			continue
		}

		if currentHunk == nil {
			continue
		}

		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			currentHunk.Lines = append(currentHunk.Lines, DiffLine{
				Type:    "add",
				Content: strings.TrimPrefix(line, "+"),
				NewNum:  newLineNum,
			})
			newLineNum++
		} else if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
			currentHunk.Lines = append(currentHunk.Lines, DiffLine{
				Type:    "del",
				Content: strings.TrimPrefix(line, "-"),
				OldNum:  oldLineNum,
			})
			oldLineNum++
		} else {
			currentHunk.Lines = append(currentHunk.Lines, DiffLine{
				Type:    "ctx",
				Content: strings.TrimPrefix(line, " "),
				NewNum:  newLineNum,
				OldNum:  oldLineNum,
			})
			newLineNum++
			oldLineNum++
		}
	}

	if currentFile != nil {
		if currentHunk != nil {
			currentFile.Hunks = append(currentFile.Hunks, *currentHunk)
		}
		files = append(files, *currentFile)
	}

	return files
}

// parseHunkHeader parses a @@ -oldStart,oldCount +newStart,newCount @@ line.
func parseHunkHeader(line string) *DiffHunk {
	hunk := &DiffHunk{}
	// Format: @@ -oldStart,oldCount +newStart,newCount @@
	rest := strings.TrimPrefix(line, "@@ ")
	parts := strings.SplitN(rest, " ", 2)
	if len(parts) >= 1 {
		oldPart := strings.TrimPrefix(parts[0], "-")
		oldStart, oldCount := parseRange(oldPart)
		hunk.OldStart = oldStart
		hunk.OldCount = oldCount
	}
	if len(parts) >= 2 {
		newPart := strings.TrimPrefix(parts[1], "+")
		// Remove trailing @@ and anything after
		if idx := strings.Index(newPart, " @@"); idx >= 0 {
			newPart = newPart[:idx]
		}
		newStart, newCount := parseRange(newPart)
		hunk.NewStart = newStart
		hunk.NewCount = newCount
	}
	return hunk
}

func parseRange(s string) (start, count int) {
	parts := strings.SplitN(s, ",", 2)
	fmt.Sscanf(parts[0], "%d", &start)
	if len(parts) == 2 {
		fmt.Sscanf(parts[1], "%d", &count)
	} else {
		count = 1
	}
	return
}

// GetDiff runs git diff and returns the raw output.
func GetDiff(repoRoot, baseRef string) (string, error) {
	cmd := exec.Command("git", "diff", baseRef+"...HEAD", "--unified=3")
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Fallback to two-dot diff
		cmd = exec.Command("git", "diff", baseRef+"..HEAD", "--unified=3")
		cmd.Dir = repoRoot
		out, err = cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("git diff failed: %w", err)
		}
	}
	return string(out), nil
}

// FindingPlacement maps a finding to its position in the diff.
type FindingPlacement struct {
	Finding    analysis.Finding
	FilePath   string
	LineInDiff int    // line number in the new file
	InDiff     bool   // whether the finding is in a changed hunk
	HunkIndex  int    // which hunk the finding falls in
	DiffLine   string // the actual diff line content
}

// PlaceFindings maps findings to diff hunks to determine which findings
// are in changed code and where they should be annotated.
func PlaceFindings(findings []analysis.Finding, diffs []FileDiff) []FindingPlacement {
	var placements []FindingPlacement

	// Build a map of file -> diffs
	diffMap := make(map[string]*FileDiff)
	for i := range diffs {
		diffMap[diffs[i].Path] = &diffs[i]
	}

	for _, f := range findings {
		placement := FindingPlacement{
			Finding:  f,
			FilePath: f.FilePath,
		}

		diff, ok := diffMap[f.FilePath]
		if !ok {
			// Try matching by basename
			baseName := filepath.Base(f.FilePath)
			for path, d := range diffMap {
				if filepath.Base(path) == baseName {
					diff = d
					break
				}
			}
		}

		if diff != nil {
			placement.InDiff = true
			placement.LineInDiff = f.LineStart
			// Find which hunk the finding falls in
			for i, hunk := range diff.Hunks {
				if f.LineStart >= hunk.NewStart && f.LineStart < hunk.NewStart+hunk.NewCount {
					placement.HunkIndex = i
					// Find the actual diff line
					for _, dl := range hunk.Lines {
						if dl.NewNum == f.LineStart {
							placement.DiffLine = dl.Content
							break
						}
					}
					break
				}
			}
		}

		placements = append(placements, placement)
	}

	return placements
}

// PRSummary is a PR-optimized summary of analysis results.
type PRSummary struct {
	Title         string             `json:"title"`
	GeneratedAt   time.Time          `json:"generated_at"`
	Branch        string             `json:"branch"`
	BaseBranch    string             `json:"base_branch"`
	CommitSHA     string             `json:"commit_sha"`
	FilesChanged  int                `json:"files_changed"`
	AddedLines    int                `json:"added_lines"`
	DeletedLines  int                `json:"deleted_lines"`
	RiskScore     int                `json:"risk_score"`
	RiskLevel     string             `json:"risk_level"`
	TotalFindings int                `json:"total_findings"`
	NewFindings   int                `json:"new_findings"`
	BySeverity    map[string]int     `json:"by_severity"`
	ByType        map[string]int     `json:"by_type"`
	TopFindings   []FindingSummary   `json:"top_findings"`
	Recommendations []string         `json:"recommendations"`
	Status        string             `json:"status"`
	Verdict       string             `json:"verdict"`
}

// FindingSummary is a condensed finding for PR display.
type FindingSummary struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Severity     string `json:"severity"`
	Title        string `json:"title"`
	FilePath     string `json:"file_path,omitempty"`
	LineStart    int    `json:"line_start,omitempty"`
	PackageName  string `json:"package_name,omitempty"`
	Reachability string `json:"reachability,omitempty"`
	InDiff       bool   `json:"in_diff"`
}

// GeneratePRSummary creates a PR-optimized summary from analysis results,
// risk score, and diff information.
func GeneratePRSummary(result *analysis.AnalysisResult, riskScore *risk.ScoreOutput, placements []FindingPlacement) *PRSummary {
	summary := &PRSummary{
		GeneratedAt:  time.Now().UTC(),
		Branch:       result.Branch,
		BaseBranch:   result.BaseBranch,
		CommitSHA:    result.CommitSHA,
		FilesChanged: result.FilesChanged,
		AddedLines:   result.AddedLines,
		DeletedLines: result.DeletedLines,
		RiskScore:    riskScore.Score,
		RiskLevel:    riskScore.Level,
		BySeverity:   make(map[string]int),
		ByType:       make(map[string]int),
	}

	// Count findings
	summary.TotalFindings = len(result.Findings)
	for _, f := range result.Findings {
		summary.BySeverity[string(f.Severity)]++
		summary.ByType[string(f.Type)]++
	}

	// Count findings in diff
	inDiffCount := 0
	for _, p := range placements {
		if p.InDiff {
			inDiffCount++
		}
	}
	summary.NewFindings = inDiffCount

	// Build finding summaries (sorted by severity)
	var findingSummaries []FindingSummary
	placementMap := make(map[string]*FindingPlacement)
	for i := range placements {
		placementMap[placements[i].Finding.ID] = &placements[i]
	}
	for _, f := range result.Findings {
		fs := FindingSummary{
			ID:           f.ID,
			Type:         string(f.Type),
			Severity:     string(f.Severity),
			Title:        f.Title,
			FilePath:     f.FilePath,
			LineStart:    f.LineStart,
			PackageName:  f.PackageName,
			Reachability: string(f.Reachability),
		}
		if p, ok := placementMap[f.ID]; ok {
			fs.InDiff = p.InDiff
		}
		findingSummaries = append(findingSummaries, fs)
	}

	// Sort by severity (critical first)
	sort.Slice(findingSummaries, func(i, j int) bool {
		return analysis.SeverityOrder(analysis.Severity(findingSummaries[i].Severity)) >
			analysis.SeverityOrder(analysis.Severity(findingSummaries[j].Severity))
	})

	// Top 10
	if len(findingSummaries) > 10 {
		findingSummaries = findingSummaries[:10]
	}
	summary.TopFindings = findingSummaries

	// Status and verdict
	summary.Status = "Ready for review"
	summary.Verdict = "This PR looks safe to merge."
	if riskScore.Score >= 80 {
		summary.Status = "BLOCKING"
		summary.Verdict = "This PR introduces critical security issues. Do not merge until fixed."
	} else if riskScore.Score >= 60 {
		summary.Status = "Warning"
		summary.Verdict = "This PR has high-severity findings. Review carefully before merging."
	} else if riskScore.Score >= 40 {
		summary.Status = "Caution"
		summary.Verdict = "This PR has some findings worth reviewing."
	}

	return summary
}

// RenderMarkdown renders the PR summary as a markdown comment suitable for
// posting as a PR review comment.
func RenderMarkdown(summary *PRSummary) string {
	var b strings.Builder

	b.WriteString("## PatchFlow PR Review\n\n")

	// Risk badge
	riskEmoji := "green_circle"
	switch summary.RiskLevel {
	case "critical":
		riskEmoji = "red_circle"
	case "high":
		riskEmoji = "orange_circle"
	case "medium":
		riskEmoji = "yellow_circle"
	case "low":
		riskEmoji = "green_circle"
	default:
		riskEmoji = "white_circle"
	}

	b.WriteString(fmt.Sprintf("**Risk:** %s %d/100 — %s\n\n",
		riskEmoji, summary.RiskScore, strings.ToUpper(summary.RiskLevel)))
	b.WriteString(fmt.Sprintf("**Status:** %s\n\n", summary.Status))
	b.WriteString(fmt.Sprintf("> %s\n\n", summary.Verdict))

	// Change summary
	b.WriteString("### Changes\n\n")
	b.WriteString(fmt.Sprintf("- **Files changed:** %d\n", summary.FilesChanged))
	b.WriteString(fmt.Sprintf("- **Lines:** +%d / -%d\n", summary.AddedLines, summary.DeletedLines))
	b.WriteString(fmt.Sprintf("- **Findings:** %d total (%d in changed code)\n\n",
		summary.TotalFindings, summary.NewFindings))

	// Severity breakdown
	if len(summary.BySeverity) > 0 {
		b.WriteString("### Findings by Severity\n\n")
		b.WriteString("| Severity | Count |\n")
		b.WriteString("|----------|-------|\n")
		for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
			if count, ok := summary.BySeverity[sev]; ok && count > 0 {
				b.WriteString(fmt.Sprintf("| %s | %d |\n", sev, count))
			}
		}
		b.WriteString("\n")
	}

	// Top findings
	if len(summary.TopFindings) > 0 {
		b.WriteString("### Top Findings\n\n")
		for i, f := range summary.TopFindings {
			diffMarker := ""
			if f.InDiff {
				diffMarker = " **[NEW]**"
			}
			b.WriteString(fmt.Sprintf("%d. **[%s]** %s%s\n", i+1,
				strings.ToUpper(f.Severity), f.Title, diffMarker))
			if f.PackageName != "" {
				b.WriteString(fmt.Sprintf("   - Package: `%s`\n", f.PackageName))
			}
			if f.FilePath != "" {
				b.WriteString(fmt.Sprintf("   - File: `%s:%d`\n", f.FilePath, f.LineStart))
			}
			if f.Reachability != "" {
				b.WriteString(fmt.Sprintf("   - Reachability: %s\n", f.Reachability))
			}
		}
		b.WriteString("\n")
	}

	// Recommendations
	if len(summary.Recommendations) > 0 {
		b.WriteString("### Recommendations\n\n")
		for _, rec := range summary.Recommendations {
			b.WriteString(fmt.Sprintf("- %s\n", rec))
		}
		b.WriteString("\n")
	}

	b.WriteString("---\n_Generated by [PatchFlow](https://patchflow.dev)_\n")

	return b.String()
}
