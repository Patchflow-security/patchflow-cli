// Inline annotation generation for GitHub and GitLab PR review comments.
package pr

import (
	"fmt"
	"strings"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
)

// Annotation represents a single inline code annotation for a PR review.
type Annotation struct {
	// Path is the file path relative to repo root.
	Path string `json:"path"`
	// Line is the line number in the new version of the file.
	Line int `json:"line"`
	// EndLine is the end line for multi-line annotations (optional).
	EndLine int `json:"end_line,omitempty"`
	// Severity is the annotation severity: "critical", "high", "medium", "low".
	Severity string `json:"severity"`
	// Title is a short title for the annotation.
	Title string `json:"title"`
	// Message is the detailed annotation message.
	Message string `json:"message"`
	// FindingID links back to the PatchFlow finding.
	FindingID string `json:"finding_id"`
}

// GenerateAnnotations creates inline annotations from finding placements.
// Only findings that are in the diff (InDiff=true) are included, since
// inline annotations can only be placed on changed lines.
func GenerateAnnotations(placements []FindingPlacement) []Annotation {
	var annotations []Annotation
	for _, p := range placements {
		if !p.InDiff || p.Finding.FilePath == "" || p.Finding.LineStart == 0 {
			continue
		}

		ann := Annotation{
			Path:      p.Finding.FilePath,
			Line:      p.Finding.LineStart,
			EndLine:   p.Finding.LineEnd,
			Severity:  string(p.Finding.Severity),
			Title:     p.Finding.Title,
			FindingID: p.Finding.ID,
		}

		// Build message
		var msg strings.Builder
		msg.WriteString(p.Finding.Description)
		if p.Finding.Recommendation != "" {
			msg.WriteString("\n\n**Fix:** ")
			msg.WriteString(p.Finding.Recommendation)
		}
		if p.Finding.CVEID != "" {
			msg.WriteString("\n\n**CVE:** ")
			msg.WriteString(p.Finding.CVEID)
		}
		if p.Finding.Reachability != "" {
			msg.WriteString("\n**Reachability:** ")
			msg.WriteString(string(p.Finding.Reachability))
		}
		ann.Message = msg.String()

		annotations = append(annotations, ann)
	}
	return annotations
}

// GitHubAnnotation is the GitHub Checks API annotation format.
type GitHubAnnotation struct {
	Path        string `json:"path"`
	StartLine   int    `json:"start_line"`
	EndLine     int    `json:"end_line"`
	StartColumn int    `json:"start_column,omitempty"`
	EndColumn   int    `json:"end_column,omitempty"`
	AnnotationLevel string `json:"annotation_level"` // "notice", "warning", "failure"
	Message     string `json:"message"`
	Title       string `json:"title,omitempty"`
	RawDetails  string `json:"raw_details,omitempty"`
}

// ToGitHubAnnotations converts PatchFlow annotations to GitHub Checks API format.
func ToGitHubAnnotations(annotations []Annotation) []GitHubAnnotation {
	var result []GitHubAnnotation
	for _, ann := range annotations {
		level := "notice"
		switch ann.Severity {
		case "critical", "high":
			level = "failure"
		case "medium":
			level = "warning"
		case "low":
			level = "notice"
		}

		endLine := ann.EndLine
		if endLine == 0 {
			endLine = ann.Line
		}

		ga := GitHubAnnotation{
			Path:            ann.Path,
			StartLine:       ann.Line,
			EndLine:         endLine,
			AnnotationLevel: level,
			Message:         ann.Message,
			Title:           ann.Title,
		}
		result = append(result, ga)
	}
	return result
}

// GitLabAnnotation is the GitLab MR discussion annotation format.
type GitLabAnnotation struct {
	Body     string         `json:"body"`
	Position GitLabPosition `json:"position"`
}

// GitLabPosition describes the position of an annotation in a GitLab MR.
type GitLabPosition struct {
	BaseSHA      string `json:"base_sha"`
	HeadSHA      string `json:"head_sha"`
	StartSHA     string `json:"start_sha"`
	PositionType string `json:"position_type"` // "text"
	NewPath      string `json:"new_path"`
	NewLine      int    `json:"new_line"`
	OldPath      string `json:"old_path,omitempty"`
	OldLine      int    `json:"old_line,omitempty"`
}

// ToGitLabAnnotations converts PatchFlow annotations to GitLab MR format.
func ToGitLabAnnotations(annotations []Annotation, baseSHA, headSHA, startSHA string) []GitLabAnnotation {
	var result []GitLabAnnotation
	for _, ann := range annotations {
		body := fmt.Sprintf("**[%s] %s**\n\n%s", strings.ToUpper(ann.Severity), ann.Title, ann.Message)

		ga := GitLabAnnotation{
			Body: body,
			Position: GitLabPosition{
				BaseSHA:      baseSHA,
				HeadSHA:      headSHA,
				StartSHA:     startSHA,
				PositionType: "text",
				NewPath:      ann.Path,
				NewLine:      ann.Line,
			},
		}
		result = append(result, ga)
	}
	return result
}

// RenderAnnotationsMarkdown renders annotations as a markdown list (for
// PR comments when inline API isn't available).
func RenderAnnotationsMarkdown(annotations []Annotation) string {
	if len(annotations) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("### Inline Findings\n\n")
	for _, ann := range annotations {
		severityIcon := severityIcon(ann.Severity)
		b.WriteString(fmt.Sprintf("%s **[%s]** %s\n", severityIcon,
			strings.ToUpper(ann.Severity), ann.Title))
		b.WriteString(fmt.Sprintf("   - `[%s:%d](%s#L%d)`\n",
			ann.Path, ann.Line, ann.Path, ann.Line))
		if ann.Message != "" {
			// Show first line of message
			lines := strings.Split(ann.Message, "\n")
			b.WriteString(fmt.Sprintf("   - %s\n", lines[0]))
		}
	}
	return b.String()
}

func severityIcon(severity string) string {
	switch severity {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	default:
		return "⚪"
	}
}

// FilterByDiff returns only annotations for findings that are in the diff.
func FilterByDiff(annotations []Annotation, diffs []FileDiff) []Annotation {
	diffFiles := make(map[string]bool)
	for _, d := range diffs {
		diffFiles[d.Path] = true
	}

	var filtered []Annotation
	for _, ann := range annotations {
		if diffFiles[ann.Path] {
			filtered = append(filtered, ann)
		}
	}
	return filtered
}

// SummaryByFile groups annotations by file path.
func SummaryByFile(annotations []Annotation) map[string][]Annotation {
	result := make(map[string][]Annotation)
	for _, ann := range annotations {
		result[ann.Path] = append(result[ann.Path], ann)
	}
	return result
}

// CountBySeverity counts annotations by severity level.
func CountBySeverity(annotations []Annotation) map[string]int {
	result := make(map[string]int)
	for _, ann := range annotations {
		result[ann.Severity]++
	}
	return result
}

// FormatFindingForComment creates a single-line comment for a finding.
func FormatFindingForComment(f analysis.Finding) string {
	severity := strings.ToUpper(string(f.Severity))
	if f.PackageName != "" {
		return fmt.Sprintf("[%s] %s — %s@%s", severity, f.Title, f.PackageName, f.PackageVersion)
	}
	if f.FilePath != "" {
		return fmt.Sprintf("[%s] %s — %s:%d", severity, f.Title, f.FilePath, f.LineStart)
	}
	return fmt.Sprintf("[%s] %s", severity, f.Title)
}
