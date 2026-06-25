// Package sast runs static analysis security tools on the repository.
// It uses embedded scanners (Go SAST, secret scanner, multi-language pattern
// scanner) that require no external installation, and supplements them with
// external tools (gosec, bandit, semgrep, gitleaks) when available.
//
// The embedded scanners run first and always provide baseline coverage.
// External tools run second and add deeper analysis when installed.
package sast

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/patchflow/patchflow-cli/internal/analysis"
	"github.com/patchflow/patchflow-cli/internal/sast/gosast"
	"github.com/patchflow/patchflow-cli/internal/sast/patterns"
	"github.com/patchflow/patchflow-cli/internal/sast/secrets"
	"github.com/patchflow/patchflow-cli/internal/sast/suppression"
)

// Tool represents an external SAST tool that can be invoked via subprocess.
type Tool struct {
	Name        string
	Binary      string
	Language    string // primary language (go, python, multi, secrets)
	IsAvailable func() bool
	Run         func(ctx context.Context, root string) ([]analysis.Finding, error)
}

// Runner manages embedded scanners and external SAST tools.
type Runner struct {
	// Embedded scanners (always available, no installation required)
	gosastAnalyzer *gosast.Analyzer
	secretScanner  *secrets.Scanner
	patternScanner *patterns.Scanner

	// Suppression manager for //patchflow:ignore directives
	suppressionMgr *suppression.Manager

	// External tools (optional, supplement embedded scanners)
	Tools        []Tool
	ChangedOnly  bool
	ChangedFiles []string
	Timeout      time.Duration

	// Flags to control which scanners run
	NoEmbeddedGo      bool
	NoEmbeddedSecrets bool
	NoEmbeddedPatterns bool

	// ShowSuppressed controls whether suppressed findings are included in output
	ShowSuppressed bool
}

// NewRunner creates a SAST runner with embedded scanners and external tools.
func NewRunner() *Runner {
	r := &Runner{
		Timeout:          120 * time.Second,
		gosastAnalyzer:   gosast.NewAnalyzer(),
		secretScanner:    secrets.NewScanner(),
		patternScanner:   patterns.NewScanner(),
		suppressionMgr:   suppression.NewManager(),
	}

	r.Tools = []Tool{
		{
			Name:        "gosec",
			Binary:      "gosec",
			Language:    "go",
			IsAvailable: func() bool { return commandExists("gosec") },
			Run:         runGosec,
		},
		{
			Name:        "bandit",
			Binary:      "bandit",
			Language:    "python",
			IsAvailable: func() bool { return commandExists("bandit") },
			Run:         runBandit,
		},
		{
			Name:        "semgrep",
			Binary:      "semgrep",
			Language:    "multi",
			IsAvailable: func() bool { return commandExists("semgrep") },
			Run:         runSemgrep,
		},
		{
			Name:        "gitleaks",
			Binary:      "gitleaks",
			Language:    "secrets",
			IsAvailable: func() bool { return commandExists("gitleaks") },
			Run:         runGitleaks,
		},
	}

	return r
}

// AvailableTools returns the names of external tools that are installed and ready to run.
func (r *Runner) AvailableTools() []string {
	var available []string
	for _, t := range r.Tools {
		if t.IsAvailable() {
			available = append(available, t.Name)
		}
	}
	return available
}

// EmbeddedTools returns the names of embedded scanners that are always available.
func (r *Runner) EmbeddedTools() []string {
	return []string{"gosast-embedded", "secrets-embedded", "patterns-embedded"}
}

// Result is the output of a SAST analysis run.
type Result struct {
	Findings        []analysis.Finding `json:"findings"`
	ToolsRun        []string           `json:"tools_run"`
	ToolsSkipped    []string           `json:"tools_skipped"`
	Errors          []string           `json:"errors,omitempty"`
	SuppressedCount int                `json:"suppressed_count,omitempty"`
}

// Analyze runs all embedded scanners first, then external tools as supplements.
func (r *Runner) Analyze(ctx context.Context, root string) (*Result, error) {
	result := &Result{}

	// --- Phase 1: Embedded scanners (always run) ---

	// 1a. Embedded Go SAST (gosec rules ported to library)
	if !r.NoEmbeddedGo {
		toolCtx, cancel := context.WithTimeout(ctx, r.Timeout)
		findings, err := r.gosastAnalyzer.Analyze(toolCtx, root)
		cancel()
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("gosast-embedded: %v", err))
		} else {
			if r.ChangedOnly && len(r.ChangedFiles) > 0 {
				findings = filterFindingsToChanged(findings, r.ChangedFiles)
			}
			result.Findings = append(result.Findings, findings...)
			result.ToolsRun = append(result.ToolsRun, "gosast-embedded")
		}
	}

	// 1b. Embedded secret scanner
	if !r.NoEmbeddedSecrets {
		toolCtx, cancel := context.WithTimeout(ctx, r.Timeout)
		findings, err := r.secretScanner.Analyze(toolCtx, root)
		cancel()
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("secrets-embedded: %v", err))
		} else {
			if r.ChangedOnly && len(r.ChangedFiles) > 0 {
				findings = filterFindingsToChanged(findings, r.ChangedFiles)
			}
			result.Findings = append(result.Findings, findings...)
			result.ToolsRun = append(result.ToolsRun, "secrets-embedded")
		}
	}

	// 1c. Embedded multi-language pattern scanner
	if !r.NoEmbeddedPatterns {
		toolCtx, cancel := context.WithTimeout(ctx, r.Timeout)
		findings, err := r.patternScanner.Analyze(toolCtx, root)
		cancel()
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("patterns-embedded: %v", err))
		} else {
			if r.ChangedOnly && len(r.ChangedFiles) > 0 {
				findings = filterFindingsToChanged(findings, r.ChangedFiles)
			}
			result.Findings = append(result.Findings, findings...)
			result.ToolsRun = append(result.ToolsRun, "patterns-embedded")
		}
	}

	// --- Phase 2: External tools (supplement embedded scanners) ---

	for _, tool := range r.Tools {
		if !tool.IsAvailable() {
			result.ToolsSkipped = append(result.ToolsSkipped, tool.Name)
			continue
		}

		toolCtx, cancel := context.WithTimeout(ctx, r.Timeout)
		findings, err := tool.Run(toolCtx, root)
		cancel()

		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", tool.Name, err))
			result.ToolsSkipped = append(result.ToolsSkipped, tool.Name)
			continue
		}

		// Filter to changed files if requested
		if r.ChangedOnly && len(r.ChangedFiles) > 0 {
			findings = filterFindingsToChanged(findings, r.ChangedFiles)
		}

		result.Findings = append(result.Findings, findings...)
		result.ToolsRun = append(result.ToolsRun, tool.Name)
	}

	// --- Phase 3: Apply suppression directives (//patchflow:ignore) ---
	if !r.ShowSuppressed {
		var filtered []analysis.Finding
		suppressedCount := 0
		for _, f := range result.Findings {
			if r.suppressionMgr.IsSuppressed(f.FilePath, f.LineStart, f.RuleID) {
				suppressedCount++
				continue
			}
			filtered = append(filtered, f)
		}
		if suppressedCount > 0 {
			result.SuppressedCount = suppressedCount
		}
		result.Findings = filtered
	}

	return result, nil
}

func filterFindingsToChanged(findings []analysis.Finding, changedFiles []string) []analysis.Finding {
	changedSet := make(map[string]bool, len(changedFiles))
	for _, f := range changedFiles {
		changedSet[f] = true
	}

	var filtered []analysis.Finding
	for _, f := range findings {
		// Normalize paths for comparison
		normalized := filepath.ToSlash(f.FilePath)
		normalized = strings.TrimPrefix(normalized, "./")
		if changedSet[normalized] {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// commandExists checks if a binary is available on the PATH.
func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// parseIntSafe converts a string to an int, returning 0 on failure.
// gosec outputs line numbers as strings in its JSON format.
func parseIntSafe(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}

// --- gosec ---

type gosecReport struct {
	Issues []gosecIssue `json:"Issues"`
	Rules  map[string]gosecRule `json:"Rules"`
}

type gosecIssue struct {
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	RuleID     string `json:"rule_id"`
	Details    string `json:"details"`
	File       string `json:"file"`
	Line       string `json:"line"`
	Col        string `json:"column"`
	What       string `json:"what"`
	Code       string `json:"code"`
}

type gosecRule struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

func runGosec(ctx context.Context, root string) ([]analysis.Finding, error) {
	cmd := exec.CommandContext(ctx, "gosec", "-fmt=json", "-quiet", "./...")
	cmd.Dir = root
	output, err := cmd.Output()
	if err != nil {
		// gosec returns non-zero exit code when issues are found
		if len(output) > 0 {
			// parse the output anyway
		} else {
			return nil, fmt.Errorf("gosec execution failed: %w", err)
		}
	}

	var report gosecReport
	if err := json.Unmarshal(output, &report); err != nil {
		return nil, fmt.Errorf("failed to parse gosec output: %w", err)
	}

	var findings []analysis.Finding
	for _, issue := range report.Issues {
		rule, hasRule := report.Rules[issue.RuleID]
		title := issue.What
		desc := issue.Details
		if hasRule {
			if title == "" {
				title = rule.Title
			}
			if desc == "" {
				desc = rule.Description
			}
		}
		// Fall back to details or rule_id if title is still empty
		if title == "" {
			title = desc
		}
		if title == "" {
			title = issue.RuleID
		}

		lineNum := parseIntSafe(issue.Line)

		findings = append(findings, analysis.Finding{
			ID:          fmt.Sprintf("sast-gosec-%s-%s-%d", issue.RuleID, filepath.Base(issue.File), lineNum),
			Type:        analysis.TypeSAST,
			Analyzer:    "gosec",
			Severity:    normalizeGosecSeverity(issue.Severity),
			Confidence:  normalizeGosecConfidence(issue.Confidence),
			Title:       title,
			Description: desc,
			FilePath:    issue.File,
			LineStart:   lineNum,
			RuleID:      issue.RuleID,
			Evidence:    issue.Code,
			DetectedAt:  time.Now(),
		})
	}

	return findings, nil
}

func normalizeGosecSeverity(s string) analysis.Severity {
	switch strings.ToUpper(s) {
	case "HIGH":
		return analysis.SeverityHigh
	case "MEDIUM":
		return analysis.SeverityMedium
	case "LOW":
		return analysis.SeverityLow
	default:
		return analysis.SeverityInfo
	}
}

func normalizeGosecConfidence(s string) analysis.Confidence {
	switch strings.ToUpper(s) {
	case "HIGH":
		return analysis.ConfidenceHigh
	case "MEDIUM":
		return analysis.ConfidenceMedium
	case "LOW":
		return analysis.ConfidenceLow
	default:
		return analysis.ConfidenceLow
	}
}

// --- bandit ---

type banditReport struct {
	Results []banditResult `json:"results"`
	Errors  []interface{}  `json:"errors"`
}

type banditResult struct {
	TestID     string `json:"test_id"`
	TestName   string `json:"test_name"`
	IssueSeverity string `json:"issue_severity"`
	IssueConfidence string `json:"issue_confidence"`
	IssueText  string `json:"issue_text"`
	Filename   string `json:"filename"`
	LineNumber int    `json:"line_number"`
	ColNumber  int    `json:"col_number"`
	MoreInfo   string `json:"more_info"`
	Code       string `json:"issue_cwe"`
}

func runBandit(ctx context.Context, root string) ([]analysis.Finding, error) {
	// Find Python files to scan
	cmd := exec.CommandContext(ctx, "bandit", "-r", ".", "-f", "json", "-q")
	cmd.Dir = root
	output, err := cmd.Output()
	if err != nil {
		if len(output) > 0 {
			// bandit returns non-zero when issues found
		} else {
			return nil, fmt.Errorf("bandit execution failed: %w", err)
		}
	}

	var report banditReport
	if err := json.Unmarshal(output, &report); err != nil {
		return nil, fmt.Errorf("failed to parse bandit output: %w", err)
	}

	var findings []analysis.Finding
	for _, r := range report.Results {
		findings = append(findings, analysis.Finding{
			ID:          fmt.Sprintf("sast-bandit-%s-%s-%d", r.TestID, filepath.Base(r.Filename), r.LineNumber),
			Type:        analysis.TypeSAST,
			Analyzer:    "bandit",
			Severity:    normalizeBanditSeverity(r.IssueSeverity),
			Confidence:  normalizeBanditConfidence(r.IssueConfidence),
			Title:       r.TestName,
			Description: r.IssueText,
			FilePath:    r.Filename,
			LineStart:   r.LineNumber,
			RuleID:      r.TestID,
			AdvisoryURL: r.MoreInfo,
			DetectedAt:  time.Now(),
		})
	}

	return findings, nil
}

func normalizeBanditSeverity(s string) analysis.Severity {
	switch strings.ToUpper(s) {
	case "HIGH":
		return analysis.SeverityHigh
	case "MEDIUM":
		return analysis.SeverityMedium
	case "LOW":
		return analysis.SeverityLow
	default:
		return analysis.SeverityInfo
	}
}

func normalizeBanditConfidence(s string) analysis.Confidence {
	switch strings.ToUpper(s) {
	case "HIGH":
		return analysis.ConfidenceHigh
	case "MEDIUM":
		return analysis.ConfidenceMedium
	case "LOW":
		return analysis.ConfidenceLow
	default:
		return analysis.ConfidenceLow
	}
}

// --- semgrep ---

type semgrepReport struct {
	Results []semgrepResult `json:"results"`
	Errors  []interface{}   `json:"errors"`
}

type semgrepResult struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   semgrepPosition `json:"start"`
	End     semgrepPosition `json:"end"`
	Extra   semgrepExtra `json:"extra"`
}

type semgrepPosition struct {
	Line   int `json:"line"`
	Col    int `json:"col"`
	Offset int `json:"offset"`
}

type semgrepExtra struct {
	Message  string `json:"message"`
	Severity string `json:"severity"`
	Lines    string `json:"lines"`
	Metadata map[string]interface{} `json:"metadata"`
}

func runSemgrep(ctx context.Context, root string) ([]analysis.Finding, error) {
	cmd := exec.CommandContext(ctx, "semgrep", "--json", "--quiet", root)
	cmd.Dir = root
	output, err := cmd.Output()
	if err != nil {
		if len(output) > 0 {
			// semgrep returns non-zero when findings exist
		} else {
			return nil, fmt.Errorf("semgrep execution failed: %w", err)
		}
	}

	var report semgrepReport
	if err := json.Unmarshal(output, &report); err != nil {
		return nil, fmt.Errorf("failed to parse semgrep output: %w", err)
	}

	var findings []analysis.Finding
	for _, r := range report.Results {
		severity := analysis.SeverityInfo
		if s, ok := r.Extra.Metadata["severity"]; ok {
			if sv, ok := s.(string); ok {
				severity = normalizeSemgrepSeverity(sv)
			}
		}
		if severity == analysis.SeverityInfo && r.Extra.Severity != "" {
			severity = normalizeSemgrepSeverity(r.Extra.Severity)
		}

		cwe := ""
		if c, ok := r.Extra.Metadata["cwe"]; ok {
			if cv, ok := c.(string); ok {
				cwe = cv
			}
		}

		advisory := ""
		if ref, ok := r.Extra.Metadata["references"]; ok {
			if refs, ok := ref.([]interface{}); ok && len(refs) > 0 {
				if refStr, ok := refs[0].(string); ok {
					advisory = refStr
				}
			}
		}

		findings = append(findings, analysis.Finding{
			ID:          fmt.Sprintf("sast-semgrep-%s-%s-%d", r.CheckID, filepath.Base(r.Path), r.Start.Line),
			Type:        analysis.TypeSAST,
			Analyzer:    "semgrep",
			Severity:    severity,
			Confidence:  analysis.ConfidenceMedium,
			Title:       r.CheckID,
			Description: r.Extra.Message,
			FilePath:    r.Path,
			LineStart:   r.Start.Line,
			LineEnd:     r.End.Line,
			RuleID:      r.CheckID,
			CWEID:       cwe,
			AdvisoryURL: advisory,
			Evidence:    r.Extra.Lines,
			DetectedAt:  time.Now(),
		})
	}

	return findings, nil
}

func normalizeSemgrepSeverity(s string) analysis.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "ERROR", "HIGH", "CRITICAL":
		if strings.ToUpper(s) == "CRITICAL" {
			return analysis.SeverityCritical
		}
		return analysis.SeverityHigh
	case "WARNING", "MEDIUM":
		return analysis.SeverityMedium
	case "INFO", "LOW":
		return analysis.SeverityLow
	default:
		return analysis.SeverityInfo
	}
}

// --- gitleaks ---

type gitleaksReport []gitleaksFinding

type gitleaksFinding struct {
	Description string `json:"Description"`
	RuleID      string `json:"RuleID"`
	RuleName    string `json:"RuleName"`
	Secret      string `json:"Secret"`
	File        string `json:"File"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
	StartColumn int    `json:"StartColumn"`
	EndColumn   int    `json:"EndColumn"`
	Match       string `json:"Match"`
}

func runGitleaks(ctx context.Context, root string) ([]analysis.Finding, error) {
	// gitleaks detect --source . --report-format json --report-path -
	cmd := exec.CommandContext(ctx, "gitleaks", "detect", "--source", root, "--report-format", "json", "--report-path", "-", "--no-banner")
	cmd.Dir = root
	output, err := cmd.Output()
	if err != nil {
		if len(output) > 0 {
			// gitleaks returns non-zero when secrets are found
		} else {
			return nil, fmt.Errorf("gitleaks execution failed: %w", err)
		}
	}

	var report gitleaksReport
	if err := json.Unmarshal(output, &report); err != nil {
		return nil, fmt.Errorf("failed to parse gitleaks output: %w", err)
	}

	var findings []analysis.Finding
	for _, f := range report {
		// Mask the secret value — never expose it in findings
		maskedSecret := maskSecret(f.Secret)
		title := f.RuleName
		if title == "" {
			title = f.Description
		}
		if title == "" {
			title = f.RuleID
		}

		findings = append(findings, analysis.Finding{
			ID:          fmt.Sprintf("secret-gitleaks-%s-%s-%d", f.RuleID, filepath.Base(f.File), f.StartLine),
			Type:        analysis.TypeSecret,
			Analyzer:    "gitleaks",
			Severity:    analysis.SeverityHigh, // secrets are always high severity
			Confidence:  analysis.ConfidenceHigh,
			Title:       fmt.Sprintf("Secret detected: %s", title),
			Description: fmt.Sprintf("Potential secret matching rule %s detected. Value masked: %s", f.RuleID, maskedSecret),
			FilePath:    f.File,
			LineStart:   f.StartLine,
			LineEnd:     f.EndLine,
			RuleID:      f.RuleID,
			Evidence:    maskSecret(f.Match),
			Recommendation: "Remove the secret from the code, rotate it immediately, and use environment variables or a secrets manager.",
			DetectedAt:  time.Now(),
		})
	}

	return findings, nil
}

// maskSecret masks a secret value, showing only the first and last 2 characters.
func maskSecret(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 4 {
		return strings.Repeat("*", len(s))
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}

// PlatformBinaryName returns the platform-specific binary name for a tool.
func PlatformBinaryName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}
