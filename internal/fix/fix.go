// Package fix provides safe fix proposal generation and application for
// security findings detected by PatchFlow. It generates code patches for
// common vulnerability patterns, supports dry-run preview, and applies
// fixes with user confirmation.
package fix

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
)

// FixProposal represents a proposed fix for a security finding.
type FixProposal struct {
	ID            string          `json:"id"`
	FindingID     string          `json:"finding_id"`
	RuleID        string          `json:"rule_id"`
	Title         string          `json:"title"`
	Description   string          `json:"description"`
	Severity      string          `json:"severity"`
	FilePath      string          `json:"file_path"`
	LineStart     int             `json:"line_start"`
	LineEnd       int             `json:"line_end"`
	OriginalCode  string          `json:"original_code"`
	FixedCode     string          `json:"fixed_code"`
	Patch         string          `json:"patch"`
	Confidence    FixConfidence   `json:"confidence"`
	Strategy      FixStrategy     `json:"strategy"`
	Rationale     string          `json:"rationale"`
	References    []string        `json:"references,omitempty"`
	AutoApplicable bool           `json:"auto_applicable"`
	PackageName   string          `json:"package_name,omitempty"`
	PackageVersion string         `json:"package_version,omitempty"`
	FixedVersion  string          `json:"fixed_version,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
}

// FixConfidence represents how confident we are that the fix is correct.
type FixConfidence string

const (
	FixConfidenceHigh   FixConfidence = "high"    // Deterministic transformation
	FixConfidenceMedium FixConfidence = "medium"  // Pattern-based, may need review
	FixConfidenceLow    FixConfidence = "low"     // Suggestion only, needs manual review
)

// FixStrategy describes the type of fix being applied.
type FixStrategy string

const (
	StrategyReplace       FixStrategy = "replace"        // Replace vulnerable code with safe alternative
	StrategyWrap          FixStrategy = "wrap"           // Wrap existing code with validation
	StrategyRemove        FixStrategy = "remove"         // Remove the vulnerable code
	StrategyUpgrade       FixStrategy = "upgrade"        // Upgrade dependency to fixed version
	StrategyConfigure     FixStrategy = "configure"      // Change configuration
	StrategyAddValidation FixStrategy = "add_validation" // Add input validation
)

// FixResult holds the result of a fix application.
type FixResult struct {
	ProposalID  string `json:"proposal_id"`
	Applied     bool   `json:"applied"`
	FilePath    string `json:"file_path"`
	BytesChanged int   `json:"bytes_changed"`
	LinesChanged int   `json:"lines_changed"`
	Error       string `json:"error,omitempty"`
	BackupPath  string `json:"backup_path,omitempty"`
}

// Engine generates fix proposals for security findings.
type Engine struct {
	templates []FixTemplate
}

// NewEngine creates a fix engine with all built-in fix templates loaded.
func NewEngine() *Engine {
	return &Engine{
		templates: builtinTemplates(),
	}
}

// FixTemplate defines a fix for a specific rule pattern.
type FixTemplate struct {
	RuleID      string
	Languages   []string
	Strategy    FixStrategy
	Confidence  FixConfidence
	Generate    func(finding analysis.Finding, source string) (*FixProposal, error)
	Description string
}

// Suggest generates fix proposals for a list of findings.
// Only findings that have a matching fix template will get a proposal.
func (e *Engine) Suggest(findings []analysis.Finding) []FixProposal {
	var proposals []FixProposal

	for _, finding := range findings {
		// SCA findings get upgrade suggestions
		if finding.Type == analysis.TypeSCA {
			if p := suggestSCAFix(finding); p != nil {
				proposals = append(proposals, *p)
			}
			continue
		}

		// SAST findings get code fixes
		if finding.Type == analysis.TypeSAST || finding.Type == analysis.TypeSecret {
			if p := e.suggestSASTFix(finding); p != nil {
				proposals = append(proposals, *p)
			}
		}
	}

	// Sort by severity (critical first)
	sort.Slice(proposals, func(i, j int) bool {
		return analysis.SeverityOrder(analysis.Severity(proposals[i].Severity)) >
			analysis.SeverityOrder(analysis.Severity(proposals[j].Severity))
	})

	return proposals
}

// SuggestForFinding generates a fix proposal for a single finding.
func (e *Engine) SuggestForFinding(finding analysis.Finding) (*FixProposal, error) {
	if finding.Type == analysis.TypeSCA {
		return suggestSCAFix(finding), nil
	}

	// Read the source file
	if finding.FilePath == "" {
		return nil, fmt.Errorf("finding has no file path")
	}

	source, err := os.ReadFile(finding.FilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", finding.FilePath, err)
	}

	// Find matching template
	for _, tmpl := range e.templates {
		if tmpl.RuleID == finding.RuleID {
			return tmpl.Generate(finding, string(source))
		}
	}

	// Try generic fix based on rule ID prefix
	return e.suggestGenericFix(finding, string(source))
}

// suggestSASTFix generates a fix for a SAST finding by reading the source
// and applying the matching template.
func (e *Engine) suggestSASTFix(finding analysis.Finding) *FixProposal {
	if finding.FilePath == "" || finding.LineStart == 0 {
		return nil
	}

	source, err := os.ReadFile(finding.FilePath)
	if err != nil {
		return nil
	}

	// Find matching template
	for _, tmpl := range e.templates {
		if tmpl.RuleID == finding.RuleID {
			proposal, err := tmpl.Generate(finding, string(source))
			if err == nil {
				return proposal
			}
		}
	}

	// Try generic fix
	proposal, err := e.suggestGenericFix(finding, string(source))
	if err == nil {
		return proposal
	}

	return nil
}

// suggestGenericFix attempts a generic fix based on the rule ID pattern.
func (e *Engine) suggestGenericFix(finding analysis.Finding, source string) (*FixProposal, error) {
	ruleID := finding.RuleID

	// Group by rule prefix for common patterns
	switch {
	case strings.Contains(ruleID, "eval") || strings.Contains(strings.ToLower(finding.Title), "eval"):
		return fixEval(finding, source)
	case strings.Contains(ruleID, "exec") && strings.Contains(ruleID, "JS"):
		return fixChildProcessExec(finding, source)
	case strings.Contains(ruleID, "shell=True") || strings.Contains(strings.ToLower(finding.Title), "shell=true"):
		return fixSubprocessShellTrue(finding, source)
	case strings.Contains(ruleID, "InsecureSkipVerify") || strings.Contains(strings.ToLower(finding.Title), "insecureskipverify"):
		return fixInsecureSkipVerify(finding, source)
	case strings.Contains(ruleID, "md5") || strings.Contains(strings.ToLower(finding.Title), "md5"):
		return fixMD5(finding, source)
	case strings.Contains(ruleID, "sha1") || strings.Contains(strings.ToLower(finding.Title), "sha1"):
		return fixSHA1(finding, source)
	case strings.Contains(strings.ToLower(finding.Title), "sql"):
		return fixSQLInjection(finding, source)
	case strings.Contains(strings.ToLower(finding.Title), "hardcoded") && (strings.Contains(strings.ToLower(finding.Title), "password") || strings.Contains(strings.ToLower(finding.Title), "api key")):
		return fixHardcodedSecret(finding, source)
	case strings.Contains(strings.ToLower(finding.Title), "debug") && strings.Contains(strings.ToLower(finding.Title), "true"):
		return fixDebugTrue(finding, source)
	}

	return nil, fmt.Errorf("no fix template for rule %s", ruleID)
}

// suggestSCAFix generates an upgrade suggestion for a vulnerable dependency.
func suggestSCAFix(finding analysis.Finding) *FixProposal {
	if finding.FixedVersion == "" {
		return &FixProposal{
			ID:             fmt.Sprintf("fix-sca-%s", finding.ID),
			FindingID:      finding.ID,
			RuleID:         finding.RuleID,
			Title:          fmt.Sprintf("Upgrade %s to a fixed version", finding.PackageName),
			Description:    fmt.Sprintf("%s@%s is vulnerable to %s. No fixed version is available yet.", finding.PackageName, finding.PackageVersion, finding.CVEID),
			Severity:       string(finding.Severity),
			FilePath:       finding.FilePath,
			PackageName:    finding.PackageName,
			PackageVersion: finding.PackageVersion,
			Strategy:       StrategyUpgrade,
			Confidence:     FixConfidenceLow,
			Rationale:      "No fixed version is available. Consider replacing this dependency or applying a workaround.",
			References:     []string{finding.AdvisoryURL},
			AutoApplicable: false,
			CreatedAt:      time.Now().UTC(),
		}
	}

	return &FixProposal{
		ID:             fmt.Sprintf("fix-sca-%s", finding.ID),
		FindingID:      finding.ID,
		RuleID:         finding.RuleID,
		Title:          fmt.Sprintf("Upgrade %s from %s to %s", finding.PackageName, finding.PackageVersion, finding.FixedVersion),
		Description:    fmt.Sprintf("%s@%s is vulnerable to %s. Upgrade to %s or later.", finding.PackageName, finding.PackageVersion, finding.CVEID, finding.FixedVersion),
		Severity:       string(finding.Severity),
		FilePath:       finding.FilePath,
		PackageName:    finding.PackageName,
		PackageVersion: finding.PackageVersion,
		FixedVersion:   finding.FixedVersion,
		Strategy:       StrategyUpgrade,
		Confidence:     FixConfidenceHigh,
		Rationale:      fmt.Sprintf("Upgrading %s to version %s or later resolves this vulnerability.", finding.PackageName, finding.FixedVersion),
		References:     []string{finding.AdvisoryURL},
		AutoApplicable:  true,
		CreatedAt:      time.Now().UTC(),
	}
}

// extractLine reads a specific line from source code.
func extractLine(source string, lineNum int) string {
	lines := strings.Split(source, "\n")
	if lineNum > 0 && lineNum <= len(lines) {
		return lines[lineNum-1]
	}
	return ""
}

// extractLines reads a range of lines from source code.
func extractLines(source string, start, end int) string {
	lines := strings.Split(source, "\n")
	if start < 1 {
		start = 1
	}
	if end > len(lines) {
		end = len(lines)
	}
	if start > len(lines) {
		return ""
	}
	return strings.Join(lines[start-1:end], "\n")
}

// replaceLine replaces a specific line in the source code.
func replaceLine(source string, lineNum int, newLine string) string {
	lines := strings.Split(source, "\n")
	if lineNum > 0 && lineNum <= len(lines) {
		lines[lineNum-1] = newLine
	}
	return strings.Join(lines, "\n")
}

// replaceLines replaces a range of lines in the source code.
func replaceLines(source string, start, end int, newLines string) string {
	lines := strings.Split(source, "\n")
	if start < 1 {
		start = 1
	}
	if end > len(lines) {
		end = len(lines)
	}
	if start > len(lines) {
		return source
	}

	newLineSlice := strings.Split(newLines, "\n")
	result := make([]string, 0, len(lines)-end+start+len(newLineSlice))
	result = append(result, lines[:start-1]...)
	result = append(result, newLineSlice...)
	result = append(result, lines[end:]...)

	return strings.Join(result, "\n")
}

// generateUnifiedDiff creates a unified diff between original and fixed code.
func generateUnifiedDiff(filePath, original, fixed string) string {
	var diff strings.Builder

	origLines := strings.Split(original, "\n")
	fixedLines := strings.Split(fixed, "\n")

	diff.WriteString(fmt.Sprintf("--- a/%s\n", filePath))
	diff.WriteString(fmt.Sprintf("+++ b/%s\n", filePath))

	// Simple line-by-line diff
	maxLines := len(origLines)
	if len(fixedLines) > maxLines {
		maxLines = len(fixedLines)
	}

	// Find the first differing line
	startLine := 0
	for i := 0; i < maxLines; i++ {
		var origLine, fixedLine string
		if i < len(origLines) {
			origLine = origLines[i]
		}
		if i < len(fixedLines) {
			fixedLine = fixedLines[i]
		}
		if origLine != fixedLine {
			startLine = i
			break
		}
	}

	// Find the last differing line
	endOrig := len(origLines)
	endFixed := len(fixedLines)
	for i := maxLines - 1; i >= startLine; i-- {
		var origLine, fixedLine string
		if i < len(origLines) {
			origLine = origLines[i]
		}
		if i < len(fixedLines) {
			fixedLine = fixedLines[i]
		}
		if origLine != fixedLine {
			endOrig = i + 1
			endFixed = i + 1
			break
		}
	}

	// Write hunk header
	diff.WriteString(fmt.Sprintf("@@ -%d,%d +%d,%d @@\n",
		startLine+1, endOrig-startLine,
		startLine+1, endFixed-startLine))

	// Write context (2 lines before)
	ctxStart := startLine - 2
	if ctxStart < 0 {
		ctxStart = 0
	}
	for i := ctxStart; i < startLine; i++ {
		if i < len(origLines) {
			diff.WriteString(" " + origLines[i] + "\n")
		}
	}

	// Write removed lines
	for i := startLine; i < endOrig; i++ {
		if i < len(origLines) {
			diff.WriteString("-" + origLines[i] + "\n")
		}
	}

	// Write added lines
	for i := startLine; i < endFixed; i++ {
		if i < len(fixedLines) {
			diff.WriteString("+" + fixedLines[i] + "\n")
		}
	}

	// Write context (2 lines after)
	ctxEnd := endOrig + 2
	if ctxEnd > len(origLines) {
		ctxEnd = len(origLines)
	}
	for i := endOrig; i < ctxEnd; i++ {
		if i < len(origLines) {
			diff.WriteString(" " + origLines[i] + "\n")
		}
	}

	return diff.String()
}

// detectLanguage determines the programming language from a file path.
func detectLanguage(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".py":
		return "python"
	case ".js", ".jsx", ".mjs":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	case ".go":
		return "go"
	case ".rb":
		return "ruby"
	case ".php":
		return "php"
	case ".java":
		return "java"
	default:
		return ""
	}
}

// goFormatFile attempts to format Go source code using go/format.
func goFormatFile(src string) string {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "patch.go", src, parser.ParseComments)
	if err != nil {
		return src // Return unformatted if parse fails
	}

	var buf strings.Builder
	if err := printer.Fprint(&buf, fset, file); err != nil {
		return src
	}
	return buf.String()
}

// goASTReplaceEval finds and replaces eval() calls in Go AST.
// This is a placeholder for more sophisticated AST-based fixes.
func goASTReplaceEval(src string) (string, bool) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "patch.go", src, parser.ParseComments)
	if err != nil {
		return src, false
	}

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		if ident.Name == "eval" {
			// Mark for replacement — actual AST manipulation is complex
			ident.Name = "safeEval"
		}
		return true
	})

	var buf strings.Builder
	if err := printer.Fprint(&buf, fset, file); err != nil {
		return src, false
	}
	return buf.String(), true
}

// Add fields needed for SCA fixes
var _ = regexp.MustCompile // ensure regexp is used
