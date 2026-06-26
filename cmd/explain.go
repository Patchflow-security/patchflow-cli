package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/patchflow/patchflow-cli/internal/analysis"
	"github.com/patchflow/patchflow-cli/internal/baseline"
	"github.com/patchflow/patchflow-cli/internal/exitcode"
	"github.com/patchflow/patchflow-cli/internal/git"
	"github.com/patchflow/patchflow-cli/internal/output"
	"github.com/patchflow/patchflow-cli/internal/sast"
	"github.com/spf13/cobra"
)

var explainCmd = &cobra.Command{
	Use:   "explain [finding-id]",
	Short: "Explain a finding with evidence, fix hints, and suppression info",
	Long: `Explain a security finding in detail.

Shows:
  - What the issue is and why it's dangerous
  - Where the evidence is (file, line, code snippet)
  - How to fix it (with example code)
  - How to suppress it if it's a false positive
  - Whether it would block a PR (--fail-on)

The finding ID can be obtained from ` + "`patchflow scan run`" + ` output.
You can also use --file and --line to explain a finding at a specific location.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runExplain,
}

var (
	explainFile   string
	explainLine   int
	explainRuleID string
)

func init() {
	explainCmd.Flags().StringVar(&explainFile, "file", "", "Explain finding at this file path")
	explainCmd.Flags().IntVar(&explainLine, "line", 0, "Line number (use with --file)")
	explainCmd.Flags().StringVar(&explainRuleID, "rule", "", "Rule ID to explain (e.g., PY001, TS-JS004)")
	rootCmd.AddCommand(explainCmd)
}

func runExplain(cmd *cobra.Command, args []string) error {
	formatter := FormatterFromContext(cmd.Context())

	repo, _, err := git.DetectOrLocal()
	if err != nil {
		return formatter.PrintError(fmt.Errorf("failed to detect repository: %w", err))
	}

	// Mode 1: Explain by finding ID (from a previous scan)
	if len(args) == 1 {
		return explainByFindingID(formatter, repo.Root, args[0])
	}

	// Mode 2: Explain by file+line
	if explainFile != "" && explainLine > 0 {
		return explainByLocation(formatter, repo.Root, explainFile, explainLine, explainRuleID)
	}

	// Mode 3: Explain by rule ID only (show rule documentation)
	if explainRuleID != "" {
		return explainByRuleID(formatter, repo.Root, explainRuleID)
	}

	return formatter.PrintError(fmt.Errorf("provide a finding ID, or use --file and --line, or --rule"))
}

// explainByFindingID runs a scan and finds the matching finding by ID.
func explainByFindingID(formatter output.Formatter, root, findingID string) error {
	if !output.IsJSON(formatter) {
		_ = formatter.Print("Running scan to locate finding " + findingID + "...")
	}

	findings, _, err := runExplainScan(root)
	if err != nil {
		return formatter.PrintError(fmt.Errorf("scan failed: %w", err))
	}

	// Find the matching finding
	var target *analysis.Finding
	for i := range findings {
		if findings[i].ID == findingID || findings[i].RuleID == findingID {
			target = &findings[i]
			break
		}
	}

	if target == nil {
		return formatter.PrintError(fmt.Errorf("finding %q not found. Run 'patchflow scan run' to see current findings.", findingID))
	}

	return outputFindingExplanation(formatter, root, target)
}

// explainByLocation runs a scan and finds findings at the given file+line.
func explainByLocation(formatter output.Formatter, root, file string, line int, ruleID string) error {
	findings, _, err := runExplainScan(root)
	if err != nil {
		return formatter.PrintError(fmt.Errorf("scan failed: %w", err))
	}

	// Normalize the file path for comparison
	normalizedFile := filepath.ToSlash(strings.TrimPrefix(file, "./"))

	var matches []*analysis.Finding
	for i := range findings {
		fFile := filepath.ToSlash(strings.TrimPrefix(findings[i].FilePath, "./"))
		if strings.HasSuffix(fFile, normalizedFile) || fFile == normalizedFile {
			if line == 0 || findings[i].LineStart == line {
				if ruleID == "" || findings[i].RuleID == ruleID {
					matches = append(matches, &findings[i])
				}
			}
		}
	}

	if len(matches) == 0 {
		return formatter.PrintError(fmt.Errorf("no findings at %s:%d", file, line))
	}

	for _, m := range matches {
		if err := outputFindingExplanation(formatter, root, m); err != nil {
			return err
		}
	}
	return nil
}

// explainByRuleID shows rule documentation without running a scan.
func explainByRuleID(formatter output.Formatter, root, ruleID string) error {
	runner := sast.NewRunner()
	runner.RespectGitignore = true

	groups := runner.AllRules()
	for _, g := range groups {
		for _, r := range g.Rules {
			if r.ID == ruleID {
				if output.IsJSON(formatter) {
					return formatter.Print(map[string]interface{}{
						"rule_id":   r.ID,
						"title":     r.Title,
						"severity":  r.Severity,
						"scanner":   g.Scanner,
						"language":  g.Language,
						"fix_hint":  getFixHint(r.ID),
						"suppression": map[string]interface{}{
							"allowed": true,
							"format":  "// patchflow:ignore " + r.ID + " -- reason",
						},
					})
				}
				_ = formatter.Print("Rule: " + r.ID)
				_ = formatter.Print("  Title: " + r.Title)
				_ = formatter.Print("  Severity: " + r.Severity)
				_ = formatter.Print("  Scanner: " + g.Scanner)
				_ = formatter.Print("  Language: " + g.Language)
				if hint := getFixHint(r.ID); hint != "" {
					_ = formatter.Print("\n  Fix: " + hint)
				}
				_ = formatter.Print("\n  Suppress: // patchflow:ignore " + r.ID + " -- reason")
				return nil
			}
		}
	}

	return formatter.PrintError(fmt.Errorf("rule %q not found. Run 'patchflow rules list' to see available rules.", ruleID))
}

// runExplainScan runs a full SAST scan for the explain command.
func runExplainScan(root string) ([]analysis.Finding, string, error) {
	runner := sast.NewRunner()
	runner.RespectGitignore = true
	runner.Timeout = 120 * time.Second

	result, err := runner.Analyze(context.Background(), root)
	if err != nil {
		return nil, "", err
	}
	return result.Findings, "", nil
}

// outputFindingExplanation outputs a detailed finding explanation.
func outputFindingExplanation(formatter output.Formatter, root string, f *analysis.Finding) error {
	// Read the source code around the finding
	evidence := readEvidence(root, f.FilePath, f.LineStart)

	if output.IsJSON(formatter) {
		return formatter.Print(map[string]interface{}{
			"id":          f.ID,
			"rule_id":     f.RuleID,
			"title":       f.Title,
			"description": f.Description,
			"severity":    string(f.Severity),
			"confidence":  string(f.Confidence),
			"scanner":     f.Analyzer,
			"file":        f.FilePath,
			"line":        f.LineStart,
			"evidence":    evidence,
			"fix_hint":    getFixHint(f.RuleID),
			"suppression": map[string]interface{}{
				"allowed": true,
				"format":  "// patchflow:ignore " + f.RuleID + " -- reason",
			},
			"recommendation": f.Recommendation,
		})
	}

	// Terminal output
	_ = formatter.Print("")
	_ = formatter.Print(fmt.Sprintf("Finding: %s", f.ID))
	_ = formatter.Print(fmt.Sprintf("  Rule:      %s — %s", f.RuleID, f.Title))
	_ = formatter.Print(fmt.Sprintf("  Severity:  %s (confidence: %s)", f.Severity, f.Confidence))
	_ = formatter.Print(fmt.Sprintf("  Scanner:   %s", f.Analyzer))
	_ = formatter.Print(fmt.Sprintf("  Location:  %s:%d", f.FilePath, f.LineStart))
	if f.Description != "" {
		_ = formatter.Print("")
		_ = formatter.Print("  Description:")
		_ = formatter.Print("    " + f.Description)
	}
	if evidence != "" {
		_ = formatter.Print("")
		_ = formatter.Print("  Evidence:")
		for _, line := range strings.Split(evidence, "\n") {
			_ = formatter.Print("    " + line)
		}
	}
	if hint := getFixHint(f.RuleID); hint != "" {
		_ = formatter.Print("")
		_ = formatter.Print("  Fix:")
		_ = formatter.Print("    " + hint)
	}
	if f.Recommendation != "" {
		_ = formatter.Print("")
		_ = formatter.Print("  Recommendation:")
		_ = formatter.Print("    " + f.Recommendation)
	}
	_ = formatter.Print("")
	_ = formatter.Print("  Suppress:")
	_ = formatter.Print(fmt.Sprintf("    // patchflow:ignore %s -- false positive: <reason>", f.RuleID))
	_ = formatter.Print("")

	return nil
}

// readEvidence reads the source code around a finding location.
func readEvidence(root, filePath string, line int) string {
	absPath := filePath
	if !filepath.IsAbs(absPath) {
		absPath = filepath.Join(root, filePath)
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		return ""
	}

	lines := strings.Split(string(data), "\n")
	start := line - 2
	end := line + 2
	if start < 0 {
		start = 0
	}
	if end >= len(lines) {
		end = len(lines) - 1
	}

	var sb strings.Builder
	for i := start; i <= end; i++ {
		marker := "  "
		if i+1 == line {
			marker = "> "
		}
		if i < len(lines) {
			sb.WriteString(fmt.Sprintf("%s%d: %s\n", marker, i+1, lines[i]))
		}
	}
	return strings.TrimSuffix(sb.String(), "\n")
}

// getFixHint returns a fix hint for a given rule ID.
func getFixHint(ruleID string) string {
	hints := map[string]string{
		// Python
		"PY001":  "Use ast.literal_eval() instead of eval() for safe evaluation of literals.",
		"PY002":  "Use subprocess with shell=False and pass arguments as a list: subprocess.run(['cmd', 'arg1'], shell=False)",
		"PY003":  "Use subprocess.run() with a list of arguments instead of shell=True.",
		"PY005":  "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
		"PY006":  "Use os.path.join() and validate paths against a base directory.",
		"PY007":  "Use hashlib.sha256() or similar for password hashing instead of MD5/SHA1.",
		"PY008":  "Use secrets.token_urlsafe() or os.urandom() instead of random for security-sensitive values.",
		"PY010":  "Use pickle only with trusted data. Consider JSON for untrusted input.",
		"PY011":  "Use yaml.safe_load() instead of yaml.load().",
		"PY012":  "Use a verified XML parser with defusedxml to prevent XXE attacks.",
		"PY013":  "Use parameterized queries with the database driver's escape functions.",
		// JS/TS
		"JS001":  "Avoid eval(). If necessary, use Function() with strict mode or a sandbox.",
		"JS002":  "Use child_process.execFile() with argument arrays instead of exec() with shell strings.",
		"JS003":  "Use parameterized queries: db.query('SELECT * FROM users WHERE id = $1', [userId])",
		"JS004":  "Avoid dangerouslySetInnerHTML. Use DOMPurify to sanitize HTML before rendering.",
		"JS005":  "Use bcrypt or argon2 for password hashing instead of MD5/SHA1.",
		"JS006":  "Use crypto.randomBytes() instead of Math.random() for security-sensitive values.",
		"JS007":  "Set 'HttpOnly; Secure; SameSite=Strict' on cookie attributes.",
		// Go
		"G104":   "Check errors from all function calls, especially in security-critical paths.",
		"G107":   "Do not pass user input to http.Get URLs. Validate and restrict allowed hosts.",
		"G204":   "Use exec.Command with argument lists, never shell=True or user input in cmd string.",
		// Secrets
		"SECRET-AWS-Access-Key":          "Rotate the key immediately. Use IAM roles or environment variables instead.",
		"SECRET-AWS-Secret-Access-Key":   "Rotate the key immediately. Use IAM roles or environment variables instead.",
		"SECRET-GitHub-Token":            "Revoke the token. Use GitHub Actions secrets or OIDC instead.",
		"SECRET-Database-Connection-URL": "Use environment variables or a secrets manager. Never commit connection strings.",
		"SECRET-Private-Key":             "Rotate the key. Use a secrets manager or key management service.",
		// Taint patterns
		"TP-PY001": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
		"TP-PY002": "Use subprocess with shell=False and argument lists.",
		"TP-PY003": "Validate file paths with os.path.abspath() and check against a base directory.",
		"TP-PY004": "Validate URLs against an allowlist of permitted hosts.",
		"TP-PY005": "Avoid eval()/exec() with untrusted input. Use ast.literal_eval() for literals.",
		"TP-PY006": "Enable auto-escaping in templates. Use Jinja2's |e filter or markupsafe.escape().",
		"TP-JS001": "Use parameterized queries: db.query('SELECT * FROM users WHERE id = $1', [userId])",
		"TP-JS002": "Use execFile() with argument arrays instead of exec() with shell strings.",
		"TP-JS003": "Use proper output encoding. Avoid string concatenation in HTML responses.",
		"TP-JS004": "Use path.resolve() and validate against a base directory.",
		"TP-JS005": "Validate URLs against an allowlist of permitted hosts.",
		"TP-JS006": "Avoid eval() and new Function() with untrusted input.",
		"TP-JS007": "Validate redirect URLs against an allowlist. Reject absolute URLs from user input.",
	}
	return hints[ruleID]
}

// Ensure unused imports are referenced
var _ = exitcode.Success
var _ = baseline.NewManager
