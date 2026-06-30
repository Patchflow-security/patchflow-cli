package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/fix"
	"github.com/Patchflow-security/patchflow-cli/internal/git"
	"github.com/Patchflow-security/patchflow-cli/internal/output"
	"github.com/Patchflow-security/patchflow-cli/internal/sast"
	"github.com/spf13/cobra"
)

var (
	fixFindingID   string
	fixRuleID      string
	fixFile        string
	fixLine        int
	fixDryRun      bool
	fixBackup      bool
	fixYes         bool
	fixAll         bool
	fixAutoOnly    bool
	fixOutput      string
	fixSeverity    string
)

var fixCmd = &cobra.Command{
	Use:   "fix",
	Short: "Generate and apply safe fixes for security findings",
	Long: `Generate and apply safe fixes for security findings detected by PatchFlow.

The fix command can:
  1. Suggest fixes for findings (patchflow fix suggest)
  2. Apply fixes with dry-run preview and confirmation (patchflow fix apply)
  3. Show a specific fix proposal (patchflow fix show <id>)

Fixes are generated from built-in templates that target common vulnerability
patterns (eval, command injection, SQL injection, weak crypto, etc.).
Each fix includes a confidence score, rationale, and unified diff patch.

Safe by design:
  - Never applies without confirmation (unless --yes)
  - Always shows a preview before applying
  - Creates backups with --backup
  - Dry-run mode for CI pipelines`,
}

var fixSuggestCmd = &cobra.Command{
	Use:   "suggest",
	Short: "Generate fix proposals for current findings",
	Long: `Run a scan and generate fix proposals for all findings that have
matching fix templates. Outputs a summary with confidence levels and
auto-applicability flags.`,
	RunE: runFixSuggest,
}

var fixApplyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply fix proposals to source files",
	Long: `Apply fix proposals to source files. By default, shows a preview
and asks for confirmation before applying. Use --dry-run to preview
without applying, or --yes to skip confirmation (for CI).`,
	RunE: runFixApply,
}

var fixShowCmd = &cobra.Command{
	Use:   "show [finding-id]",
	Short: "Show the fix proposal for a specific finding",
	Long: `Show the fix proposal for a specific finding. Runs a scan to locate
the finding, then generates and displays the proposed fix with diff.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runFixShow,
}

func init() {
	fixSuggestCmd.Flags().StringVar(&fixSeverity, "severity", "", "Only suggest fixes for findings at or above this severity (low, medium, high, critical)")
	fixSuggestCmd.Flags().BoolVar(&fixAutoOnly, "auto-only", false, "Only show auto-applicable fixes")
	fixSuggestCmd.Flags().StringVar(&fixOutput, "output", "", "Write proposals to file (JSON format)")

	fixApplyCmd.Flags().StringVar(&fixFindingID, "finding", "", "Apply fix for a specific finding ID")
	fixApplyCmd.Flags().StringVar(&fixRuleID, "rule", "", "Apply fixes for a specific rule ID")
	fixApplyCmd.Flags().StringVar(&fixFile, "file", "", "Apply fixes in a specific file")
	fixApplyCmd.Flags().IntVar(&fixLine, "line", 0, "Apply fix at a specific line (use with --file)")
	fixApplyCmd.Flags().BoolVar(&fixDryRun, "dry-run", false, "Preview changes without applying")
	fixApplyCmd.Flags().BoolVar(&fixBackup, "backup", false, "Create backups before applying fixes")
	fixApplyCmd.Flags().BoolVar(&fixYes, "yes", false, "Skip confirmation prompt (for CI use)")
	fixApplyCmd.Flags().BoolVar(&fixAll, "all", false, "Apply all auto-applicable fixes")
	fixApplyCmd.Flags().StringVar(&fixSeverity, "severity", "", "Only apply fixes at or above this severity")

	fixShowCmd.Flags().StringVar(&fixFile, "file", "", "Show fix for finding at this file")
	fixShowCmd.Flags().IntVar(&fixLine, "line", 0, "Line number (use with --file)")
	fixShowCmd.Flags().StringVar(&fixRuleID, "rule", "", "Rule ID to show fix for")

	fixCmd.AddCommand(fixSuggestCmd)
	fixCmd.AddCommand(fixApplyCmd)
	fixCmd.AddCommand(fixShowCmd)
	rootCmd.AddCommand(fixCmd)
}

// runFixSuggest runs a scan and generates fix proposals.
func runFixSuggest(cmd *cobra.Command, _ []string) error {
	formatter := FormatterFromContext(cmd.Context())

	repo, _, err := git.DetectOrLocal()
	if err != nil {
		return formatter.PrintError(fmt.Errorf("failed to detect repository: %w", err))
	}

	if !output.IsJSON(formatter) {
		_ = formatter.Print("Scanning for findings...")
	}

	findings, err := runFixScan(repo.Root)
	if err != nil {
		return formatter.PrintError(fmt.Errorf("scan failed: %w", err))
	}

	// Filter by severity if requested
	if fixSeverity != "" {
		findings = filterFindingsBySeverity(findings, fixSeverity)
	}

	engine := fix.NewEngine()
	proposals := engine.Suggest(findings)

	// Filter to auto-applicable only if requested
	if fixAutoOnly {
		var filtered []fix.FixProposal
		for _, p := range proposals {
			if p.AutoApplicable {
				filtered = append(filtered, p)
			}
		}
		proposals = filtered
	}

	if len(proposals) == 0 {
		if output.IsJSON(formatter) {
			return formatter.Print(map[string]interface{}{
				"proposals": []interface{}{},
				"total":     0,
			})
		}
		_ = formatter.Print("No fix proposals available for the current findings.")
		return nil
	}

	// Write to file if requested
	if fixOutput != "" {
		data, err := json.MarshalIndent(map[string]interface{}{
			"proposals": proposals,
			"total":     len(proposals),
		}, "", "  ")
		if err != nil {
			return formatter.PrintError(fmt.Errorf("failed to marshal proposals: %w", err))
		}
		if err := os.WriteFile(fixOutput, data, 0600); err != nil {
			return formatter.PrintError(fmt.Errorf("failed to write output: %w", err))
		}
		_ = formatter.Print(fmt.Sprintf("Wrote %d proposals to %s", len(proposals), fixOutput))
		return nil
	}

	if output.IsJSON(formatter) {
		return formatter.Print(map[string]interface{}{
			"proposals": proposals,
			"total":     len(proposals),
		})
	}

	_ = formatter.Print(fix.RenderSummary(proposals))
	return nil
}

// runFixApply applies fix proposals.
func runFixApply(cmd *cobra.Command, args []string) error {
	formatter := FormatterFromContext(cmd.Context())

	repo, _, err := git.DetectOrLocal()
	if err != nil {
		return formatter.PrintError(fmt.Errorf("failed to detect repository: %w", err))
	}

	if !output.IsJSON(formatter) && !fixDryRun {
		_ = formatter.Print("Scanning for findings...")
	}

	findings, err := runFixScan(repo.Root)
	if err != nil {
		return formatter.PrintError(fmt.Errorf("scan failed: %w", err))
	}

	// Filter findings based on flags
	if fixSeverity != "" {
		findings = filterFindingsBySeverity(findings, fixSeverity)
	}
	if fixFile != "" {
		findings = filterFindingsByFile(findings, fixFile)
	}
	if fixRuleID != "" {
		findings = filterFindingsByRule(findings, fixRuleID)
	}
	if fixFindingID != "" {
		findings = filterFindingsByID(findings, fixFindingID)
	}

	engine := fix.NewEngine()
	proposals := engine.Suggest(findings)

	if len(proposals) == 0 {
		if output.IsJSON(formatter) {
			return formatter.Print(map[string]interface{}{
				"applied": 0,
				"message": "no fix proposals available",
			})
		}
		_ = formatter.Print("No fix proposals available for the current findings.")
		return nil
	}

	// Filter to auto-applicable if --all is set
	if fixAll {
		var autoProposals []fix.FixProposal
		for _, p := range proposals {
			if p.AutoApplicable {
				autoProposals = append(autoProposals, p)
			}
		}
		proposals = autoProposals
		if len(proposals) == 0 {
			_ = formatter.Print("No auto-applicable fixes available.")
			return nil
		}
	}

	// Show preview
	if !fixDryRun && !fixYes {
		_ = formatter.Print(fix.RenderSummary(proposals))
		_ = formatter.Print("")
		_ = formatter.Print("Preview of changes:")
		for _, p := range proposals {
			if p.Patch != "" {
				_ = formatter.Print("")
				_ = formatter.Print(fmt.Sprintf("--- %s ---", p.FilePath))
				_ = formatter.Print(p.Patch)
			}
		}
		_ = formatter.Print("")
		fmt.Print("Apply these fixes? [y/N] ")
		var response string
		_, _ = fmt.Scanln(&response)
		if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
			_ = formatter.Print("Aborted.")
			return nil
		}
	}

	// Apply fixes
	opts := fix.ApplyOptions{
		DryRun:    fixDryRun,
		Backup:    fixBackup,
		NoConfirm: fixYes,
	}

	result := fix.ApplyAll(proposals, opts)

	if output.IsJSON(formatter) {
		return formatter.Print(result)
	}

	_ = formatter.Print(fix.RenderApplyResult(result))
	return nil
}

// runFixShow shows a fix proposal for a specific finding.
func runFixShow(cmd *cobra.Command, args []string) error {
	formatter := FormatterFromContext(cmd.Context())

	repo, _, err := git.DetectOrLocal()
	if err != nil {
		return formatter.PrintError(fmt.Errorf("failed to detect repository: %w", err))
	}

	// If a finding ID is provided, find it
	if len(args) == 1 {
		findings, err := runFixScan(repo.Root)
		if err != nil {
			return formatter.PrintError(fmt.Errorf("scan failed: %w", err))
		}

		var target *analysis.Finding
		for i := range findings {
			if findings[i].ID == args[0] || findings[i].RuleID == args[0] {
				target = &findings[i]
				break
			}
		}
		if target == nil {
			return formatter.PrintError(fmt.Errorf("finding %q not found", args[0]))
		}

		engine := fix.NewEngine()
		proposal, err := engine.SuggestForFinding(*target)
		if err != nil {
			return formatter.PrintError(fmt.Errorf("no fix available: %w", err))
		}
		if proposal == nil {
			return formatter.PrintError(fmt.Errorf("no fix template for rule %s", target.RuleID))
		}

		if output.IsJSON(formatter) {
			return formatter.Print(proposal)
		}
		_ = formatter.Print(fix.RenderProposalMarkdown(*proposal))
		return nil
	}

	// If file+line is provided
	if fixFile != "" && fixLine > 0 {
		findings, err := runFixScan(repo.Root)
		if err != nil {
			return formatter.PrintError(fmt.Errorf("scan failed: %w", err))
		}

		normalizedFile := filepath.ToSlash(strings.TrimPrefix(fixFile, "./"))
		for i := range findings {
			fFile := filepath.ToSlash(strings.TrimPrefix(findings[i].FilePath, "./"))
			if (strings.HasSuffix(fFile, normalizedFile) || fFile == normalizedFile) && findings[i].LineStart == fixLine {
				engine := fix.NewEngine()
				proposal, err := engine.SuggestForFinding(findings[i])
				if err != nil {
					return formatter.PrintError(fmt.Errorf("no fix available: %w", err))
				}
				if proposal == nil {
					return formatter.PrintError(fmt.Errorf("no fix template for rule %s", findings[i].RuleID))
				}
				if output.IsJSON(formatter) {
					return formatter.Print(proposal)
				}
				_ = formatter.Print(fix.RenderProposalMarkdown(*proposal))
				return nil
			}
		}
		return formatter.PrintError(fmt.Errorf("no finding at %s:%d", fixFile, fixLine))
	}

	return formatter.PrintError(fmt.Errorf("provide a finding ID, or use --file and --line"))
}

// runFixScan runs a SAST scan for the fix command.
func runFixScan(root string) ([]analysis.Finding, error) {
	runner := sast.NewRunner()
	runner.RespectGitignore = true
	runner.Timeout = 120 * time.Second

	result, err := runner.Analyze(context.Background(), root)
	if err != nil {
		return nil, err
	}
	return result.Findings, nil
}

// filterFindingsBySeverity filters findings to those at or above the given severity.
func filterFindingsBySeverity(findings []analysis.Finding, minSeverity string) []analysis.Finding {
	minOrder := analysis.SeverityOrder(analysis.Severity(minSeverity))
	var filtered []analysis.Finding
	for _, f := range findings {
		if analysis.SeverityOrder(f.Severity) >= minOrder {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// filterFindingsByFile filters findings to those in the given file.
func filterFindingsByFile(findings []analysis.Finding, file string) []analysis.Finding {
	normalizedFile := filepath.ToSlash(strings.TrimPrefix(file, "./"))
	var filtered []analysis.Finding
	for _, f := range findings {
		fFile := filepath.ToSlash(strings.TrimPrefix(f.FilePath, "./"))
		if fFile == normalizedFile || strings.HasSuffix(fFile, normalizedFile) {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// filterFindingsByRule filters findings to those matching the given rule ID.
func filterFindingsByRule(findings []analysis.Finding, ruleID string) []analysis.Finding {
	var filtered []analysis.Finding
	for _, f := range findings {
		if f.RuleID == ruleID {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// filterFindingsByID filters findings to the one with the given ID.
func filterFindingsByID(findings []analysis.Finding, id string) []analysis.Finding {
	var filtered []analysis.Finding
	for _, f := range findings {
		if f.ID == id || f.RuleID == id {
			filtered = append(filtered, f)
		}
	}
	return filtered
}
