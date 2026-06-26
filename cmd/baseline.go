package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/patchflow/patchflow-cli/internal/analysis"
	"github.com/patchflow/patchflow-cli/internal/baseline"
	"github.com/patchflow/patchflow-cli/internal/git"
	"github.com/patchflow/patchflow-cli/internal/output"
	"github.com/patchflow/patchflow-cli/internal/sast"
	"github.com/spf13/cobra"
)

var baselineCmd = &cobra.Command{
	Use:   "baseline",
	Short: "Manage finding baselines for CI noise reduction",
	Long: `Create and compare finding baselines to reduce CI noise.

A baseline stores a snapshot of known findings. Subsequent scans can compare
against the baseline to only report NEW findings, dramatically reducing
CI noise on existing codebases.

Baselines are stored in .patchflow/baselines/ as JSON files.

Examples:
  patchflow scan baseline create v1.0
  patchflow scan baseline compare v1.0
  patchflow scan baseline list
  patchflow scan baseline delete v1.0
`,
}

var baselineCreateCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Create a baseline from current scan findings",
	Args:  cobra.ExactArgs(1),
	RunE:  runBaselineCreate,
}

var baselineCompareCmd = &cobra.Command{
	Use:   "compare [name]",
	Short: "Compare current scan findings against a baseline",
	Args:  cobra.ExactArgs(1),
	RunE:  runBaselineCompare,
}

var baselineListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all saved baselines",
	RunE:  runBaselineList,
}

var baselineDeleteCmd = &cobra.Command{
	Use:   "delete [name]",
	Short: "Delete a saved baseline",
	Args:  cobra.ExactArgs(1),
	RunE:  runBaselineDelete,
}

func init() {
	baselineCmd.AddCommand(baselineCreateCmd)
	baselineCmd.AddCommand(baselineCompareCmd)
	baselineCmd.AddCommand(baselineListCmd)
	baselineCmd.AddCommand(baselineDeleteCmd)
	scanCmd.AddCommand(baselineCmd)
}

// runBaselineScan runs a full SAST scan and returns all findings.
// This is used by baseline create/compare to get the current finding set.
func runBaselineScan() ([]analysis.Finding, string, error) {
	repo, isGitRepo, err := git.DetectOrLocal()
	if err != nil {
		return nil, "", err
	}

	commit := ""
	if isGitRepo {
		commit = repo.CommitSHA
	}

	runner := sast.NewRunner()
	runner.RespectGitignore = true
	runner.Timeout = 120 * time.Second

	result, err := runner.Analyze(context.Background(), repo.Root)
	if err != nil {
		return nil, commit, err
	}
	return result.Findings, commit, nil
}

func runBaselineCreate(cmd *cobra.Command, args []string) error {
	formatter := FormatterFromContext(cmd.Context())
	name := args[0]

	repo, _, err := git.DetectOrLocal()
	if err != nil {
		return formatter.PrintError(err)
	}

	if !output.IsJSON(formatter) {
		_ = formatter.Print("Running scan to capture baseline findings...")
	}

	findings, commit, err := runBaselineScan()
	if err != nil {
		return formatter.PrintError(fmt.Errorf("scan failed: %w", err))
	}

	mgr := baseline.NewManager(repo.Root)
	if err := mgr.Create(name, findings, commit); err != nil {
		return formatter.PrintError(err)
	}

	if output.IsJSON(formatter) {
		return formatter.Print(map[string]interface{}{
			"baseline":      name,
			"findings_count": len(findings),
			"commit":        commit,
			"created":       true,
		})
	}

	_ = formatter.Print(fmt.Sprintf("Baseline %q created with %d findings.", name, len(findings)))
	if commit != "" {
		_ = formatter.Print(fmt.Sprintf("Commit: %s", commit))
	}
	return nil
}

func runBaselineCompare(cmd *cobra.Command, args []string) error {
	formatter := FormatterFromContext(cmd.Context())
	name := args[0]

	repo, _, err := git.DetectOrLocal()
	if err != nil {
		return formatter.PrintError(err)
	}

	if !output.IsJSON(formatter) {
		_ = formatter.Print("Running scan for baseline comparison...")
	}

	findings, _, err := runBaselineScan()
	if err != nil {
		return formatter.PrintError(fmt.Errorf("scan failed: %w", err))
	}

	mgr := baseline.NewManager(repo.Root)
	diff, err := mgr.Compare(name, findings)
	if err != nil {
		return formatter.PrintError(err)
	}

	if output.IsJSON(formatter) {
		return formatter.Print(diff)
	}

	_ = formatter.Print(fmt.Sprintf("Baseline: %s", diff.BaselineName))
	_ = formatter.Print(fmt.Sprintf("  New:      %d", diff.NewCount))
	_ = formatter.Print(fmt.Sprintf("  Resolved: %d", diff.ResolvedCount))
	_ = formatter.Print(fmt.Sprintf("  Unchanged: %d", diff.UnchangedCount))

	if diff.NewCount > 0 {
		_ = formatter.Print("\nNew findings:")
		for _, f := range diff.New {
			_ = formatter.Print(fmt.Sprintf("  [%s] %s:%d — %s", f.RuleID, f.FilePath, f.LineStart, f.Title))
		}
	}

	if diff.ResolvedCount > 0 {
		_ = formatter.Print("\nResolved findings:")
		for _, f := range diff.Resolved {
			_ = formatter.Print(fmt.Sprintf("  [%s] %s:%d — %s", f.RuleID, f.FilePath, f.LineStart, f.Title))
		}
	}

	// Exit with non-zero code if there are new findings (for CI)
	if diff.NewCount > 0 {
		os.Exit(1)
	}
	return nil
}

func runBaselineList(cmd *cobra.Command, _ []string) error {
	formatter := FormatterFromContext(cmd.Context())
	repo, _, err := git.DetectOrLocal()
	if err != nil {
		return formatter.PrintError(err)
	}

	mgr := baseline.NewManager(repo.Root)
	names, err := mgr.List()
	if err != nil {
		return formatter.PrintError(err)
	}

	if output.IsJSON(formatter) {
		return formatter.Print(map[string]interface{}{
			"baselines": names,
		})
	}

	if len(names) == 0 {
		_ = formatter.Print("No baselines found. Create one with: patchflow scan baseline create <name>")
		return nil
	}

	_ = formatter.Print("Baselines:")
	for _, name := range names {
		bl, err := mgr.Load(name)
		if err != nil {
			continue
		}
		_ = formatter.Print(fmt.Sprintf("  %s — %d findings (created %s)", name, len(bl.Findings), bl.CreatedAt.Format("2006-01-02")))
	}
	return nil
}

func runBaselineDelete(cmd *cobra.Command, args []string) error {
	formatter := FormatterFromContext(cmd.Context())
	name := args[0]

	repo, _, err := git.DetectOrLocal()
	if err != nil {
		return formatter.PrintError(err)
	}

	mgr := baseline.NewManager(repo.Root)
	if err := mgr.Delete(name); err != nil {
		return formatter.PrintError(err)
	}

	if output.IsJSON(formatter) {
		return formatter.Print(map[string]interface{}{
			"baseline": name,
			"deleted":  true,
		})
	}
	_ = formatter.Print(fmt.Sprintf("Baseline %q deleted.", name))
	return nil
}
