package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/patchflow/patchflow-cli/internal/analysis"
	"github.com/patchflow/patchflow-cli/internal/baseline"
	"github.com/patchflow/patchflow-cli/internal/exitcode"
	"github.com/patchflow/patchflow-cli/internal/git"
	"github.com/patchflow/patchflow-cli/internal/output"
	"github.com/patchflow/patchflow-cli/internal/sast"
	"github.com/spf13/cobra"
)

// --- Top-level `patchflow baseline` command (production lifecycle) ---
//
// The top-level baseline command uses flag-based arguments (--name, --from)
// for a stable, scriptable CI interface. The legacy `patchflow scan baseline`
// subcommand (positional args) is preserved below for backward compatibility.

var (
	baselineCreateName string
	baselineDiffFrom   string
	baselineDeleteName string
)

var baselineRootCmd = &cobra.Command{
	Use:   "baseline",
	Short: "Manage finding baselines for CI noise reduction",
	Long: `Create, compare, and manage finding baselines to reduce CI noise.

A baseline stores a snapshot of known findings. Subsequent scans can compare
against the baseline to only report NEW findings, dramatically reducing
CI noise on existing codebases.

Baselines are stored under .patchflow/baselines/<name>.json and compared
using stable semantic fingerprints (rule id + scanner + normalized path +
normalized snippet) so that findings survive line-number shifts from
unrelated edits.

Examples:
  patchflow baseline create --name v1.0
  patchflow baseline list
  patchflow baseline diff --from v1.0
  patchflow baseline delete --name v1.0
  patchflow scan run --new-only --baseline v1.0
`,
}

var baselineRootCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a baseline from current scan findings",
	Long:  `Run a full SAST scan and store the findings as a named baseline.`,
	RunE:  runBaselineRootCreate,
}

var baselineRootListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all saved baselines",
	RunE:  runBaselineRootList,
}

var baselineRootDiffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Diff current scan findings against a baseline",
	Long:  `Run a full SAST scan and report new, resolved, and unchanged findings relative to the named baseline.`,
	RunE:  runBaselineRootDiff,
}

var baselineRootDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a saved baseline",
	RunE:  runBaselineRootDelete,
}

func init() {
	baselineRootCreateCmd.Flags().StringVar(&baselineCreateName, "name", "", "Name of the baseline to create (required)")
	_ = baselineRootCreateCmd.MarkFlagRequired("name")

	baselineRootDiffCmd.Flags().StringVar(&baselineDiffFrom, "from", "", "Baseline name to diff against (required)")
	_ = baselineRootDiffCmd.MarkFlagRequired("from")

	baselineRootDeleteCmd.Flags().StringVar(&baselineDeleteName, "name", "", "Name of the baseline to delete (required)")
	_ = baselineRootDeleteCmd.MarkFlagRequired("name")

	baselineRootCmd.AddCommand(baselineRootCreateCmd)
	baselineRootCmd.AddCommand(baselineRootListCmd)
	baselineRootCmd.AddCommand(baselineRootDiffCmd)
	baselineRootCmd.AddCommand(baselineRootDeleteCmd)
	rootCmd.AddCommand(baselineRootCmd)
}

// runBaselineRootCreate implements `patchflow baseline create --name <name>`.
func runBaselineRootCreate(cmd *cobra.Command, _ []string) error {
	formatter := FormatterFromContext(cmd.Context())
	return doBaselineCreate(formatter, baselineCreateName)
}

// runBaselineRootList implements `patchflow baseline list`.
func runBaselineRootList(cmd *cobra.Command, _ []string) error {
	formatter := FormatterFromContext(cmd.Context())
	return doBaselineList(formatter)
}

// runBaselineRootDiff implements `patchflow baseline diff --from <name>`.
func runBaselineRootDiff(cmd *cobra.Command, _ []string) error {
	formatter := FormatterFromContext(cmd.Context())
	return doBaselineDiff(formatter, baselineDiffFrom)
}

// runBaselineRootDelete implements `patchflow baseline delete --name <name>`.
func runBaselineRootDelete(cmd *cobra.Command, _ []string) error {
	formatter := FormatterFromContext(cmd.Context())
	return doBaselineDelete(formatter, baselineDeleteName)
}

// --- Shared implementation (used by both top-level and legacy subcommands) ---

func doBaselineCreate(formatter output.Formatter, name string) error {
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
			"baseline":       name,
			"findings_count": len(findings),
			"commit":         commit,
			"created":        true,
		})
	}

	_ = formatter.Print(fmt.Sprintf("Baseline %q created with %d findings.", name, len(findings)))
	if commit != "" {
		_ = formatter.Print(fmt.Sprintf("Commit: %s", commit))
	}
	return nil
}

func doBaselineList(formatter output.Formatter) error {
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
		_ = formatter.Print("No baselines found. Create one with: patchflow baseline create --name <name>")
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

func doBaselineDiff(formatter output.Formatter, name string) error {
	repo, _, err := git.DetectOrLocal()
	if err != nil {
		return formatter.PrintError(err)
	}

	if !output.IsJSON(formatter) {
		_ = formatter.Print("Running scan for baseline diff...")
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
	_ = formatter.Print(fmt.Sprintf("  New:       %d", diff.NewCount))
	_ = formatter.Print(fmt.Sprintf("  Resolved:  %d", diff.ResolvedCount))
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

	// Exit with non-zero code if there are new findings (for CI).
	if diff.NewCount > 0 {
		return &ExitError{
			Code: exitcode.FindingsFound,
			Msg:  fmt.Sprintf("%d new finding(s) relative to baseline %q", diff.NewCount, name),
		}
	}
	return nil
}

func doBaselineDelete(formatter output.Formatter, name string) error {
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

// --- Legacy `patchflow scan baseline` subcommand (backward compatible) ---

var baselineCmd = &cobra.Command{
	Use:   "baseline",
	Short: "Manage finding baselines for CI noise reduction (legacy)",
	Long: `Create and compare finding baselines to reduce CI noise.

A baseline stores a snapshot of known findings. Subsequent scans can compare
against the baseline to only report NEW findings, dramatically reducing
CI noise on existing codebases.

Baselines are stored in .patchflow/baselines/ as JSON files.

Prefer the top-level 'patchflow baseline' command for new scripts:
  patchflow baseline create --name v1.0
  patchflow baseline diff --from v1.0

Legacy usage:
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
	RunE: func(cmd *cobra.Command, args []string) error {
		return doBaselineCreate(FormatterFromContext(cmd.Context()), args[0])
	},
}

var baselineCompareCmd = &cobra.Command{
	Use:   "compare [name]",
	Short: "Compare current scan findings against a baseline",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return doBaselineDiff(FormatterFromContext(cmd.Context()), args[0])
	},
}

var baselineListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all saved baselines",
	RunE: func(cmd *cobra.Command, _ []string) error {
		return doBaselineList(FormatterFromContext(cmd.Context()))
	},
}

var baselineDeleteCmd = &cobra.Command{
	Use:   "delete [name]",
	Short: "Delete a saved baseline",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return doBaselineDelete(FormatterFromContext(cmd.Context()), args[0])
	},
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
	// Populate stable fingerprints so the baseline stores line-independent keys.
	analysis.PopulateFingerprints(result.Findings)
	return result.Findings, commit, nil
}
