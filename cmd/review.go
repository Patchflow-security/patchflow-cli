package cmd

import (
	"fmt"

	"github.com/Patchflow-security/patchflow-cli/internal/api"
	"github.com/Patchflow-security/patchflow-cli/internal/git"
	"github.com/Patchflow-security/patchflow-cli/internal/output"
	"github.com/Patchflow-security/patchflow-cli/internal/review"
	"github.com/spf13/cobra"
)

var reviewCmd = &cobra.Command{
	Use:   "review",
	Short: "Review code changes",
	Long:  `Review code changes with context, PR analysis, or diff inspection.`,
}

var reviewContextCmd = &cobra.Command{
	Use:   "context",
	Short: "Show review context for the current repository",
	RunE:  runReviewContext,
}

var reviewPRCmd = &cobra.Command{
	Use:   "pr",
	Short: "Review a pull request",
	RunE:  runReviewPR,
}

var reviewDiffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Review a diff",
	RunE:  runReviewDiff,
}

var submitFlag bool
var fullDiffFlag bool

func init() {
	reviewPRCmd.Flags().BoolVar(&submitFlag, "submit", false, "Submit review payload to PatchFlow backend")
	reviewDiffCmd.Flags().BoolVar(&fullDiffFlag, "full-diff", false, "Include full diff content (not yet implemented)")

	reviewCmd.AddCommand(reviewContextCmd)
	reviewCmd.AddCommand(reviewPRCmd)
	reviewCmd.AddCommand(reviewDiffCmd)
	rootCmd.AddCommand(reviewCmd)
}

func runReviewContext(cmd *cobra.Command, _ []string) error {
	formatter := FormatterFromContext(cmd.Context())
	ctx, err := collectReviewContext()
	if err != nil {
		return formatter.PrintError(err)
	}
	return printContext(formatter, ctx)
}

func runReviewPR(cmd *cobra.Command, _ []string) error {
	formatter := FormatterFromContext(cmd.Context())
	ctx, err := collectReviewContext()
	if err != nil {
		return formatter.PrintError(err)
	}

	if !submitFlag {
		return printContext(formatter, ctx)
	}

	cfg := ConfigFromContext(cmd.Context())
	token, err := requireAuthToken(cmd)
	if err != nil {
		return formatter.PrintError(err)
	}

	client := api.NewClient(cfg.APIURL, token)
	payload := api.ReviewPayload{
		RepoRoot:     ctx.RepoRoot,
		RemoteURL:    ctx.RemoteURL,
		Branch:       ctx.Branch,
		CommitSHA:    ctx.CommitSHA,
		BaseBranch:   ctx.BaseBranch,
		ChangedFiles: nil, // metadata-only for MVP
		AddedLines:   ctx.AddedLines,
		DeletedLines: ctx.DeletedLines,
		Manifests:    ctx.Manifests,
		Submit:       true,
	}

	id, err := client.PostReview(cmd.Context(), payload)
	if err != nil {
		return formatter.PrintError(fmt.Errorf("failed to submit review: %w", err))
	}
	return formatter.PrintSuccess(fmt.Sprintf("Review submitted. Job ID: %s", id))
}

func runReviewDiff(cmd *cobra.Command, _ []string) error {
	formatter := FormatterFromContext(cmd.Context())
	ctx, err := collectReviewContext()
	if err != nil {
		return formatter.PrintError(err)
	}
	if fullDiffFlag {
		_ = formatter.Print("Note: Full diff mode not yet implemented. Only metadata is sent by default.")
	}
	return printContext(formatter, ctx)
}

func collectReviewContext() (*review.Context, error) {
	repo, err := git.Detect()
	if err != nil {
		return nil, err
	}
	if err := repo.DetectChangedFiles(); err != nil {
		return nil, err
	}
	if err := repo.DetectDiffStats(); err != nil {
		return nil, err
	}
	ctx, err := review.CollectContext(repo)
	if err != nil {
		return nil, err
	}
	ctx.Manifests = review.DetectManifests(repo.Root)
	return ctx, nil
}

func printContext(formatter output.Formatter, ctx *review.Context) error {
	// JSON mode: print the struct directly
	_, isJSON := formatter.(*output.JSONFormatter)
	if isJSON {
		return formatter.Print(ctx)
	}

	_ = formatter.Print("PatchFlow Review Context")
	_ = formatter.Print("")
	_ = formatter.Print("Repository:")
	_ = formatter.Print(fmt.Sprintf("  Remote: %s", ctx.RemoteURL))
	_ = formatter.Print(fmt.Sprintf("  Branch: %s", ctx.Branch))
	_ = formatter.Print(fmt.Sprintf("  Commit: %s", shortenSHA(ctx.CommitSHA)))
	_ = formatter.Print(fmt.Sprintf("  Base:   %s", ctx.BaseBranch))
	_ = formatter.Print("")
	_ = formatter.Print("Changes:")
	_ = formatter.Print(fmt.Sprintf("  Files changed: %d", ctx.FilesChanged))
	_ = formatter.Print(fmt.Sprintf("  Added lines: %d", ctx.AddedLines))
	_ = formatter.Print(fmt.Sprintf("  Deleted lines: %d", ctx.DeletedLines))
	_ = formatter.Print("")
	_ = formatter.Print("Detected manifests:")
	if len(ctx.Manifests) == 0 {
		_ = formatter.Print("  (none)")
	} else {
		for _, m := range ctx.Manifests {
			_ = formatter.Print(fmt.Sprintf("  %s", m))
		}
	}
	_ = formatter.Print("")
	_ = formatter.Print("Risk hints:")
	_ = formatter.Print(fmt.Sprintf("  Dependency files changed: %s", yesNo(ctx.DependencyFilesChanged)))
	_ = formatter.Print(fmt.Sprintf("  CI workflow changed: %s", yesNo(ctx.CIWorkflowChanged)))
	_ = formatter.Print(fmt.Sprintf("  Auth-related files changed: %s", yesNo(ctx.AuthFilesChanged)))
	_ = formatter.Print("")
	_ = formatter.Print("Next:")
	_ = formatter.Print("  Run: patchflow review pr --submit")
	return nil
}

func shortenSHA(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
