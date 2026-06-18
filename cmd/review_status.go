package cmd

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/patchflow/patchflow-cli/internal/api"
	"github.com/patchflow/patchflow-cli/internal/output"
	"github.com/spf13/cobra"
)

var watchFlag bool

var reviewStatusCmd = &cobra.Command{
	Use:   "status <job-id>",
	Short: "Check the status of a submitted review",
	Args:  cobra.ExactArgs(1),
	RunE:  runReviewStatus,
}

func init() {
	reviewStatusCmd.Flags().BoolVar(&watchFlag, "watch", false, "Poll every 5 seconds until the job completes or fails")
	reviewCmd.AddCommand(reviewStatusCmd)
}

func runReviewStatus(cmd *cobra.Command, args []string) error {
	formatter := FormatterFromContext(cmd.Context())
	jobID := args[0]

	cfg := ConfigFromContext(cmd.Context())
	if cfg.Token == "" {
		return formatter.PrintError(errors.New("Not authenticated. Run 'patchflow login --token <token>' first."))
	}

	client := api.NewClient(cfg.APIURL, cfg.Token)

	if watchFlag {
		return watchStatus(cmd.Context(), formatter, client, jobID)
	}

	resp, err := client.GetStatus(cmd.Context(), jobID)
	if err != nil {
		return formatter.PrintError(fmt.Errorf("failed to get status: %w", err))
	}
	return printStatus(formatter, resp)
}

func watchStatus(ctx context.Context, formatter output.Formatter, client api.APIClient, jobID string) error {
	interval := 5 * time.Second
	maxAttempts := 60

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		resp, err := client.GetStatus(ctx, jobID)
		if err != nil {
			return formatter.PrintError(fmt.Errorf("failed to get status: %w", err))
		}

		if err := printStatus(formatter, resp); err != nil {
			return err
		}

		if resp.Status == "completed" || resp.Status == "failed" {
			return nil
		}

		if attempt == maxAttempts {
			break
		}

		select {
		case <-ctx.Done():
			return formatter.PrintError(ctx.Err())
		case <-time.After(interval):
		}
	}

	return formatter.PrintError(fmt.Errorf("max polling attempts (%d) reached for job %s", maxAttempts, jobID))
}

func printStatus(formatter output.Formatter, resp *api.StatusResponse) error {
	// JSON mode: print the struct directly
	_, isJSON := formatter.(*output.JSONFormatter)
	if isJSON {
		return formatter.Print(resp)
	}

	// Human mode: print structured status output
	_ = formatter.Print(fmt.Sprintf("Job ID:     %s", resp.ID))
	_ = formatter.Print(fmt.Sprintf("Status:     %s", resp.Status))
	if resp.ResultURL != "" {
		_ = formatter.Print(fmt.Sprintf("Result URL: %s", resp.ResultURL))
	}
	return nil
}
