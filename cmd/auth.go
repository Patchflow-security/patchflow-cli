package cmd

import (
	"fmt"

	"github.com/patchflow/patchflow-cli/internal/auth"
	"github.com/patchflow/patchflow-cli/internal/output"
	"github.com/spf13/cobra"
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Manage PatchFlow authentication",
	Long:  `Check authentication status and manage credentials for the PatchFlow platform.`,
}

var authStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show authentication status",
	RunE: func(cmd *cobra.Command, _ []string) error {
		formatter := FormatterFromContext(cmd.Context())
		mgr := auth.NewManager(ConfigFromContext(cmd.Context()))
		status, err := mgr.Status()
		if err != nil {
			return formatter.PrintError(err)
		}
		if _, ok := formatter.(*output.JSONFormatter); ok {
			return formatter.Print(status)
		}
		state := "not authenticated"
		if status.Authenticated {
			state = "authenticated"
		}
		return formatter.Print(fmt.Sprintf("Authentication: %s (token: %s, storage: %s)", state, status.MaskedToken, status.StorageType))
	},
}

func init() {
	authCmd.AddCommand(authStatusCmd)
	rootCmd.AddCommand(authCmd)
}
