package cmd

import (
	"github.com/patchflow/patchflow-cli/internal/auth"
	"github.com/spf13/cobra"
)

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Log out from PatchFlow",
	Long:  `Remove stored credentials and log out from the PatchFlow platform.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		formatter := FormatterFromContext(cmd.Context())
		mgr := auth.NewManager(ConfigFromContext(cmd.Context()))
		if err := mgr.Logout(); err != nil {
			return formatter.PrintError(err)
		}
		return formatter.Print("Logged out of PatchFlow.")
	},
}

func init() {
	rootCmd.AddCommand(logoutCmd)
}
