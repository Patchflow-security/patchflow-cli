package cmd

import (
	"github.com/patchflow/patchflow-cli/internal/auth"
	"github.com/spf13/cobra"
)

var loginCmd = &cobra.Command{
	Use:   "login --token <token>",
	Short: "Authenticate with PatchFlow",
	Long:  `Authenticate with the PatchFlow platform using an API token.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		formatter := FormatterFromContext(cmd.Context())
		token, err := cmd.Flags().GetString("token")
		if err != nil {
			return err
		}

		mgr := auth.NewManager(ConfigFromContext(cmd.Context()))
		if err := mgr.Login(token); err != nil {
			return formatter.PrintError(err)
		}
		return formatter.Print("Authenticated with PatchFlow.")
	},
}

func init() {
	loginCmd.Flags().String("token", "", "API token")
	rootCmd.AddCommand(loginCmd)
}
