package cmd

import (
	"github.com/Patchflow-security/patchflow-cli/pkg/version"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of PatchFlow CLI",
	RunE: func(cmd *cobra.Command, _ []string) error {
		formatter := FormatterFromContext(cmd.Context())
		jsonMode, _ := cmd.Flags().GetBool("json")

		if jsonMode {
			return formatter.Print(version.FullInfo())
		}
		return formatter.Print(version.BuildInfo())
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

// versionBuildInfo returns the CLI version string for scan metadata.
func versionBuildInfo() string {
	return version.Short()
}
