package cmd

import (
	"github.com/patchflow/patchflow-cli/internal/output"
	"github.com/patchflow/patchflow-cli/internal/project"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize PatchFlow in the current repository",
	Long: `Create a .patchflow/ directory with configuration, cache, baselines, and reports
subdirectories. This sets up the project for local analysis with PatchFlow CLI.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		formatter := FormatterFromContext(cmd.Context())

		root, err := getRepoRoot()
		if err != nil {
			return formatter.PrintError(err)
		}

		result, err := project.Init(root)
		if err != nil {
			return formatter.PrintError(err)
		}

		if result.Created {
			if _, ok := formatter.(*output.JSONFormatter); ok {
				return formatter.Print(result)
			}
			_ = formatter.PrintSuccess("PatchFlow initialized.")
			_ = formatter.Print("  Config:  " + result.ConfigPath)
			_ = formatter.Print("  Dir:     " + result.Dir)
			_ = formatter.Print("")
			_ = formatter.Print("Next steps:")
			_ = formatter.Print("  patchflow scan local      # scan the repository")
			_ = formatter.Print("  patchflow pr-review       # review changes before opening a PR")
			return nil
		}

		if _, ok := formatter.(*output.JSONFormatter); ok {
			return formatter.Print(result)
		}
		_ = formatter.Print("PatchFlow already initialized at " + result.Dir)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}
