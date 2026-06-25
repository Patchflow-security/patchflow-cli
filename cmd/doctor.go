package cmd

import (
	"fmt"

	"github.com/patchflow/patchflow-cli/internal/doctor"
	"github.com/patchflow/patchflow-cli/internal/output"
	"github.com/spf13/cobra"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check the PatchFlow CLI environment",
	Long:  `Performs a series of checks to verify that the PatchFlow CLI environment is correctly configured.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		formatter := FormatterFromContext(cmd.Context())

		report, err := doctor.Run()
		if err != nil {
			return formatter.PrintError(err)
		}

		if _, ok := formatter.(*output.JSONFormatter); ok {
			return formatter.Print(report)
		}

		fmt.Println("PatchFlow Doctor")
		fmt.Println("================")

		if report.GitVersion != "" {
			fmt.Printf("[OK] Git installed: %s\n", report.GitVersion)
		} else {
			fmt.Println("[X]  Git not installed")
		}

		if report.IsGitRepo {
			fmt.Printf("[OK] Inside a git repository: %s\n", report.RepoRoot)
		} else {
			fmt.Println("[X]  Not inside a git repository")
		}

		if report.RemoteURL != "" {
			fmt.Printf("[OK] Remote configured: %s\n", report.RemoteURL)
		} else if report.IsGitRepo {
			fmt.Println("[!]  No remote origin configured")
		}

		// Embedded scanners
		fmt.Println("\nEmbedded SAST Scanners (always available, zero installation):")
		for _, s := range report.EmbeddedScanners {
			fmt.Printf("[OK] %-20s (%s) — %d rules\n", s.Name, s.Language, s.RuleCount)
		}

		// External tools
		fmt.Println("\nExternal SAST Tools (optional supplements):")
		for _, t := range report.ExternalTools {
			if t.Found {
				fmt.Printf("[OK] %-20s (%s) — installed\n", t.Name, t.Language)
			} else {
				fmt.Printf("[--] %-20s (%s) — not installed (optional)\n", t.Name, t.Language)
			}
		}

		if len(report.Errors) > 0 {
			fmt.Println("\nErrors:")
			for _, e := range report.Errors {
				fmt.Printf("  - %s\n", e)
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}
