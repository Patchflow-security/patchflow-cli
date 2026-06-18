package cmd

import (
	"strconv"

	"github.com/patchflow/patchflow-cli/internal/output"
	"github.com/patchflow/patchflow-cli/internal/scan"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan code for issues",
	Long:  `Scan your codebase for issues, vulnerabilities, and style violations.`,
}

var scanLocalCmd = &cobra.Command{
	Use:   "local",
	Short: "Scan the local repository",
	RunE: func(cmd *cobra.Command, _ []string) error {
		formatter := FormatterFromContext(cmd.Context())
		result, err := scan.ScanLocal()
		if err != nil {
			return formatter.PrintError(err)
		}
		return printScanResult(formatter, result)
	},
}

var scanChangedCmd = &cobra.Command{
	Use:   "changed",
	Short: "Scan changed files",
	RunE: func(cmd *cobra.Command, _ []string) error {
		formatter := FormatterFromContext(cmd.Context())
		result, err := scan.ScanChanged()
		if err != nil {
			return formatter.PrintError(err)
		}
		return printScanResult(formatter, result)
	},
}

func printScanResult(formatter output.Formatter, result *scan.Result) error {
	if _, ok := formatter.(*output.JSONFormatter); ok {
		return formatter.Print(result)
	}

	_ = formatter.Print("Repository: " + result.Root)

	if len(result.ChangedFiles) > 0 {
		_ = formatter.Print("Changed files: " + strconv.Itoa(len(result.ChangedFiles)))
	}

	if len(result.Manifests) == 0 {
		_ = formatter.Print("No manifests detected.")
	} else {
		_ = formatter.Print("Detected manifests:")
		rows := make([][]string, 0, len(result.Manifests))
		for _, m := range result.Manifests {
			rows = append(rows, []string{m.Type, m.Path})
		}
		_ = formatter.PrintTable([]string{"Type", "Path"}, rows)
	}

	_ = formatter.Print("Total manifests: " + strconv.Itoa(len(result.Manifests)))

	return nil
}

func init() {
	scanCmd.AddCommand(scanLocalCmd)
	scanCmd.AddCommand(scanChangedCmd)
	scanCmd.AddCommand(scanExportCmd)
	rootCmd.AddCommand(scanCmd)
}
