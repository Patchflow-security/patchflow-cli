package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/patchflow/patchflow-cli/internal/scan"
	"github.com/spf13/cobra"
)

var scanExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export scan results",
	Long:  `Export scan results in SARIF or JSON format.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		format, _ := cmd.Flags().GetString("format")
		outputPath, _ := cmd.Flags().GetString("output")

		result, err := scan.ScanLocal()
		if err != nil {
			return err
		}

		var data []byte
		switch format {
		case "sarif":
			sarifReport, err := scan.ExportSARIF(result)
			if err != nil {
				return err
			}
			data, err = json.MarshalIndent(sarifReport, "", "  ")
			if err != nil {
				return err
			}
		case "json":
			data, err = scan.ExportJSON(result)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported format: %q (supported: json, sarif)", format)
		}

		if outputPath != "" {
			if err := os.WriteFile(outputPath, data, 0644); err != nil {
				return fmt.Errorf("failed to write output file: %w", err)
			}
			formatter := FormatterFromContext(cmd.Context())
			return formatter.PrintSuccess("Report written to " + outputPath)
		}

		_, err = fmt.Fprintln(os.Stdout, string(data))
		return err
	},
}

func init() {
	scanExportCmd.Flags().String("format", "json", "Export format (json, sarif)")
	scanExportCmd.Flags().String("output", "", "Output file path (stdout if omitted)")
}
