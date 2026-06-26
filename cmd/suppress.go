package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/patchflow/patchflow-cli/internal/git"
	"github.com/patchflow/patchflow-cli/internal/output"
	"github.com/spf13/cobra"
)

var suppressCmd = &cobra.Command{
	Use:   "suppress [rule-id] --file [path] --line [n]",
	Short: "Add a //patchflow:ignore suppression directive to a file",
	Long: `Add a suppression directive to ignore a specific finding.

This inserts a // patchflow:ignore comment at the specified line,
which tells the scanner to skip that finding in future scans.

Examples:
  patchflow suppress PY001 --file app.py --line 42 --reason "safe eval of trusted config"
  patchflow suppress TS-JS004 --file src/app.tsx --line 100`,
	Args: cobra.ExactArgs(1),
	RunE: runSuppress,
}

var (
	suppressFile   string
	suppressLine   int
	suppressReason string
)

func init() {
	suppressCmd.Flags().StringVar(&suppressFile, "file", "", "File to add suppression to (required)")
	suppressCmd.Flags().IntVar(&suppressLine, "line", 0, "Line number of the finding (required)")
	suppressCmd.Flags().StringVar(&suppressReason, "reason", "", "Justification for suppression (required)")
	_ = suppressCmd.MarkFlagRequired("file")
	_ = suppressCmd.MarkFlagRequired("line")
	_ = suppressCmd.MarkFlagRequired("reason")
	rootCmd.AddCommand(suppressCmd)
}

func runSuppress(cmd *cobra.Command, args []string) error {
	formatter := FormatterFromContext(cmd.Context())
	ruleID := args[0]

	repo, _, err := git.DetectOrLocal()
	if err != nil {
		return formatter.PrintError(fmt.Errorf("failed to detect repository: %w", err))
	}

	absPath := suppressFile
	if !filepath.IsAbs(absPath) {
		absPath = filepath.Join(repo.Root, suppressFile)
	}

	// Read the file
	data, err := os.ReadFile(absPath)
	if err != nil {
		return formatter.PrintError(fmt.Errorf("failed to read file: %w", err))
	}

	lines := strings.Split(string(data), "\n")
	if suppressLine < 1 || suppressLine > len(lines) {
		return formatter.PrintError(fmt.Errorf("line %d is out of range (file has %d lines)", suppressLine, len(lines)))
	}

	// Determine the comment syntax based on file extension
	commentPrefix := getCommentPrefix(absPath)
	directive := fmt.Sprintf("%s patchflow:ignore %s -- %s", commentPrefix, ruleID, suppressReason)

	// Insert the suppression directive on the line BEFORE the finding
	// (or on the same line if it's a single-line comment language)
	insertAt := suppressLine - 1 // 0-based index for the line before the finding
	if insertAt < 0 {
		insertAt = 0
	}

	// Check if there's already a suppression directive nearby
	for i := insertAt - 1; i >= 0 && i >= insertAt-3; i-- {
		if strings.Contains(lines[i], "patchflow:ignore") && strings.Contains(lines[i], ruleID) {
			if !output.IsJSON(formatter) {
				_ = formatter.Print("Suppression already exists at line " + fmt.Sprintf("%d", i+1))
			}
			return nil
		}
	}

	// Insert the directive
	newLines := make([]string, 0, len(lines)+1)
	newLines = append(newLines, lines[:insertAt]...)
	newLines = append(newLines, directive)
	newLines = append(newLines, lines[insertAt:]...)

	// Write the file
	output := strings.Join(newLines, "\n")
	if err := os.WriteFile(absPath, []byte(output), 0644); err != nil {
		return formatter.PrintError(fmt.Errorf("failed to write file: %w", err))
	}

	if outputIsJSON(formatter) {
		return formatter.Print(map[string]interface{}{
			"rule_id":  ruleID,
			"file":     suppressFile,
			"line":     suppressLine,
			"reason":   suppressReason,
			"inserted": true,
		})
	}

	_ = formatter.Print(fmt.Sprintf("Suppression added: %s:%d", suppressFile, suppressLine))
	_ = formatter.Print(fmt.Sprintf("  Directive: %s", directive))
	_ = formatter.Print(fmt.Sprintf("  Rule: %s", ruleID))
	_ = formatter.Print(fmt.Sprintf("  Reason: %s", suppressReason))
	return nil
}

// getCommentPrefix returns the comment syntax for the given file type.
func getCommentPrefix(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".py", ".rb", ".sh", ".bash", ".zsh", ".yaml", ".yml", ".toml", ".dockerfile", ".tf", ".tfvars":
		return "#"
	case ".go", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".c", ".cpp", ".h",
		".hpp", ".rs", ".swift", ".kt", ".scala", ".cs", ".php":
		return "//"
	default:
		base := strings.ToLower(filepath.Base(path))
		if base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") {
			return "#"
		}
		return "//"
	}
}

// outputIsJSON checks if the formatter is JSON mode.
func outputIsJSON(f output.Formatter) bool {
	type jsonNamer interface {
		IsJSON() bool
	}
	if j, ok := f.(jsonNamer); ok {
		return j.IsJSON()
	}
	return false
}

// Ensure bufio is used
var _ = bufio.NewReader
