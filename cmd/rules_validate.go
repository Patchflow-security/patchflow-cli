package cmd

import (
	"fmt"
	"os"
	"regexp"

	"github.com/patchflow/patchflow-cli/internal/output"
	"github.com/patchflow/patchflow-cli/internal/sast/customrules"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var rulesValidateCmd = &cobra.Command{
	Use:   "validate [path]",
	Short: "Validate a custom rules YAML file",
	Long: `Validate the structure and contents of a custom rules YAML file.

If a path argument is provided, that file is validated. Otherwise the command
looks for .patchflow/rules.yaml in the project root.

Validation checks:
  1. File exists and is valid YAML
  2. Each rule has required fields: id, title, pattern, severity
  3. Severity is one of: low, medium, high, critical
  4. Pattern is a valid regex (compiles without error)
  5. Languages field is present and non-empty
  6. Rule IDs are unique
  7. Rule IDs match pattern ^[A-Z][A-Z0-9]{2,}-[A-Z0-9]+$

Exit code is 0 if valid, 1 if invalid.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runRulesValidate,
}

func init() {
	rulesCmd.AddCommand(rulesValidateCmd)
}

// ruleValidationError is a single validation error for JSON output.
type ruleValidationError struct {
	RuleID string `json:"rule_id,omitempty"`
	Error  string `json:"error"`
}

// rulesValidateResult is the JSON-serializable result of 'rules validate'.
type rulesValidateResult struct {
	Valid   bool                 `json:"valid"`
	Path    string               `json:"path"`
	Rules   int                  `json:"rules"`
	Errors  []ruleValidationError `json:"errors,omitempty"`
}

// idPattern enforces the rule ID naming convention: uppercase alphanumeric
// segments separated by a single hyphen, e.g. CUSTOM-001, SQL-INJECTION.
var idPattern = regexp.MustCompile(`^[A-Z][A-Z0-9]{2,}-[A-Z0-9]+$`)

// validSeverities is the set of accepted severity values.
var validSeverities = map[string]bool{
	"low":      true,
	"medium":   true,
	"high":     true,
	"critical": true,
}

func runRulesValidate(cmd *cobra.Command, args []string) error {
	formatter := FormatterFromContext(cmd.Context())

	var path string
	if len(args) == 1 {
		path = args[0]
	} else {
		root, err := getProjectRoot()
		if err != nil {
			return formatter.PrintError(err)
		}
		path = root + "/.patchflow/rules.yaml"
	}

	result := rulesValidateResult{Path: path}

	// 1. File exists and is valid YAML.
	data, err := os.ReadFile(path)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, ruleValidationError{
			Error: fmt.Sprintf("failed to read file: %v", err),
		})
		return printValidateResult(formatter, result)
	}

	var ruleFile customrules.RuleFile
	if err := yaml.Unmarshal(data, &ruleFile); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, ruleValidationError{
			Error: fmt.Sprintf("invalid YAML: %v", err),
		})
		return printValidateResult(formatter, result)
	}

	result.Rules = len(ruleFile.Rules)

	if len(ruleFile.Rules) == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, ruleValidationError{
			Error: "no rules defined",
		})
		return printValidateResult(formatter, result)
	}

	// Track seen IDs for uniqueness check.
	seen := map[string]bool{}

	for i, r := range ruleFile.Rules {
		// Use index as a fallback label when ID is missing.
		label := r.ID
		if label == "" {
			label = fmt.Sprintf("rule[%d]", i)
		}

		// 2. Required fields: id, title, pattern, severity.
		if r.ID == "" {
			result.Errors = append(result.Errors, ruleValidationError{
				Error: fmt.Sprintf("rule at index %d: missing required field 'id'", i),
			})
		}
		if r.Title == "" {
			result.Errors = append(result.Errors, ruleValidationError{
				RuleID: label,
				Error:  "missing required field 'title'",
			})
		}
		if r.Pattern == "" {
			result.Errors = append(result.Errors, ruleValidationError{
				RuleID: label,
				Error:  "missing required field 'pattern'",
			})
		}
		if r.Severity == "" {
			result.Errors = append(result.Errors, ruleValidationError{
				RuleID: label,
				Error:  "missing required field 'severity'",
			})
		}

		// 3. Severity is one of: low, medium, high, critical.
		if r.Severity != "" && !validSeverities[r.Severity] {
			result.Errors = append(result.Errors, ruleValidationError{
				RuleID: label,
				Error:  fmt.Sprintf("invalid severity %q (must be one of: low, medium, high, critical)", r.Severity),
			})
		}

		// 4. Pattern is a valid regex.
		if r.Pattern != "" {
			if _, err := regexp.Compile(r.Pattern); err != nil {
				result.Errors = append(result.Errors, ruleValidationError{
					RuleID: label,
					Error:  fmt.Sprintf("invalid regex pattern: %v", err),
				})
			}
		}

		// 5. Languages field is present and non-empty.
		if len(r.Languages) == 0 {
			result.Errors = append(result.Errors, ruleValidationError{
				RuleID: label,
				Error:  "missing or empty required field 'languages'",
			})
		}

		// 6. Rule IDs are unique.
		if r.ID != "" {
			if seen[r.ID] {
				result.Errors = append(result.Errors, ruleValidationError{
					RuleID: r.ID,
					Error:  "duplicate rule ID",
				})
			}
			seen[r.ID] = true
		}

		// 7. Rule IDs match the naming convention.
		if r.ID != "" && !idPattern.MatchString(r.ID) {
			result.Errors = append(result.Errors, ruleValidationError{
				RuleID: r.ID,
				Error:  "rule ID must match pattern ^[A-Z][A-Z0-9]{2,}-[A-Z0-9]+$ (uppercase with hyphens)",
			})
		}
	}

	result.Valid = len(result.Errors) == 0
	return printValidateResult(formatter, result)
}

func printValidateResult(formatter output.Formatter, result rulesValidateResult) error {
	if output.IsJSON(formatter) {
		return formatter.Print(result)
	}

	if result.Valid {
		_ = formatter.PrintSuccess(fmt.Sprintf("%d rules validated successfully", result.Rules))
		_ = formatter.Print("  File: " + result.Path)
		return nil
	}

	_ = formatter.Print("Validation failed for " + result.Path)
	_ = formatter.Print("")
	for _, e := range result.Errors {
		if e.RuleID != "" {
			_ = formatter.Print(fmt.Sprintf("  [%s] %s", e.RuleID, e.Error))
		} else {
			_ = formatter.Print("  " + e.Error)
		}
	}
	_ = formatter.Print("")
	_ = formatter.Print(fmt.Sprintf("%d error(s) found.", len(result.Errors)))
	// Signal failure to cobra so the process exits with code 1.
	return fmt.Errorf("rules validation failed: %d error(s)", len(result.Errors))
}
