package cmd

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/patchflow/patchflow-cli/internal/sast"
	"github.com/spf13/cobra"
)

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Manage and inspect SAST rules",
	Long:  `Manage and inspect security rules from the embedded SAST scanners.`,
}

var rulesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all registered SAST rules",
	Long: `List all security rules from the embedded SAST scanners.

Shows rules from:
  - gosast-embedded (Go AST-based rules ported from gosec)
  - secrets-embedded (regex-based secret detection patterns)
  - patterns-embedded (multi-language regex patterns for Python, JS/TS, Ruby, PHP)

Custom rules from .patchflow/rules.yaml are included if present.

Use --rules <path> to load custom rules from a specific file.
Use --json for machine-readable output.`,
	Run: runRulesList,
}

var (
	rulesListJSON bool
	rulesListAll  bool
)

func init() {
	rootCmd.AddCommand(rulesCmd)
	rulesCmd.AddCommand(rulesListCmd)
	rulesListCmd.Flags().BoolVar(&rulesListJSON, "json", false, "Output in JSON format")
	rulesListCmd.Flags().BoolVar(&rulesListAll, "all", false, "Show all rules (default: summary only)")
	rulesListCmd.Flags().StringVar(&scanRulesPath, "rules", "", "Path to custom rules YAML file")
}

func runRulesList(cmd *cobra.Command, args []string) {
	runner := sast.NewRunner()
	runner.CustomRulesPath = scanRulesPath

	// Load custom rules from the specified path or from .patchflow/rules.yaml
	cwd, _ := os.Getwd()
	if err := runner.LoadCustomRules(cwd); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to load custom rules: %v\n", err)
	}

	groups := runner.AllRules()

	if rulesListJSON {
		printRulesJSON(groups)
		return
	}

	printRulesTable(groups)
}

func printRulesTable(groups []sast.RuleGroup) {
	totalRules := 0
	for _, g := range groups {
		totalRules += g.RuleCount
	}

	fmt.Printf("PatchFlow SAST Rules\n")
	fmt.Printf("====================\n\n")
	fmt.Printf("Total rules: %d across %d scanners\n\n", totalRules, len(groups))

	for _, g := range groups {
		fmt.Printf("\n[%s] (%s) — %d rules\n", g.Scanner, g.Language, g.RuleCount)
		fmt.Printf("%s\n", strings.Repeat("-", len(fmt.Sprintf("[%s] (%s) — %d rules", g.Scanner, g.Language, g.RuleCount))))

		if !rulesListAll {
			// Summary only: show count by severity
			sevCount := map[string]int{}
			for _, r := range g.Rules {
				sevCount[r.Severity]++
			}
			for _, sev := range []string{"high", "medium", "low", "info"} {
				if c := sevCount[sev]; c > 0 {
					fmt.Printf("  %s: %d\n", sev, c)
				}
			}
			continue
		}

		// Full listing
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "  ID\tSEVERITY\tTITLE\n")
		fmt.Fprintf(w, "  --\t--------\t-----\n")
		for _, r := range g.Rules {
			fmt.Fprintf(w, "  %s\t%s\t%s\n", r.ID, r.Severity, r.Title)
		}
		w.Flush()
	}

	fmt.Printf("\nUse --all to see individual rule details\n")
}

func printRulesJSON(groups []sast.RuleGroup) {
	fmt.Println("{")
	fmt.Printf("  \"total_rules\": %d,\n", func() int {
		t := 0
		for _, g := range groups {
			t += g.RuleCount
		}
		return t
	}())
	fmt.Println("  \"scanners\": [")
	for i, g := range groups {
		fmt.Printf("    {\n")
		fmt.Printf("      \"scanner\": \"%s\",\n", g.Scanner)
		fmt.Printf("      \"language\": \"%s\",\n", g.Language)
		fmt.Printf("      \"rule_count\": %d,\n", g.RuleCount)
		fmt.Printf("      \"rules\": [")
		for j, r := range g.Rules {
			fmt.Printf("\n        {\"id\": \"%s\", \"title\": \"%s\", \"severity\": \"%s\"}", r.ID, escapeJSON(r.Title), r.Severity)
			if j < len(g.Rules)-1 {
				fmt.Printf(",")
			}
		}
		if len(g.Rules) > 0 {
			fmt.Printf("\n      ]\n")
		} else {
			fmt.Printf("]\n")
		}
		fmt.Printf("    }")
		if i < len(groups)-1 {
			fmt.Printf(",")
		}
		fmt.Println()
	}
	fmt.Println("  ]")
	fmt.Println("}")
}

func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return s
}
