package cmd

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/patchflow/patchflow-cli/internal/output"
	"github.com/patchflow/patchflow-cli/internal/rules"
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

var rulesMaturityCmd = &cobra.Command{
	Use:   "maturity",
	Short: "Show rule governance maturity coverage report",
	Long: `Show a governance coverage report for all registered rules.

The report includes:
  - Maturity level distribution (experimental, beta, stable, enterprise)
  - Blocking-eligible vs excluded rule counts
  - CWE and OWASP mapping coverage
  - Profile activation counts (dev, pr, ci, audit)
  - Per-engine rule counts

Use --json for machine-readable output.
Use --all to list every rule with its maturity, CWE, and blocking status.`,
	Run: runRulesMaturity,
}

var rulesDocsCmd = &cobra.Command{
	Use:   "docs",
	Short: "Generate rule documentation",
	Long: `Generate documentation for all registered rules.

Outputs a Markdown document with one section per rule, including:
  - Rule ID, title, severity, confidence
  - Maturity level and blocking eligibility
  - CWE and OWASP mapping
  - Security category
  - Fix recommendation
  - Active scan profiles

Use --output <file> to write to a file (stdout if omitted).
Use --engine <name> to filter to a specific engine.`,
	Run: runRulesDocs,
}

var (
	rulesListJSON     bool
	rulesListAll      bool
	rulesMaturityJSON bool
	rulesMaturityAll  bool
	rulesDocsOutput   string
	rulesDocsEngine   string
)

func init() {
	rootCmd.AddCommand(rulesCmd)
	rulesCmd.AddCommand(rulesListCmd)
	rulesCmd.AddCommand(rulesMaturityCmd)
	rulesCmd.AddCommand(rulesDocsCmd)
	rulesListCmd.Flags().BoolVar(&rulesListJSON, "json", false, "Output in JSON format")
	rulesListCmd.Flags().BoolVar(&rulesListAll, "all", false, "Show all rules (default: summary only)")
	rulesListCmd.Flags().StringVar(&scanRulesPath, "rules", "", "Path to custom rules YAML file")
	rulesMaturityCmd.Flags().BoolVar(&rulesMaturityJSON, "json", false, "Output in JSON format")
	rulesMaturityCmd.Flags().BoolVar(&rulesMaturityAll, "all", false, "List every rule with maturity and CWE")
	rulesDocsCmd.Flags().StringVar(&rulesDocsOutput, "output", "", "Write docs to file (stdout if omitted)")
	rulesDocsCmd.Flags().StringVar(&rulesDocsEngine, "engine", "", "Filter to a specific engine")
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

// runRulesMaturity implements `patchflow rules maturity`.
func runRulesMaturity(cmd *cobra.Command, _ []string) {
	formatter := FormatterFromContext(cmd.Context())
	registry := rules.BuildDefaultRegistry()
	report := registry.Coverage()

	if rulesMaturityJSON {
		printMaturityJSON(formatter, registry, report)
		return
	}

	printMaturityTable(formatter, registry, report)
}

func printMaturityTable(formatter output.Formatter, registry *rules.Registry, report rules.CoverageReport) {
	_ = formatter.Print("PatchFlow Rule Maturity Report")
	_ = formatter.Print("==============================")
	_ = formatter.Print("")
	_ = formatter.Print(fmt.Sprintf("Total rules: %d", report.TotalRules))
	_ = formatter.Print("")

	// Maturity distribution
	_ = formatter.Print("Maturity levels:")
	for _, m := range []rules.Maturity{rules.MaturityEnterprise, rules.MaturityStable, rules.MaturityBeta, rules.MaturityExperimental} {
		count := report.MaturityCounts[m.String()]
		_ = formatter.Print(fmt.Sprintf("  %-15s  %d", m.String(), count))
	}
	_ = formatter.Print("")

	// Blocking eligibility
	_ = formatter.Print("Blocking eligible:")
	_ = formatter.Print(fmt.Sprintf("  yes: %d", report.BlockingEligible))
	_ = formatter.Print(fmt.Sprintf("  no:  %d", report.BlockingExcluded))
	_ = formatter.Print("")

	// Coverage metrics
	cwePct := pct(report.CWEMapped, report.TotalRules)
	owaspPct := pct(report.OWASPMapped, report.TotalRules)
	_ = formatter.Print("Coverage:")
	_ = formatter.Print(fmt.Sprintf("  CWE mapped:    %d / %d (%s%%)", report.CWEMapped, report.TotalRules, cwePct))
	_ = formatter.Print(fmt.Sprintf("  OWASP mapped:  %d / %d (%s%%)", report.OWASPMapped, report.TotalRules, owaspPct))
	_ = formatter.Print("")

	// Profile activation
	_ = formatter.Print("Profile activation:")
	for _, p := range rules.AllProfiles() {
		count := report.ProfilesActive[p.String()]
		_ = formatter.Print(fmt.Sprintf("  %-8s  %d rules", p.String(), count))
	}
	_ = formatter.Print("")

	// Per-engine counts
	_ = formatter.Print("By engine:")
	for _, e := range []rules.Engine{rules.EngineGoSAST, rules.EngineTaintSSA, rules.EngineSecrets, rules.EngineTreeSitter, rules.EngineTaintPatterns, rules.EnginePatterns} {
		count := report.ByEngine[e.String()]
		if count > 0 {
			_ = formatter.Print(fmt.Sprintf("  %-20s  %d rules", e.String(), count))
		}
	}

	// Full listing if --all
	if rulesMaturityAll {
		_ = formatter.Print("")
		_ = formatter.Print("All rules:")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "  ID\tENGINE\tSEVERITY\tMATURITY\tCWE\tBLOCKING\tTITLE\n")
		fmt.Fprintf(w, "  --\t------\t--------\t--------\t---\t--------\t-----\n")
		for _, meta := range registry.All() {
			blocking := "no"
			if meta.BlockingEligible {
				blocking = "yes"
			}
			fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				meta.ID, meta.Engine, meta.Severity, meta.Maturity, meta.CWE, blocking, meta.Title)
		}
		w.Flush()
	}
}

func printMaturityJSON(formatter output.Formatter, registry *rules.Registry, report rules.CoverageReport) {
	type maturityJSON struct {
		TotalRules       int            `json:"total_rules"`
		MaturityCounts   map[string]int `json:"maturity_counts"`
		BlockingEligible int            `json:"blocking_eligible"`
		BlockingExcluded int            `json:"blocking_excluded"`
		CWEMapped        int            `json:"cwe_mapped"`
		CWEMissing       int            `json:"cwe_missing"`
		OWASPMapped      int            `json:"owasp_mapped"`
		ProfilesActive   map[string]int `json:"profiles_active"`
		ByEngine         map[string]int `json:"by_engine"`
		Rules            []rules.RuleMetadata `json:"rules,omitempty"`
	}

	out := maturityJSON{
		TotalRules:       report.TotalRules,
		MaturityCounts:   report.MaturityCounts,
		BlockingEligible: report.BlockingEligible,
		BlockingExcluded: report.BlockingExcluded,
		CWEMapped:        report.CWEMapped,
		CWEMissing:       report.CWEMissing,
		OWASPMapped:      report.OWASPMapped,
		ProfilesActive:   report.ProfilesActive,
		ByEngine:         report.ByEngine,
	}
	if rulesMaturityAll {
		out.Rules = registry.All()
	}

	_ = formatter.Print(out)
}

// runRulesDocs implements `patchflow rules docs`.
func runRulesDocs(cmd *cobra.Command, _ []string) {
	formatter := FormatterFromContext(cmd.Context())
	registry := rules.BuildDefaultRegistry()

	var allRules []rules.RuleMetadata
	if rulesDocsEngine != "" {
		allRules = registry.ByEngine(rules.Engine(rulesDocsEngine))
	} else {
		allRules = registry.All()
	}

	docs := generateRuleDocs(allRules)

	if rulesDocsOutput != "" {
		if err := os.WriteFile(rulesDocsOutput, []byte(docs), 0644); err != nil {
			_ = formatter.PrintError(fmt.Errorf("failed to write docs: %w", err))
			return
		}
		_ = formatter.PrintSuccess("Rule documentation written to " + rulesDocsOutput)
		return
	}

	_ = formatter.Print(docs)
}

func generateRuleDocs(allRules []rules.RuleMetadata) string {
	var sb strings.Builder

	sb.WriteString("# PatchFlow Rule Documentation\n\n")
	sb.WriteString(fmt.Sprintf("Generated from %d rules across %d scanner engines.\n\n", len(allRules), countEngines(allRules)))

	sb.WriteString("## Maturity Levels\n\n")
	sb.WriteString("| Level | Description |\n|-------|-------------|\n")
	sb.WriteString("| enterprise | Large regression corpus, framework-aware, low FP rate, default CI blocking |\n")
	sb.WriteString("| stable | Positive/negative/FP tests, CWE/OWASP mapping, can block PRs |\n")
	sb.WriteString("| beta | Basic tests and metadata, enabled in standard scans, not blocking |\n")
	sb.WriteString("| experimental | New rule, audit-only, never blocks |\n\n")

	sb.WriteString("## Scan Profiles\n\n")
	sb.WriteString("| Profile | Description |\n|---------|-------------|\n")
	sb.WriteString("| dev | Fast, high-confidence rules only (local development) |\n")
	sb.WriteString("| pr | Stable secrets + AST + high-confidence patterns (pull requests) |\n")
	sb.WriteString("| ci | All stable rules + beta as warnings (CI pipelines) |\n")
	sb.WriteString("| audit | All rules including experimental (security audits) |\n\n")

	// Group by engine
	byEngine := make(map[string][]rules.RuleMetadata)
	for _, meta := range allRules {
		byEngine[meta.Engine.String()] = append(byEngine[meta.Engine.String()], meta)
	}

	for _, engineName := range []string{"gosast-embedded", "taint-ssa", "secrets-embedded", "treesitter-ast", "taint-patterns", "patterns-embedded"} {
		engineRules, ok := byEngine[engineName]
		if !ok || len(engineRules) == 0 {
			continue
		}

		sb.WriteString(fmt.Sprintf("## %s (%d rules)\n\n", engineName, len(engineRules)))

		for _, meta := range engineRules {
			sb.WriteString(fmt.Sprintf("### %s — %s\n\n", meta.ID, meta.Title))
			sb.WriteString(fmt.Sprintf("- **Engine:** %s\n", meta.Engine))
			sb.WriteString(fmt.Sprintf("- **Severity:** %s\n", meta.Severity))
			if meta.Confidence != "" {
				sb.WriteString(fmt.Sprintf("- **Confidence:** %s\n", meta.Confidence))
			}
			if meta.Language != "" {
				sb.WriteString(fmt.Sprintf("- **Language:** %s\n", meta.Language))
			}
			sb.WriteString(fmt.Sprintf("- **Maturity:** %s\n", meta.Maturity))
			sb.WriteString(fmt.Sprintf("- **Category:** %s\n", meta.Category))
			if meta.CWE != "" {
				sb.WriteString(fmt.Sprintf("- **CWE:** %s\n", meta.CWE))
			}
			if meta.OWASP != "" {
				sb.WriteString(fmt.Sprintf("- **OWASP:** %s\n", meta.OWASP))
			}
			sb.WriteString(fmt.Sprintf("- **Blocking eligible:** %v\n", meta.BlockingEligible))
			if len(meta.Profiles) > 0 {
				profileStrs := make([]string, len(meta.Profiles))
				for i, p := range meta.Profiles {
					profileStrs[i] = p.String()
				}
				sb.WriteString(fmt.Sprintf("- **Profiles:** %s\n", strings.Join(profileStrs, ", ")))
			}
			if meta.Recommendation != "" {
				sb.WriteString(fmt.Sprintf("- **Fix:** %s\n", meta.Recommendation))
			}
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

func countEngines(rules []rules.RuleMetadata) int {
	seen := make(map[string]bool)
	for _, r := range rules {
		seen[r.Engine.String()] = true
	}
	return len(seen)
}

func pct(n, total int) string {
	if total == 0 {
		return "0"
	}
	return fmt.Sprintf("%d", n*100/total)
}
