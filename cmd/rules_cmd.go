package cmd

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/Patchflow-security/patchflow-cli/internal/frameworks"
	"github.com/Patchflow-security/patchflow-cli/internal/output"
	"github.com/Patchflow-security/patchflow-cli/internal/rules"
	"github.com/Patchflow-security/patchflow-cli/internal/rulesconfig"
	"github.com/Patchflow-security/patchflow-cli/internal/sast"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks/packs"
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
	rulesListJSON       bool
	rulesListAll        bool
	rulesListFrameworks []string
	rulesListMode       bool
	rulesMaturityJSON   bool
	rulesMaturityAll    bool
	rulesDocsOutput     string
	rulesDocsEngine     string
	rulesFrameworksJSON bool
)

var rulesFrameworksCmd = &cobra.Command{
	Use:   "list-frameworks",
	Short: "List all official embedded framework rule packs",
	Long: `List all official embedded framework rule packs and their detection status.

Shows:
  - Pack name and primary language
  - File and template extensions owned by the pack
  - Number of rules in the pack
  - Whether the pack would be auto-detected in the current project

Use --json for machine-readable output.`,
	Run: runRulesListFrameworks,
}

var rulesInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate a .patchflow/rules.yaml with all known rules commented out",
	Long: `Generate a .patchflow/rules.yaml configuration file with all registered rules
listed and commented out. Uncomment lines to override the default mode for a rule.

Modes:
  block  — finding is reported and fails CI (non-zero exit code)
  inform — finding is reported but does not fail CI
  off    — finding is suppressed entirely

Profiles:
  --profile starter         Stable high-confidence rules block, beta/experimental inform
  --profile strict          Stable + beta injection/auth-critical rules block
  --profile audit           Everything inform, nothing blocks
  --profile framework-heavy Enable framework packs and template rules
  --profile ci-blocking     Block on all high/critical findings (stable + beta)
  --profile enterprise      Stable rules block, beta inform, experimental off

The generated file also includes templates for custom rules, taint rules,
and framework pack controls.

If .patchflow/rules.yaml already exists, this command does nothing.`,
	Run: runRulesInit,
}

func init() {
	rulesInitCmd.Flags().String("profile", "", "Configuration profile: starter, strict, audit, framework-heavy, ci-blocking, enterprise")
}

func init() {
	rootCmd.AddCommand(rulesCmd)
	rulesCmd.AddCommand(rulesListCmd)
	rulesCmd.AddCommand(rulesMaturityCmd)
	rulesCmd.AddCommand(rulesDocsCmd)
	rulesCmd.AddCommand(rulesFrameworksCmd)
	rulesCmd.AddCommand(rulesInitCmd)
	rulesListCmd.Flags().BoolVar(&rulesListJSON, "json", false, "Output in JSON format")
	rulesListCmd.Flags().BoolVar(&rulesListAll, "all", false, "Show all rules (default: summary only)")
	rulesListCmd.Flags().StringVar(&scanRulesPath, "rules", "", "Path to custom rules YAML file")
	rulesListCmd.Flags().StringSliceVar(&rulesListFrameworks, "framework", nil, "Filter to one or more framework packs (repeat flag or use comma-separated values)")
	rulesListCmd.Flags().BoolVar(&rulesListMode, "mode", false, "Show effective mode (block/inform/off) for each rule based on .patchflow/rules.yaml and maturity defaults")
	rulesMaturityCmd.Flags().BoolVar(&rulesMaturityJSON, "json", false, "Output in JSON format")
	rulesMaturityCmd.Flags().BoolVar(&rulesMaturityAll, "all", false, "List every rule with maturity and CWE")
	rulesDocsCmd.Flags().StringVar(&rulesDocsOutput, "output", "", "Write docs to file (stdout if omitted)")
	rulesDocsCmd.Flags().StringVar(&rulesDocsEngine, "engine", "", "Filter to a specific engine")
	rulesFrameworksCmd.Flags().BoolVar(&rulesFrameworksJSON, "json", false, "Output in JSON format")
}

func runRulesList(cmd *cobra.Command, args []string) {
	// If --framework is set, list rules from the named framework pack only.
	if len(rulesListFrameworks) > 0 {
		printFrameworkRules(rulesListFrameworks, rulesListJSON)
		return
	}

	runner := sast.NewRunner()
	runner.CustomRulesPath = scanRulesPath

	// Load custom rules from the specified path or from .patchflow/rules.yaml
	cwd, _ := os.Getwd()
	if err := runner.LoadCustomRules(cwd); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to load custom rules: %v\n", err)
	}

	groups := runner.AllRules()

	// Append framework pack rules as an additional group.
	fwReg := packs.BuildDefaultRegistry()
	for _, p := range fwReg.All() {
		fwRules := p.Rules()
		entries := make([]sast.RuleEntry, 0, len(fwRules))
		for _, r := range fwRules {
			entries = append(entries, sast.RuleEntry{
				ID:       r.ID,
				Title:    r.Title,
				Severity: string(r.Severity),
			})
		}
		groups = append(groups, sast.RuleGroup{
			Scanner:   "framework-" + p.Name(),
			Language:  p.Language(),
			RuleCount: len(entries),
			Rules:     entries,
		})
	}

	if rulesListJSON {
		printRulesJSON(groups)
		return
	}

	if rulesListMode {
		printRulesModeTable(groups)
		return
	}

	printRulesTable(groups)
}

// printFrameworkRules lists the rules in one or more framework packs.
func printFrameworkRules(names []string, asJSON bool) {
	fwReg := packs.BuildDefaultRegistry()

	type frameworkRuleView struct {
		ID        string `json:"id"`
		Title     string `json:"title"`
		Severity  string `json:"severity"`
		CWE       string `json:"cwe"`
		MatchMode string `json:"match_mode"`
		Maturity  string `json:"maturity"`
	}
	type frameworkPackView struct {
		Framework string              `json:"framework"`
		Language  string              `json:"language"`
		RuleCount int                 `json:"rule_count"`
		Rules     []frameworkRuleView `json:"rules"`
	}

	var views []frameworkPackView
	for _, name := range names {
		p := fwReg.Get(name)
		if p == nil {
			fmt.Fprintf(os.Stderr, "Unknown framework pack: %s\n", name)
			fmt.Fprintf(os.Stderr, "Available packs: %s\n", strings.Join(fwReg.Names(), ", "))
			os.Exit(1)
		}
		fwRules := p.Rules()
		view := frameworkPackView{
			Framework: p.Name(),
			Language:  p.Language(),
			RuleCount: len(fwRules),
		}
		for _, r := range fwRules {
			view.Rules = append(view.Rules, frameworkRuleView{
				ID:        r.ID,
				Title:     r.Title,
				Severity:  string(r.Severity),
				CWE:       r.CWE,
				MatchMode: r.MatchMode.String(),
				Maturity:  r.Maturity.String(),
			})
		}
		views = append(views, view)
	}

	if asJSON {
		fmt.Print("{\"frameworks\":[")
		for i, view := range views {
			fmt.Printf("{\"framework\":\"%s\",\"language\":\"%s\",\"rule_count\":%d,\"rules\":[",
				view.Framework, view.Language, view.RuleCount)
			for j, r := range view.Rules {
				fmt.Printf("{\"id\":\"%s\",\"title\":\"%s\",\"severity\":\"%s\",\"cwe\":\"%s\",\"match_mode\":\"%s\",\"maturity\":\"%s\"}",
					r.ID, escapeJSON(r.Title), r.Severity, r.CWE, r.MatchMode, r.Maturity)
				if j < len(view.Rules)-1 {
					fmt.Print(",")
				}
			}
			fmt.Print("]}")
			if i < len(views)-1 {
				fmt.Print(",")
			}
		}
		fmt.Println("]}")
		return
	}

	for i, view := range views {
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("Framework Pack: %s (%s)\n", view.Framework, view.Language)
		fmt.Printf("Rules: %d\n\n", view.RuleCount)
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "  ID\tSEVERITY\tMATCH\tCWE\tMATURITY\tTITLE\n")
		fmt.Fprintf(w, "  --\t--------\t-----\t---\t--------\t-----\n")
		for _, r := range view.Rules {
			fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Severity, r.MatchMode, r.CWE, r.Maturity, r.Title)
		}
		w.Flush()
	}
}

// runRulesInit implements `patchflow rules init`.
func runRulesInit(cmd *cobra.Command, _ []string) {
	formatter := FormatterFromContext(cmd.Context())
	cwd, _ := os.Getwd()
	reg := buildGovernanceRegistry()
	profile, _ := cmd.Flags().GetString("profile")
	path, err := rulesconfig.InitConfig(cwd, reg, profile)
	if err != nil {
		_ = formatter.PrintError(fmt.Errorf("failed to create rules config: %w", err))
		return
	}
	_ = formatter.PrintSuccess("Created " + path)
	_ = formatter.Print("")
	if profile != "" {
		_ = formatter.Print(fmt.Sprintf("Profile: %s — see file header for what this means.", profile))
	} else {
		_ = formatter.Print("Edit the file to override rule modes (block/inform/off).")
	}
	_ = formatter.Print("Run 'patchflow rules list --mode' to see effective modes.")
}

// buildGovernanceRegistry builds the default rules registry and registers
// framework pack rules into it. This is the canonical way to construct a
// registry that includes both core scanner rules and framework rules.
func buildGovernanceRegistry() *rules.Registry {
	reg := rules.BuildDefaultRegistry()
	packs.RegisterFrameworkRules(reg)
	return reg
}

// runRulesListFrameworks implements `patchflow rules list-frameworks`.
func runRulesListFrameworks(cmd *cobra.Command, _ []string) {
	formatter := FormatterFromContext(cmd.Context())
	fwReg := packs.BuildDefaultRegistry()

	// Detect frameworks in the current project to show which packs would
	// activate automatically.
	cwd, _ := os.Getwd()
	detector := frameworks.NewDetector()
	detections := detector.Detect(cwd)
	detectedNames := map[string]bool{}
	for _, d := range detections.Frameworks {
		detectedNames[string(d.Name)] = true
	}

	packs := fwReg.All()
	if len(packs) == 0 {
		_ = formatter.Print("No framework packs registered.")
		return
	}

	if rulesFrameworksJSON {
		type frameworkInfo struct {
			Framework  string   `json:"framework"`
			Language   string   `json:"language"`
			RuleCount  int      `json:"rule_count"`
			Detected   bool     `json:"detected"`
			Extensions []string `json:"extensions"`
		}
		var out []frameworkInfo
		for _, p := range packs {
			exts := append([]string(nil), p.FileExtensions()...)
			exts = append(exts, p.TemplateExtensions()...)
			out = append(out, frameworkInfo{
				Framework:  p.Name(),
				Language:   p.Language(),
				RuleCount:  len(p.Rules()),
				Detected:   detectedNames[p.Name()],
				Extensions: exts,
			})
		}
		_ = formatter.Print(map[string]interface{}{"frameworks": out})
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "FRAMEWORK\tLANGUAGE\tRULES\tDETECTED\tEXTENSIONS\n")
	fmt.Fprintf(w, "---------\t--------\t-----\t--------\t----------\n")
	for _, p := range packs {
		detected := "no"
		if detectedNames[p.Name()] {
			detected = "yes"
		}
		exts := strings.Join(p.FileExtensions(), ", ")
		tmpls := strings.Join(p.TemplateExtensions(), ", ")
		if tmpls != "" {
			exts = exts + " | " + tmpls
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n", p.Name(), p.Language(), len(p.Rules()), detected, exts)
	}
	w.Flush()
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

// printRulesModeTable prints all rules with their effective mode (block/inform/off)
// based on .patchflow/rules.yaml overrides and maturity-based defaults.
func printRulesModeTable(groups []sast.RuleGroup) {
	cwd, _ := os.Getwd()
	cfg, _ := rulesconfig.LoadFromDir(cwd)
	resolver := rulesconfig.NewResolver(cfg, buildGovernanceRegistry())

	fmt.Printf("PatchFlow SAST Rules — Effective Modes\n")
	fmt.Printf("======================================\n\n")

	configuredCount := 0
	if cfg != nil {
		configuredCount = len(cfg.RuleModes)
	}
	fmt.Printf("Rules config: .patchflow/rules.yaml (%d explicit overrides)\n\n", configuredCount)

	for _, g := range groups {
		fmt.Printf("\n[%s] (%s) — %d rules\n", g.Scanner, g.Language, g.RuleCount)
		fmt.Printf("%s\n", strings.Repeat("-", len(fmt.Sprintf("[%s] (%s) — %d rules", g.Scanner, g.Language, g.RuleCount))))

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "  ID\tSEVERITY\tMODE\tSOURCE\tMATURITY\tTITLE\n")
		fmt.Fprintf(w, "  --\t--------\t----\t------\t--------\t-----\n")
		for _, r := range g.Rules {
			entry := resolver.Resolve(r.ID)
			modeStr := string(entry.Mode)
			if modeStr == "" {
				modeStr = "inform"
			}
			blockingStr := ""
			if entry.Blocking {
				blockingStr = " (blocking)"
			}
			fmt.Fprintf(w, "  %s\t%s\t%s%s\t%s\t%s\t%s\n",
				r.ID, r.Severity, modeStr, blockingStr, entry.Source, entry.Maturity, r.Title)
		}
		w.Flush()
	}

	if configuredCount == 0 {
		fmt.Printf("\nNo explicit overrides — all modes are maturity-based defaults.\n")
		fmt.Printf("Run 'patchflow rules init' to create a .patchflow/rules.yaml.\n")
	} else {
		fmt.Printf("\n%d rule(s) have explicit mode overrides in .patchflow/rules.yaml.\n", configuredCount)
	}
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
	registry := buildGovernanceRegistry()
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
		TotalRules       int                  `json:"total_rules"`
		MaturityCounts   map[string]int       `json:"maturity_counts"`
		BlockingEligible int                  `json:"blocking_eligible"`
		BlockingExcluded int                  `json:"blocking_excluded"`
		CWEMapped        int                  `json:"cwe_mapped"`
		CWEMissing       int                  `json:"cwe_missing"`
		OWASPMapped      int                  `json:"owasp_mapped"`
		ProfilesActive   map[string]int       `json:"profiles_active"`
		ByEngine         map[string]int       `json:"by_engine"`
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
	registry := buildGovernanceRegistry()

	var allRules []rules.RuleMetadata
	if rulesDocsEngine != "" {
		allRules = registry.ByEngine(rules.Engine(rulesDocsEngine))
	} else {
		allRules = registry.All()
	}

	docs := generateRuleDocs(allRules)

	if rulesDocsOutput != "" {
		if err := os.WriteFile(rulesDocsOutput, []byte(docs), 0600); err != nil {
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
