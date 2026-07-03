package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/baseline"
	"github.com/Patchflow-security/patchflow-cli/internal/cwe"
	"github.com/Patchflow-security/patchflow-cli/internal/exitcode"
	"github.com/Patchflow-security/patchflow-cli/internal/fixsnippet"
	fwpatterns "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks/packs"
	"github.com/Patchflow-security/patchflow-cli/internal/git"
	"github.com/Patchflow-security/patchflow-cli/internal/output"
	"github.com/Patchflow-security/patchflow-cli/internal/sast"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/customrules"
	"github.com/spf13/cobra"
)

var explainCmd = &cobra.Command{
	Use:   "explain [finding-id]",
	Short: "Explain a finding with evidence, fix hints, and suppression info",
	Long: `Explain a security finding in detail.

Shows:
  - What the issue is and why it's dangerous
  - Where the evidence is (file, line, code snippet)
  - How to fix it (with example code)
  - How to suppress it if it's a false positive
  - Whether it would block a PR (--fail-on)

The finding ID can be obtained from ` + "`patchflow scan run`" + ` output.
You can also use --file and --line to explain a finding at a specific location.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runExplain,
}

var (
	explainFile   string
	explainLine   int
	explainRuleID string
)

func init() {
	explainCmd.Flags().StringVar(&explainFile, "file", "", "Explain finding at this file path")
	explainCmd.Flags().IntVar(&explainLine, "line", 0, "Line number (use with --file)")
	explainCmd.Flags().StringVar(&explainRuleID, "rule", "", "Rule ID to explain (e.g., PY001, TS-JS004)")
	rootCmd.AddCommand(explainCmd)
}

func runExplain(cmd *cobra.Command, args []string) error {
	formatter := FormatterFromContext(cmd.Context())

	repo, _, err := git.DetectOrLocal()
	if err != nil {
		return formatter.PrintError(fmt.Errorf("failed to detect repository: %w", err))
	}

	// Mode 1: Explain by finding ID (from a previous scan)
	if len(args) == 1 {
		return explainByFindingID(formatter, repo.Root, args[0])
	}

	// Mode 2: Explain by file+line
	if explainFile != "" && explainLine > 0 {
		return explainByLocation(formatter, repo.Root, explainFile, explainLine, explainRuleID)
	}

	// Mode 3: Explain by rule ID only (show rule documentation)
	if explainRuleID != "" {
		return explainByRuleID(formatter, repo.Root, explainRuleID)
	}

	return formatter.PrintError(fmt.Errorf("provide a finding ID, or use --file and --line, or --rule"))
}

// explainByFindingID runs a scan and finds the matching finding by ID.
func explainByFindingID(formatter output.Formatter, root, findingID string) error {
	if !output.IsJSON(formatter) {
		_ = formatter.Print("Running scan to locate finding " + findingID + "...")
	}

	findings, _, err := runExplainScan(root)
	if err != nil {
		return formatter.PrintError(fmt.Errorf("scan failed: %w", err))
	}

	// Find the matching finding
	var target *analysis.Finding
	for i := range findings {
		if findings[i].ID == findingID || findings[i].RuleID == findingID {
			target = &findings[i]
			break
		}
	}

	if target == nil {
		return formatter.PrintError(fmt.Errorf("finding %q not found. Run 'patchflow scan run' to see current findings.", findingID))
	}

	return outputFindingExplanation(formatter, root, target)
}

// explainByLocation runs a scan and finds findings at the given file+line.
func explainByLocation(formatter output.Formatter, root, file string, line int, ruleID string) error {
	findings, _, err := runExplainScan(root)
	if err != nil {
		return formatter.PrintError(fmt.Errorf("scan failed: %w", err))
	}

	// Normalize the file path for comparison
	normalizedFile := filepath.ToSlash(strings.TrimPrefix(file, "./"))

	var matches []*analysis.Finding
	for i := range findings {
		fFile := filepath.ToSlash(strings.TrimPrefix(findings[i].FilePath, "./"))
		if strings.HasSuffix(fFile, normalizedFile) || fFile == normalizedFile {
			if line == 0 || findings[i].LineStart == line {
				if ruleID == "" || findings[i].RuleID == ruleID {
					matches = append(matches, &findings[i])
				}
			}
		}
	}

	if len(matches) == 0 {
		return formatter.PrintError(fmt.Errorf("no findings at %s:%d", file, line))
	}

	for _, m := range matches {
		if err := outputFindingExplanation(formatter, root, m); err != nil {
			return err
		}
	}
	return nil
}

// explainByRuleID shows rule documentation without running a scan.
func explainByRuleID(formatter output.Formatter, root, ruleID string) error {
	runner := sast.NewRunner()
	runner.RespectGitignore = true

	// Load project extensions (framework_extensions from .patchflow/rules.yaml)
	// to show additional sources/sinks/sanitizers/safe patterns in the explanation.
	projectExt := loadProjectExtensions(root)

	// First, check framework pack rules (they carry richer source/sink/
	// sanitizer metadata than the core RuleEntry).
	fwReg := packs.BuildDefaultRegistry()
	for _, p := range fwReg.All() {
		for _, r := range p.Rules() {
			if r.ID == ruleID {
				return outputFrameworkRuleExplanation(formatter, r, projectExt)
			}
		}
	}

	groups := runner.AllRules()
	for _, g := range groups {
		for _, r := range g.Rules {
			if r.ID == ruleID {
				// Look up fix snippet
				snippet := fixsnippet.ForRule(ruleID)

				if output.IsJSON(formatter) {
					result := map[string]interface{}{
						"rule_id":   r.ID,
						"title":     r.Title,
						"severity":  r.Severity,
						"scanner":   g.Scanner,
						"language":  g.Language,
						"fix_hint":  getFixHint(r.ID),
						"suppression": map[string]interface{}{
							"allowed": true,
							"format":  "// patchflow:ignore " + r.ID + " -- reason",
						},
					}
					if snippet != nil {
						result["fix_snippet"] = map[string]interface{}{
							"title":       snippet.Title,
							"language":    snippet.Language,
							"vulnerable":  snippet.Vulnerable,
							"fixed":       snippet.Fixed,
							"explanation": snippet.Explanation,
						}
					}
					return formatter.Print(result)
				}

				_ = formatter.Print("Rule: " + r.ID)
				_ = formatter.Print("  Title: " + r.Title)
				_ = formatter.Print("  Severity: " + r.Severity)
				_ = formatter.Print("  Scanner: " + g.Scanner)
				_ = formatter.Print("  Language: " + g.Language)
				if hint := getFixHint(r.ID); hint != "" {
					_ = formatter.Print("\n  Fix: " + hint)
				}
				if snippet != nil {
					_ = formatter.Print("")
					_ = formatter.Print("  Fix Suggestion:")
					_ = formatter.Print("    " + snippet.Title)
					_ = formatter.Print("")
					_ = formatter.Print("    Vulnerable code:")
					for _, line := range strings.Split(snippet.Vulnerable, "\n") {
						_ = formatter.Print("      " + line)
					}
					_ = formatter.Print("")
					_ = formatter.Print("    Fixed code:")
					for _, line := range strings.Split(snippet.Fixed, "\n") {
						_ = formatter.Print("      " + line)
					}
					_ = formatter.Print("")
					_ = formatter.Print("    Why: " + snippet.Explanation)
				}
				_ = formatter.Print("\n  Suppress: // patchflow:ignore " + r.ID + " -- reason")
				return nil
			}
		}
	}

	return formatter.PrintError(fmt.Errorf("rule %q not found. Run 'patchflow rules list' to see available rules.", ruleID))
}

// outputFrameworkRuleExplanation renders a typed framework rule with its
// source/sink/sanitizer metadata, making the scanner feel intelligent instead
// of like it found a string and got excited. If projectExt contains extensions
// for this rule's framework, they are displayed as "Project extensions".
func outputFrameworkRuleExplanation(formatter output.Formatter, r fwpatterns.FrameworkRule, projectExt map[string]fwpatterns.PackOverride) error {
	// Compute default mode from maturity + severity.
	defaultMode := defaultModeForMaturity(r.Maturity, r.Severity)

	// Get project extensions for this framework (if any)
	ext, hasExt := projectExt[r.Framework]

	if output.IsJSON(formatter) {
		result := map[string]interface{}{
			"rule_id":    r.ID,
			"title":      r.Title,
			"framework":  r.Framework,
			"language":   r.Language,
			"severity":   string(r.Severity),
			"confidence": string(r.Confidence),
			"cwe":        r.CWE,
			"owasp":      owaspCategoryForCWE(r.CWE),
			"match_mode": r.MatchMode.String(),
			"maturity":   r.Maturity.String(),
			"default_mode": defaultMode,
			"recommendation": r.Recommendation,
			"suppression": map[string]interface{}{
				"allowed": true,
				"format":  "// patchflow:ignore " + r.ID + " -- reason",
			},
		}
		if len(r.Sources) > 0 {
			result["sources"] = sourceNames(r.Sources)
		}
		if len(r.Sinks) > 0 {
			result["sinks"] = sinkNames(r.Sinks)
		}
		if len(r.Sanitizers) > 0 {
			result["sanitizers"] = sanitizerNames(r.Sanitizers)
		}
		if len(r.SafePatterns) > 0 {
			safePatterns := make([]map[string]string, 0, len(r.SafePatterns))
			for _, sp := range r.SafePatterns {
				safePatterns = append(safePatterns, map[string]string{
					"reason": sp.Reason,
				})
			}
			result["safe_patterns"] = safePatterns
		}
		// Show project extensions if present
		if hasExt {
			extInfo := map[string]interface{}{}
			if len(ext.Sources) > 0 {
				extInfo["additional_sources"] = sourceNames(ext.Sources)
			}
			if len(ext.Sinks) > 0 {
				extInfo["additional_sinks"] = sinkNames(ext.Sinks)
			}
			if len(ext.Sanitizers) > 0 {
				extInfo["additional_sanitizers"] = sanitizerNames(ext.Sanitizers)
			}
			if len(ext.SafePatterns) > 0 {
				safePatterns := make([]map[string]string, 0, len(ext.SafePatterns))
				for _, sp := range ext.SafePatterns {
					safePatterns = append(safePatterns, map[string]string{
						"reason": sp.Reason,
					})
				}
				extInfo["additional_safe_patterns"] = safePatterns
			}
			if len(extInfo) > 0 {
				result["project_extensions"] = extInfo
			}
		}
		return formatter.Print(result)
	}

	_ = formatter.Print("Rule: " + r.ID)
	_ = formatter.Print("  Framework:    " + r.Framework)
	_ = formatter.Print("  Title:        " + r.Title)
	_ = formatter.Print("  Severity:     " + string(r.Severity) + " (confidence: " + string(r.Confidence) + ")")
	_ = formatter.Print("  Language:     " + r.Language)
	_ = formatter.Print("  CWE:          " + r.CWE)
	if owasp := owaspCategoryForCWE(r.CWE); owasp != "" {
		_ = formatter.Print("  OWASP:        " + owasp)
	}
	_ = formatter.Print("  Match mode:   " + r.MatchMode.String())
	_ = formatter.Print("  Maturity:     " + r.Maturity.String())
	_ = formatter.Print("  Default mode: " + defaultMode)
	if len(r.Sources) > 0 {
		_ = formatter.Print("  Sources:      " + strings.Join(sourceNames(r.Sources), ", "))
	}
	if len(r.Sinks) > 0 {
		_ = formatter.Print("  Sinks:        " + strings.Join(sinkNames(r.Sinks), ", "))
	}
	if len(r.Sanitizers) > 0 {
		_ = formatter.Print("  Sanitizers:   " + strings.Join(sanitizerNames(r.Sanitizers), ", "))
	}
	if len(r.SafePatterns) > 0 {
		_ = formatter.Print("  Safe patterns:")
		for _, sp := range r.SafePatterns {
			_ = formatter.Print("    - " + sp.Reason)
		}
	}
	if r.Recommendation != "" {
		_ = formatter.Print("")
		_ = formatter.Print("  Fix: " + r.Recommendation)
	}
	// Show project extensions if present
	if hasExt {
		_ = formatter.Print("")
		_ = formatter.Print("  Project extensions:")
		if len(ext.Sources) > 0 {
			_ = formatter.Print("    Additional sources:")
			for _, s := range ext.Sources {
				name := s.FuncName
				if s.Annotation != "" {
					name = s.Annotation
				}
				_ = formatter.Print("      " + name)
			}
		}
		if len(ext.Sinks) > 0 {
			_ = formatter.Print("    Additional sinks:")
			for _, s := range ext.Sinks {
				_ = formatter.Print("      " + s.FuncName)
			}
		}
		if len(ext.Sanitizers) > 0 {
			_ = formatter.Print("    Additional sanitizers:")
			for _, s := range ext.Sanitizers {
				if s.FuncName != "" {
					_ = formatter.Print("      " + s.FuncName)
				}
			}
		}
		if len(ext.SafePatterns) > 0 {
			_ = formatter.Print("    Additional safe patterns:")
			for _, sp := range ext.SafePatterns {
				_ = formatter.Print("      - " + sp.Reason)
			}
		}
	}
	_ = formatter.Print("")
	_ = formatter.Print("  Suppress: // patchflow:ignore " + r.ID + " -- reason")
	_ = formatter.Print("  Override: In .patchflow/rules.yaml:")
	_ = formatter.Print("    rule_modes:")
	_ = formatter.Print("      " + r.ID + ": block  # or inform, off")
	return nil
}

// defaultModeForMaturity computes the default mode based on maturity and severity.
func defaultModeForMaturity(maturity fwpatterns.Maturity, severity analysis.Severity) string {
	switch maturity {
	case fwpatterns.MaturityExperimental:
		return "inform"
	case fwpatterns.MaturityBeta:
		return "inform"
	case fwpatterns.MaturityStable, fwpatterns.MaturityEnterprise:
		if severity == analysis.SeverityHigh || severity == analysis.SeverityCritical {
			return "block"
		}
		return "inform"
	}
	return "inform"
}

// loadProjectExtensions loads framework_extensions from .patchflow/rules.yaml
// and returns them as a map of framework name → PackOverride. Returns empty
// map if no extensions are configured or the file doesn't exist.
func loadProjectExtensions(root string) map[string]fwpatterns.PackOverride {
	result := make(map[string]fwpatterns.PackOverride)
	policy, err := customrules.LoadPolicyFromDir(root)
	if err != nil {
		return result
	}
	for name, override := range policy.FrameworkOverrides {
		// Only include overrides that have content (extensions or overrides)
		if len(override.Sources) > 0 || len(override.Sinks) > 0 ||
			len(override.Sanitizers) > 0 || len(override.SafePatterns) > 0 {
			result[name] = override
		}
	}
	return result
}

// owaspCategoryForCWE maps common CWEs to OWASP Top 10 categories.
func owaspCategoryForCWE(cwe string) string {
	switch cwe {
	case "CWE-79":
		return "A03:2021 - Injection (XSS)"
	case "CWE-89":
		return "A03:2021 - Injection (SQLi)"
	case "CWE-78":
		return "A03:2021 - Injection (OS Command)"
	case "CWE-94", "CWE-1336":
		return "A03:2021 - Injection (Template/SSTI)"
	case "CWE-918":
		return "A10:2021 - SSRF"
	case "CWE-601":
		return "A01:2021 - Broken Access Control (Open Redirect)"
	case "CWE-22":
		return "A01:2021 - Broken Access Control (Path Traversal)"
	case "CWE-639":
		return "A01:2021 - Broken Access Control (IDOR)"
	case "CWE-862":
		return "A01:2021 - Broken Access Control (Missing Auth)"
	case "CWE-400":
		return "A05:2021 - Security Misconfiguration (DoS)"
	case "CWE-489", "CWE-798":
		return "A05:2021 - Security Misconfiguration (Debug/Secrets)"
	case "CWE-922":
		return "A02:2021 - Cryptographic Failures (Insecure Storage)"
	case "CWE-502":
		return "A08:2021 - Software and Data Integrity Failures (Deserialization)"
	case "CWE-352":
		return "A01:2021 - Broken Access Control (CSRF)"
	}
	return ""
}

func sourceNames(srcs []fwpatterns.SourcePattern) []string {
	out := make([]string, 0, len(srcs))
	for _, s := range srcs {
		name := s.FuncName
		if s.Annotation != "" {
			name = s.Annotation
		}
		out = append(out, name)
	}
	return out
}

func sinkNames(sinks []fwpatterns.SinkPattern) []string {
	out := make([]string, 0, len(sinks))
	for _, s := range sinks {
		out = append(out, s.FuncName)
	}
	return out
}

func sanitizerNames(sanitizers []fwpatterns.SanitizerPattern) []string {
	out := make([]string, 0, len(sanitizers))
	for _, s := range sanitizers {
		if s.FuncName != "" {
			out = append(out, s.FuncName)
		}
	}
	return out
}

// runExplainScan runs a full SAST scan for the explain command.
func runExplainScan(root string) ([]analysis.Finding, string, error) {
	runner := sast.NewRunner()
	runner.RespectGitignore = true
	runner.Timeout = 120 * time.Second

	result, err := runner.Analyze(context.Background(), root)
	if err != nil {
		return nil, "", err
	}
	return result.Findings, "", nil
}

// outputFindingExplanation outputs a detailed finding explanation with CWE
// description, OWASP mapping, attack scenario, fix snippet, and references.
func outputFindingExplanation(formatter output.Formatter, root string, f *analysis.Finding) error {
	// Read the source code around the finding
	evidence := readEvidence(root, f.FilePath, f.LineStart)

	// Look up CWE info
	var cweInfo *cwe.CWEInfo
	if f.CWEID != "" {
		if info, ok := cwe.Lookup(f.CWEID); ok {
			cweInfo = &info
		}
	}

	// Look up fix snippet
	var snippet *fixsnippet.FixSnippet
	if f.RuleID != "" {
		snippet = fixsnippet.ForRule(f.RuleID)
	}

	// Look up framework rule metadata (sources/sinks/sanitizers) when the
	// finding came from a framework pack. The Analyzer field is
	// "framework-<name>" for framework findings.
	var fwRule *fwpatterns.FrameworkRule
	if strings.HasPrefix(f.Analyzer, "framework-") {
		fwReg := packs.BuildDefaultRegistry()
		for _, p := range fwReg.All() {
			for _, r := range p.Rules() {
				if r.ID == f.RuleID {
					fwRule = &r
					break
				}
			}
			if fwRule != nil {
				break
			}
		}
	}

	if output.IsJSON(formatter) {
		result := map[string]interface{}{
			"id":            f.ID,
			"rule_id":       f.RuleID,
			"title":         f.Title,
			"description":   f.Description,
			"severity":      string(f.Severity),
			"confidence":    string(f.Confidence),
			"scanner":       f.Analyzer,
			"file":          f.FilePath,
			"line":          f.LineStart,
			"evidence":      evidence,
			"fix_hint":      getFixHint(f.RuleID),
			"recommendation": f.Recommendation,
			"suppression": map[string]interface{}{
				"allowed": true,
				"format":  "// patchflow:ignore " + f.RuleID + " -- reason",
			},
		}
		if cweInfo != nil {
			result["cwe"] = map[string]interface{}{
				"id":             cweInfo.ID,
				"name":           cweInfo.Name,
				"description":    cweInfo.Description,
				"owasp_id":       cweInfo.OWASP.ID,
				"owasp_name":     cweInfo.OWASP.Name,
				"attack_scenario": cweInfo.AttackScenario,
				"references":     cweInfo.References,
			}
		}
		if snippet != nil {
			result["fix_snippet"] = map[string]interface{}{
				"title":       snippet.Title,
				"language":    snippet.Language,
				"vulnerable":  snippet.Vulnerable,
				"fixed":       snippet.Fixed,
				"explanation": snippet.Explanation,
			}
		}
		if fwRule != nil {
			fwCtx := map[string]interface{}{
				"framework":  fwRule.Framework,
				"match_mode": fwRule.MatchMode.String(),
				"maturity":   fwRule.Maturity.String(),
			}
			if len(fwRule.Sources) > 0 {
				fwCtx["sources"] = sourceNames(fwRule.Sources)
			}
			if len(fwRule.Sinks) > 0 {
				fwCtx["sinks"] = sinkNames(fwRule.Sinks)
			}
			if len(fwRule.Sanitizers) > 0 {
				fwCtx["sanitizers"] = sanitizerNames(fwRule.Sanitizers)
			}
			result["framework"] = fwCtx
		}
		return formatter.Print(result)
	}

	// Terminal output
	_ = formatter.Print("")
	_ = formatter.Print(fmt.Sprintf("Finding: %s", f.ID))
	_ = formatter.Print(fmt.Sprintf("  Rule:       %s — %s", f.RuleID, f.Title))
	_ = formatter.Print(fmt.Sprintf("  Severity:   %s (confidence: %s)", f.Severity, f.Confidence))
	_ = formatter.Print(fmt.Sprintf("  Scanner:    %s", f.Analyzer))
	_ = formatter.Print(fmt.Sprintf("  Location:   %s:%d", f.FilePath, f.LineStart))

	// Framework context (sources/sinks/sanitizers) for framework-pack findings.
	if fwRule != nil {
		_ = formatter.Print(fmt.Sprintf("  Framework:  %s (%s, %s)", fwRule.Framework, fwRule.MatchMode.String(), fwRule.Maturity.String()))
		if len(fwRule.Sources) > 0 {
			_ = formatter.Print("  Sources:    " + strings.Join(sourceNames(fwRule.Sources), ", "))
		}
		if len(fwRule.Sinks) > 0 {
			_ = formatter.Print("  Sinks:      " + strings.Join(sinkNames(fwRule.Sinks), ", "))
		}
		if len(fwRule.Sanitizers) > 0 {
			_ = formatter.Print("  Sanitizers: " + strings.Join(sanitizerNames(fwRule.Sanitizers), ", "))
		}
	}

	// CWE + OWASP mapping
	if cweInfo != nil {
		_ = formatter.Print("")
		_ = formatter.Print(fmt.Sprintf("  CWE:        %s — %s", cweInfo.ID, cweInfo.Name))
		_ = formatter.Print(fmt.Sprintf("  OWASP:      %s: %s", cweInfo.OWASP.ID, cweInfo.OWASP.Name))
		_ = formatter.Print("")
		_ = formatter.Print("  Description:")
		_ = formatter.Print("    " + cweInfo.Description)
		_ = formatter.Print("")
		_ = formatter.Print("  Attack Scenario:")
		_ = formatter.Print("    " + cweInfo.AttackScenario)
	} else if f.Description != "" {
		_ = formatter.Print("")
		_ = formatter.Print("  Description:")
		_ = formatter.Print("    " + f.Description)
	}

	// Evidence (source code)
	if evidence != "" {
		_ = formatter.Print("")
		_ = formatter.Print("  Evidence:")
		for _, line := range strings.Split(evidence, "\n") {
			_ = formatter.Print("    " + line)
		}
	}

	// Fix snippet (code-level fix with before/after)
	if snippet != nil {
		_ = formatter.Print("")
		_ = formatter.Print("  Fix Suggestion:")
		_ = formatter.Print("    " + snippet.Title)
		_ = formatter.Print("")
		_ = formatter.Print("    Vulnerable code:")
		for _, line := range strings.Split(snippet.Vulnerable, "\n") {
			_ = formatter.Print("      " + line)
		}
		_ = formatter.Print("")
		_ = formatter.Print("    Fixed code:")
		for _, line := range strings.Split(snippet.Fixed, "\n") {
			_ = formatter.Print("      " + line)
		}
		_ = formatter.Print("")
		_ = formatter.Print("    Why: " + snippet.Explanation)
	} else if hint := getFixHint(f.RuleID); hint != "" {
		_ = formatter.Print("")
		_ = formatter.Print("  Fix:")
		_ = formatter.Print("    " + hint)
	}

	// Recommendation
	if f.Recommendation != "" {
		_ = formatter.Print("")
		_ = formatter.Print("  Recommendation:")
		_ = formatter.Print("    " + f.Recommendation)
	}

	// References
	if cweInfo != nil && len(cweInfo.References) > 0 {
		_ = formatter.Print("")
		_ = formatter.Print("  References:")
		for _, ref := range cweInfo.References {
			_ = formatter.Print("    - " + ref)
		}
	}

	// Suppression
	_ = formatter.Print("")
	_ = formatter.Print("  Suppress:")
	_ = formatter.Print(fmt.Sprintf("    // patchflow:ignore %s -- false positive: <reason>", f.RuleID))
	_ = formatter.Print("")

	return nil
}

// readEvidence reads the source code around a finding location.
func readEvidence(root, filePath string, line int) string {
	absPath := filePath
	if !filepath.IsAbs(absPath) {
		absPath = filepath.Join(root, filePath)
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		return ""
	}

	lines := strings.Split(string(data), "\n")
	start := line - 2
	end := line + 2
	if start < 0 {
		start = 0
	}
	if end >= len(lines) {
		end = len(lines) - 1
	}

	var sb strings.Builder
	for i := start; i <= end; i++ {
		marker := "  "
		if i+1 == line {
			marker = "> "
		}
		if i < len(lines) {
			sb.WriteString(fmt.Sprintf("%s%d: %s\n", marker, i+1, lines[i]))
		}
	}
	return strings.TrimSuffix(sb.String(), "\n")
}

// getFixHint returns a fix hint for a given rule ID.
func getFixHint(ruleID string) string {
	hints := map[string]string{
		// Python
		"PY001":  "Use ast.literal_eval() instead of eval() for safe evaluation of literals.",
		"PY002":  "Use subprocess with shell=False and pass arguments as a list: subprocess.run(['cmd', 'arg1'], shell=False)",
		"PY003":  "Use subprocess.run() with a list of arguments instead of shell=True.",
		"PY005":  "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
		"PY006":  "Use os.path.join() and validate paths against a base directory.",
		"PY007":  "Use hashlib.sha256() or similar for password hashing instead of MD5/SHA1.",
		"PY008":  "Use secrets.token_urlsafe() or os.urandom() instead of random for security-sensitive values.",
		"PY010":  "Use pickle only with trusted data. Consider JSON for untrusted input.",
		"PY011":  "Use yaml.safe_load() instead of yaml.load().",
		"PY012":  "Use a verified XML parser with defusedxml to prevent XXE attacks.",
		"PY013":  "Use parameterized queries with the database driver's escape functions.",
		// JS/TS
		"JS001":  "Avoid eval(). If necessary, use Function() with strict mode or a sandbox.",
		"JS002":  "Use child_process.execFile() with argument arrays instead of exec() with shell strings.",
		"JS003":  "Use parameterized queries: db.query('SELECT * FROM users WHERE id = $1', [userId])",
		"JS004":  "Avoid dangerouslySetInnerHTML. Use DOMPurify to sanitize HTML before rendering.",
		"JS005":  "Use bcrypt or argon2 for password hashing instead of MD5/SHA1.",
		"JS006":  "Use crypto.randomBytes() instead of Math.random() for security-sensitive values.",
		"JS007":  "Set 'HttpOnly; Secure; SameSite=Strict' on cookie attributes.",
		// Go
		"G104":   "Check errors from all function calls, especially in security-critical paths.",
		"G107":   "Do not pass user input to http.Get URLs. Validate and restrict allowed hosts.",
		"G204":   "Use exec.Command with argument lists, never shell=True or user input in cmd string.",
		// Secrets
		"SECRET-AWS-Access-Key":          "Rotate the key immediately. Use IAM roles or environment variables instead.",
		"SECRET-AWS-Secret-Access-Key":   "Rotate the key immediately. Use IAM roles or environment variables instead.",
		"SECRET-GitHub-Token":            "Revoke the token. Use GitHub Actions secrets or OIDC instead.",
		"SECRET-Database-Connection-URL": "Use environment variables or a secrets manager. Never commit connection strings.",
		"SECRET-Private-Key":             "Rotate the key. Use a secrets manager or key management service.",
		// Taint patterns
		"TP-PY001": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
		"TP-PY002": "Use subprocess with shell=False and argument lists.",
		"TP-PY003": "Validate file paths with os.path.abspath() and check against a base directory.",
		"TP-PY004": "Validate URLs against an allowlist of permitted hosts.",
		"TP-PY005": "Avoid eval()/exec() with untrusted input. Use ast.literal_eval() for literals.",
		"TP-PY006": "Enable auto-escaping in templates. Use Jinja2's |e filter or markupsafe.escape().",
		"TP-JS001": "Use parameterized queries: db.query('SELECT * FROM users WHERE id = $1', [userId])",
		"TP-JS002": "Use execFile() with argument arrays instead of exec() with shell strings.",
		"TP-JS003": "Use proper output encoding. Avoid string concatenation in HTML responses.",
		"TP-JS004": "Use path.resolve() and validate against a base directory.",
		"TP-JS005": "Validate URLs against an allowlist of permitted hosts.",
		"TP-JS006": "Avoid eval() and new Function() with untrusted input.",
		"TP-JS007": "Validate redirect URLs against an allowlist. Reject absolute URLs from user input.",
	}
	return hints[ruleID]
}

// Ensure unused imports are referenced
var _ = exitcode.Success
var _ = baseline.NewManager
