package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/patchflow/patchflow-cli/internal/analysis"
	"github.com/patchflow/patchflow-cli/internal/baseline"
	"github.com/patchflow/patchflow-cli/internal/exitcode"
	"github.com/patchflow/patchflow-cli/internal/git"
	"github.com/patchflow/patchflow-cli/internal/output"
	"github.com/patchflow/patchflow-cli/internal/reachability"
	"github.com/patchflow/patchflow-cli/internal/report"
	"github.com/patchflow/patchflow-cli/internal/risk"
	"github.com/patchflow/patchflow-cli/internal/sast"
	"github.com/patchflow/patchflow-cli/internal/sca"
	osvclient "github.com/patchflow/patchflow-cli/internal/osv"
	"github.com/spf13/cobra"
)

var (
	scanProfile        string
	scanNoSAST         bool
	scanNoSecrets      bool
	scanNoReach        bool
	scanOutput         string
	scanFormat         string
	scanChangedOnly    bool
	scanShowSuppressed bool
	scanRulesPath      string
	scanIncludeTests   bool
	scanNoGitignore    bool
	scanIncremental    bool
	scanNewOnly        bool
	scanFailOn         string
	scanSince          string
	scanBaselineName   string
)

var scanRealCmd = &cobra.Command{
	Use:   "run",
	Short: "Run a full security analysis (SCA + SAST + reachability + risk)",
	Long: `Run a comprehensive local security analysis on the current repository.
This performs Software Composition Analysis (SCA) via OSV.dev, Static Analysis
Security Testing (SAST) via embedded scanners (Go SAST, secret scanner, multi-language
pattern scanner) plus external tools when available (gosec, bandit, semgrep, gitleaks),
reachability analysis, and computes a risk score.

No backend connection required — all analysis runs locally.
Embedded scanners require zero installation; external tools supplement when installed.`,
	RunE: runScanReal,
}

func init() {
	scanRealCmd.Flags().StringVar(&scanProfile, "profile", "standard", "Scan profile: quick, standard, deep")
	scanRealCmd.Flags().BoolVar(&scanNoSAST, "no-sast", false, "Skip SAST analysis")
	scanRealCmd.Flags().BoolVar(&scanNoSecrets, "no-secrets", false, "Skip secret detection")
	scanRealCmd.Flags().BoolVar(&scanNoReach, "no-reachability", false, "Skip reachability analysis")
	scanRealCmd.Flags().StringVar(&scanFormat, "format", "", "Output format for report file: markdown, json, sarif")
	scanRealCmd.Flags().StringVar(&scanOutput, "output", "", "Write report to file (stdout if omitted)")
	scanRealCmd.Flags().BoolVar(&scanChangedOnly, "changed-only", false, "Only analyze changed files")
	scanRealCmd.Flags().BoolVar(&scanShowSuppressed, "show-suppressed", false, "Show findings suppressed by //patchflow:ignore comments")
	scanRealCmd.Flags().StringVar(&scanRulesPath, "rules", "", "Path to custom rules YAML file (default: .patchflow/rules.yaml)")
	scanRealCmd.Flags().BoolVar(&scanIncludeTests, "include-tests", false, "Include test files in SAST analysis")
	scanRealCmd.Flags().BoolVar(&scanNoGitignore, "no-gitignore", false, "Do not respect .gitignore patterns (scan all files)")
	scanRealCmd.Flags().BoolVar(&scanIncremental, "incremental", false, "Only re-scan files changed since last scan (uses .patchflow/cache/sast_state.json)")
	scanRealCmd.Flags().BoolVar(&scanNewOnly, "new-only", false, "Only report findings not in the baseline (requires --baseline)")
	scanRealCmd.Flags().StringVar(&scanFailOn, "fail-on", "", "Fail (exit code 1) if findings at or above this severity: low, medium, high, critical")
	scanRealCmd.Flags().StringVar(&scanSince, "since", "", "Scan files changed since the given branch/commit (e.g., --since main)")
	scanRealCmd.Flags().StringVar(&scanBaselineName, "baseline", "", "Baseline name to compare against (used with --new-only)")

	scanCmd.AddCommand(scanRealCmd)
}

func runScanReal(cmd *cobra.Command, _ []string) error {
	formatter := FormatterFromContext(cmd.Context())
	ctx := cmd.Context()

	// Detect project context. Full scans support non-git directories; diff-only
	// scans still require git metadata.
	repo, isGitRepo, err := git.DetectOrLocal()
	if err != nil {
		return formatter.PrintError(err)
	}
	if isGitRepo {
		_ = repo.DetectChangedFiles()
		_ = repo.DetectDiffStats()
		// --since <branch> implies changed-only mode with a specific base
		if scanSince != "" {
			scanChangedOnly = true
		}
	} else if scanChangedOnly || scanSince != "" {
		return formatter.PrintError(fmt.Errorf("--changed-only/--since requires a git repository"))
	} else if !output.IsJSON(formatter) {
		_ = formatter.Print("Non-git directory detected; running full-project scan.")
	}

	started := time.Now()
	var engineTimings []analysis.EngineTiming

	// 1. SCA Analysis
	if !output.IsJSON(formatter) {
		_ = formatter.Print("Running SCA analysis (OSV.dev)...")
	}
	scaStart := time.Now()
	scaAnalyzer := sca.NewAnalyzer()
	if scanChangedOnly {
		scaAnalyzer.ChangedOnly = true
		scaAnalyzer.ChangedFiles = repo.ChangedFiles
	}
	switch scanProfile {
	case "quick":
		scaAnalyzer.MaxDepth = 1
	case "deep":
		scaAnalyzer.MaxDepth = 5
	default:
		scaAnalyzer.MaxDepth = 3
	}

	// Wire up OSV response cache so repeated scans skip API calls for
	// unchanged dependencies. Cache lives at {root}/.patchflow/cache/osv/.
	osvCache := osvclient.NewCache(repo.Root)
	scaAnalyzer.OSV.SetCache(osvCache)

	scaResult, err := scaAnalyzer.Analyze(ctx, repo.Root)
	if err != nil {
		return formatter.PrintError(fmt.Errorf("SCA analysis failed: %w", err))
	}
	engineTimings = append(engineTimings, analysis.EngineTiming{
		Engine: "osv-sca", Duration: time.Since(scaStart), Findings: len(scaResult.Findings),
	})

	// 2. SAST Analysis
	var sastResult *sast.Result
	var allFindings []analysis.Finding
	allFindings = append(allFindings, scaResult.Findings...)

	analyzersRun := []string{"osv"}

	if !scanNoSAST || !scanNoSecrets {
		if !output.IsJSON(formatter) {
			_ = formatter.Print("Running SAST analysis (local tools)...")
		}
		sastStart := time.Now()
		sastRunner := sast.NewRunner()
		if scanChangedOnly {
			sastRunner.ChangedOnly = true
			sastRunner.ChangedFiles = repo.ChangedFiles
		}
		sastRunner.IncludeTests = scanIncludeTests

		// Wire embedded scanner flags based on --no-sast / --no-secrets
		if scanNoSAST {
			sastRunner.NoEmbeddedGo = true
			sastRunner.NoEmbeddedPatterns = true
		}
		if scanNoSecrets {
			sastRunner.NoEmbeddedSecrets = true
		}
		sastRunner.ShowSuppressed = scanShowSuppressed
		sastRunner.CustomRulesPath = scanRulesPath
		sastRunner.RespectGitignore = !scanNoGitignore
		sastRunner.IncrementalScan = scanIncremental

		// Profile-aware SAST: adjust scanner selection and timeouts per profile.
		// quick: skip taint and tree-sitter for fast CI feedback (~2x faster)
		// standard: all scanners with default 120s timeout
		// deep: all scanners with 10-minute timeout for thorough analysis
		switch scanProfile {
		case "quick":
			sastRunner.NoEmbeddedTaint = true
			sastRunner.NoEmbeddedTreeSitter = true
			sastRunner.NoEmbeddedTaintPatterns = true
			sastRunner.Timeout = 60 * time.Second
			// Quick profile: skip slow external tools (semgrep, bandit)
			var quickTools []sast.Tool
			for _, t := range sastRunner.Tools {
				if t.Name == "gosec" || t.Name == "gitleaks" {
					quickTools = append(quickTools, t)
				}
			}
			sastRunner.Tools = quickTools
		case "deep":
			sastRunner.Timeout = 10 * time.Minute
		default: // standard
			sastRunner.Timeout = 120 * time.Second
		}

		// Filter external tools based on flags
		if scanNoSAST && !scanNoSecrets {
			// Only keep gitleaks (external secret scanner)
			var filtered []sast.Tool
			for _, t := range sastRunner.Tools {
				if t.Name == "gitleaks" {
					filtered = append(filtered, t)
				}
			}
			sastRunner.Tools = filtered
		} else if !scanNoSAST && scanNoSecrets {
			// Remove gitleaks
			var filtered []sast.Tool
			for _, t := range sastRunner.Tools {
				if t.Name != "gitleaks" {
					filtered = append(filtered, t)
				}
			}
			sastRunner.Tools = filtered
		} else if scanNoSAST && scanNoSecrets {
			sastRunner.Tools = nil
		}

		sastResult, err = sastRunner.Analyze(ctx, repo.Root)
		if err != nil {
			return formatter.PrintError(fmt.Errorf("SAST analysis failed: %w", err))
		}
		engineTimings = append(engineTimings, analysis.EngineTiming{
			Engine: "sast", Duration: time.Since(sastStart), Findings: len(sastResult.Findings),
		})
		allFindings = append(allFindings, sastResult.Findings...)
		analyzersRun = append(analyzersRun, sastResult.ToolsRun...)
	}

	// 3. Reachability Analysis
	if !scanNoReach && len(scaResult.Findings) > 0 {
		if !output.IsJSON(formatter) {
			_ = formatter.Print("Running reachability analysis...")
		}
		reachStart := time.Now()
		reachAnalyzer := reachability.NewAnalyzer()
		reachResult, err := reachAnalyzer.Analyze(ctx, repo.Root, allFindings, scaResult.Dependencies)
		if err != nil {
			// Non-fatal — continue without reachability data
			if !output.IsJSON(formatter) {
				_ = formatter.Print("  (reachability analysis skipped: " + err.Error() + ")")
			}
		} else {
			allFindings = reachResult.Findings
			engineTimings = append(engineTimings, analysis.EngineTiming{
				Engine: "reachability", Duration: time.Since(reachStart), Findings: len(allFindings),
			})
		}
	}

	// 4. Risk Scoring
	riskEngine := risk.NewEngine()
	riskScore := riskEngine.Compute(risk.ScoreInput{
		Findings:               allFindings,
		FilesChanged:           len(repo.ChangedFiles),
		AddedLines:             repo.AddedLines,
		DeletedLines:           repo.DeletedLines,
		DependencyFilesChanged: hasDependencyFiles(repo.ChangedFiles),
		CIWorkflowChanged:      hasCIWorkflow(repo.ChangedFiles),
		AuthFilesChanged:       hasAuthFiles(repo.ChangedFiles),
	})

	completed := time.Now()

	// Build analysis result
	manifestPaths := make([]string, 0, len(scaResult.Manifests))
	for _, m := range scaResult.Manifests {
		manifestPaths = append(manifestPaths, m.Path)
	}

	result := &analysis.AnalysisResult{
		ProjectRoot:   repo.Root,
		Branch:        repo.CurrentBranch,
		CommitSHA:     repo.CommitSHA,
		BaseBranch:    repo.BaseBranch,
		StartedAt:     started,
		CompletedAt:   completed,
		Findings:      allFindings,
		Dependencies:  scaResult.Dependencies,
		RiskScore:     riskScore.Score,
		RiskLevel:     riskScore.Level,
		FilesChanged:  len(repo.ChangedFiles),
		AddedLines:    repo.AddedLines,
		DeletedLines:  repo.DeletedLines,
		Manifests:     manifestPaths,
		Analyzers:     analyzersRun,
		EngineTimings: engineTimings,
	}

	// 5. Output
	gen := report.NewGenerator(result, &riskScore)

	// Write report file if requested
	if scanFormat != "" || scanOutput != "" {
		fmtStr := scanFormat
		if fmtStr == "" {
			fmtStr = "json"
		}
		if scanOutput != "" {
			if err := gen.WriteFile(fmtStr, scanOutput); err != nil {
				return formatter.PrintError(fmt.Errorf("failed to write report: %w", err))
			}
			if !output.IsJSON(formatter) {
				_ = formatter.PrintSuccess("Report written to " + scanOutput)
			}
		}
	}

	// Auto-save a markdown report to .patchflow/reports/ for full scans, even in
	// non-git directories, so users always have a persistent artifact to share.
	if !output.IsJSON(formatter) {
		if writtenPath, err := gen.WriteToReportsDir(repo.Root, "markdown"); err == nil {
			_ = formatter.Print("  Report saved: " + writtenPath)
		}
	}

	if output.IsJSON(formatter) {
		// For JSON mode, output the full result
		return formatter.Print(struct {
			*analysis.AnalysisResult `json:"analysis"`
			Risk                     *risk.ScoreOutput `json:"risk"`
		}{
			AnalysisResult: result,
			Risk:           &riskScore,
		})
	}

	// Terminal summary
	_ = formatter.Print(gen.TerminalSummary())

	// --new-only: filter findings against baseline, show only new ones
	if scanNewOnly && scanBaselineName != "" {
		mgr := baseline.NewManager(repo.Root)
		diff, err := mgr.Compare(scanBaselineName, allFindings)
		if err != nil {
			return formatter.PrintError(fmt.Errorf("baseline comparison failed: %w", err))
		}
		_ = formatter.Print(fmt.Sprintf("\nBaseline: %s — New: %d, Resolved: %d, Unchanged: %d",
			scanBaselineName, diff.NewCount, diff.ResolvedCount, diff.UnchangedCount))
		if diff.NewCount > 0 {
			_ = formatter.Print("\nNew findings:")
			for _, f := range diff.New {
				_ = formatter.Print(fmt.Sprintf("  [%s] %s:%d — %s", f.RuleID, f.FilePath, f.LineStart, f.Title))
			}
		}
		// Replace allFindings with just new findings for fail-on check
		allFindings = diff.New
	}

	// --fail-on: exit with code 1 if findings at or above the severity threshold exist
	if scanFailOn != "" {
		threshold := parseSeverityThreshold(scanFailOn)
		blockingCount := 0
		for _, f := range allFindings {
			if severityRank(f.Severity) >= threshold {
				blockingCount++
			}
		}
		if blockingCount > 0 {
			return &ExitError{
				Code: exitcode.FindingsFound,
				Msg:  fmt.Sprintf("%d finding(s) at or above %s severity", blockingCount, scanFailOn),
			}
		}
	}

	return nil
}

func hasDependencyFiles(files []string) bool {
	for _, f := range files {
		name := f
		if idx := len(f); idx > 0 {
			// Get basename
			for i := len(f) - 1; i >= 0; i-- {
				if f[i] == '/' {
					name = f[i+1:]
					break
				}
			}
		}
		switch name {
		case "go.mod", "package.json", "requirements.txt", "pyproject.toml",
			"Cargo.toml", "Gemfile", "Gemfile.lock", "composer.json",
			"pom.xml", "build.gradle", "package-lock.json", "yarn.lock", "pnpm-lock.yaml":
			return true
		}
	}
	return false
}

func hasCIWorkflow(files []string) bool {
	for _, f := range files {
		if contains(f, ".github/workflows/") || contains(f, ".gitlab-ci.yml") ||
			contains(f, "Jenkinsfile") || contains(f, ".circleci/") {
			return true
		}
	}
	return false
}

func hasAuthFiles(files []string) bool {
	for _, f := range files {
		lower := toLower(f)
		for _, p := range []string{"auth", "login", "session", "jwt", "oauth", "password", "credential"} {
			if contains(lower, p) {
				return true
			}
		}
	}
	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 32
		}
	}
	return string(b)
}

// getRepoRoot returns the root of the current git repository.
func getRepoRoot() (string, error) {
	repo, err := git.Detect()
	if err != nil {
		return "", err
	}
	return repo.Root, nil
}

// parseSeverityThreshold converts a severity string to a numeric rank.
// low=1, medium=2, high=3, critical=4. Higher = more severe.
func parseSeverityThreshold(s string) int {
	switch toLower(s) {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	default:
		return 0
	}
}

// severityRank converts an analysis.Severity to a numeric rank.
func severityRank(s analysis.Severity) int {
	switch s {
	case analysis.SeverityLow:
		return 1
	case analysis.SeverityMedium:
		return 2
	case analysis.SeverityHigh:
		return 3
	case analysis.SeverityCritical:
		return 4
	case analysis.SeverityInfo:
		return 0
	}
	return 0
}

// Ensure context is used
var _ = context.Background
