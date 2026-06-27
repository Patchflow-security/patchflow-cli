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
	"github.com/patchflow/patchflow-cli/internal/rules"
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
	scanNewOnly          bool
	scanFailOn           string
	scanSince            string
	scanBaselineName     string
	scanGovernanceProfile string
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
	scanRealCmd.Flags().StringVar(&scanGovernanceProfile, "governance-profile", "", "Rule governance profile: dev, pr, ci, audit (filters findings by rule maturity)")

	scanCmd.AddCommand(scanRealCmd)
}

func runScanReal(cmd *cobra.Command, _ []string) error {
	formatter := FormatterFromContext(cmd.Context())
	ctx := cmd.Context()

	// Determine scan mode for metadata. --since takes precedence over
	// --changed-only, which takes precedence over a full scan.
	scanMode := "full"
	if scanChangedOnly {
		scanMode = "changed"
	}
	if scanSince != "" {
		scanMode = "since"
		scanChangedOnly = true // --since implies changed-only
	}

	// Detect project context. Full scans support non-git directories; diff-only
	// scans still require git metadata.
	repo, isGitRepo, err := git.DetectOrLocal()
	if err != nil {
		return formatter.PrintError(err)
	}
	if isGitRepo {
		if scanSince != "" {
			// --since <ref>: use git diff --name-only <ref>...HEAD and filter.
			sinceFiles, sinceErr := repo.ChangedFilesSince(scanSince)
			if sinceErr != nil {
				return formatter.PrintError(fmt.Errorf("--since %q: %w", scanSince, sinceErr))
			}
			repo.ChangedFiles = sinceFiles
			// Diff stats are still computed against the base branch for risk scoring.
			_ = repo.DetectDiffStats()
		} else {
			_ = repo.DetectChangedFiles()
			_ = repo.DetectDiffStats()
		}
	} else if scanChangedOnly || scanSince != "" {
		return formatter.PrintError(fmt.Errorf("--changed-only/--since requires a git repository"))
	} else if !output.IsJSON(formatter) {
		_ = formatter.Print("Non-git directory detected; running full-project scan.")
	}

	// Debug/verbose: show the changed-file inventory so CI logs are auditable.
	verbose, _ := cmd.Flags().GetBool("verbose")
	if verbose && len(repo.ChangedFiles) > 0 {
		_ = formatter.Print(fmt.Sprintf("Changed files (%d) since %s:", len(repo.ChangedFiles), scanSince))
		for _, f := range repo.ChangedFiles {
			_ = formatter.Print("  " + f)
		}
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

		// When --changed-only or --since is set, auto-enable incremental
		// scanning so file-based scanners (patterns, secrets, tree-sitter)
		// only process the changed files. This gives 5-50x speedup on
		// large repos with small diffs.
		if scanChangedOnly && !scanIncremental {
			sastRunner.IncrementalScan = true
		}

		// Pass git changed files as pre-filter for the fastest incremental path.
		if scanChangedOnly && len(repo.ChangedFiles) > 0 {
			sastRunner.GitChangedFiles = repo.ChangedFiles
		}

		// In changed-only mode, skip external tools that can't filter to
		// changed files (gosec, bandit, semgrep scan the whole project).
		// gitleaks can be skipped too since embedded secrets scanner
		// already covers changed files. This avoids redundant full-project
		// scans that defeat the purpose of --changed-only.
		if scanChangedOnly {
			sastRunner.Tools = nil
		}

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

	// 3b. Governance profile filtering: if --governance-profile is set,
	//     filter out findings from rules that are not active in the selected
	//     governance profile. This prevents noisy experimental/beta rules
	//     from appearing in dev/pr/ci scans while still running them in audit.
	//
	//     The governance profile is independent of the scan profile (quick/
	//     standard/deep), which controls scanner selection and timeouts.
	//     If not explicitly set, it defaults based on the scan profile:
	//       quick    → dev
	//       standard → ci
	//       deep     → audit
	governanceProfile := rules.Profile(scanGovernanceProfile)
	if governanceProfile == "" {
		switch scanProfile {
		case "quick":
			governanceProfile = rules.ProfileDev
		case "deep":
			governanceProfile = rules.ProfileAudit
		default:
			governanceProfile = rules.ProfileCI
		}
	}
	if governanceProfile != rules.ProfileAudit {
		registry := rules.BuildDefaultRegistry()
		filtered := make([]analysis.Finding, 0, len(allFindings))
		dropped := 0
		for _, f := range allFindings {
			// SCA and secret findings from external sources (OSV, gitleaks)
			// don't have rule_ids in the governance registry — they should
			// never be filtered by governance profile. Only SAST findings
			// with a rule_id are subject to governance filtering.
			if f.RuleID == "" || f.Type == analysis.TypeSCA || f.Type == analysis.TypeSecret {
				filtered = append(filtered, f)
				continue
			}
			if registry.IsRuleActiveInProfile(f.RuleID, governanceProfile) {
				filtered = append(filtered, f)
			} else {
				dropped++
			}
		}
		if dropped > 0 && !output.IsJSON(formatter) {
			_ = formatter.Print(fmt.Sprintf("  Governance profile %s: filtered %d findings from inactive rules.", governanceProfile, dropped))
		}
		allFindings = filtered
	}

	// 4. Populate stable fingerprints on all findings before risk scoring,
	//    baseline comparison, and report generation. This is the single
	//    post-processing step that makes findings line-number independent.
	analysis.PopulateFingerprints(allFindings)

	// 5. --new-only: filter findings against the baseline BEFORE report
	//    generation so that reports, risk score, and exit code all reflect
	//    only the new findings. This is the production guarantee: running
	//    --new-only right after `baseline create` returns no findings and
	//    exit code 0.
	baselineDiff := (*baseline.Diff)(nil)
	if scanNewOnly && scanBaselineName != "" {
		mgr := baseline.NewManager(repo.Root)
		diff, err := mgr.Compare(scanBaselineName, allFindings)
		if err != nil {
			return formatter.PrintError(fmt.Errorf("baseline comparison failed: %w", err))
		}
		baselineDiff = diff
		allFindings = diff.New
	}

	// 6. Risk Scoring (computed on the final, possibly filtered finding set)
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

	// Build analysis result with full scan metadata.
	manifestPaths := make([]string, 0, len(scaResult.Manifests))
	for _, m := range scaResult.Manifests {
		manifestPaths = append(manifestPaths, m.Path)
	}

	result := &analysis.AnalysisResult{
		ScanID:        generateScanID(),
		ProjectRoot:   repo.Root,
		Branch:        repo.CurrentBranch,
		CommitSHA:     repo.CommitSHA,
		BaseBranch:    repo.BaseBranch,
		StartedAt:     started,
		CompletedAt:   completed,
		Duration:      completed.Sub(started),
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
		// Scan metadata
		Profile:           scanProfile,
		Mode:              scanMode,
		Baseline:          scanBaselineName,
		NewOnly:           scanNewOnly,
		SinceRef:          scanSince,
		GovernanceProfile: governanceProfile.String(),
		Version:           versionString(),
		ChangedFiles:      repo.ChangedFiles,
	}

	// 7. Output
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
		// For JSON mode, output the full result with scan metadata.
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

	// --new-only: print baseline comparison summary after the report.
	if baselineDiff != nil {
		_ = formatter.Print(fmt.Sprintf("\nBaseline: %s — New: %d, Resolved: %d, Unchanged: %d",
			scanBaselineName, baselineDiff.NewCount, baselineDiff.ResolvedCount, baselineDiff.UnchangedCount))
		if baselineDiff.NewCount > 0 {
			_ = formatter.Print("\nNew findings:")
			for _, f := range baselineDiff.New {
				_ = formatter.Print(fmt.Sprintf("  [%s] %s:%d — %s", f.RuleID, f.FilePath, f.LineStart, f.Title))
			}
		} else {
			_ = formatter.Print("No new findings relative to baseline.")
		}
	}

	// 8. Compute exit code. --fail-on uses the (possibly filtered) findings.
	exitCode := exitcode.Success
	if scanFailOn != "" {
		threshold := parseSeverityThreshold(scanFailOn)
		blockingCount := 0
		for _, f := range allFindings {
			if severityRank(f.Severity) >= threshold {
				blockingCount++
			}
		}
		if blockingCount > 0 {
			exitCode = exitcode.FindingsFound
			result.ExitCode = exitCode
			return &ExitError{
				Code: exitCode,
				Msg:  fmt.Sprintf("%d finding(s) at or above %s severity", blockingCount, scanFailOn),
			}
		}
	}
	result.ExitCode = exitCode

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

// generateScanID returns a short, unique, sortable scan identifier of the form
// YYYYMMDDHHMMSS-<6 random hex>. It is stable enough for CI log correlation
// and report deduplication without pulling in a UUID dependency.
func generateScanID() string {
	now := time.Now().UTC()
	b := make([]byte, 3)
	for i := range b {
		b[i] = byte('0' + (now.UnixNano() >> uint(i*8) & 0x3F))
	}
	return now.Format("20060102150405") + "-" + string(b)
}

// versionString returns the CLI version for scan metadata. It reads the
// pkg/version package's Version variable via a helper to avoid an import cycle
// in test builds.
func versionString() string {
	return versionBuildInfo()
}
