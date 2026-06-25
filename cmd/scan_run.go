package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/patchflow/patchflow-cli/internal/analysis"
	"github.com/patchflow/patchflow-cli/internal/git"
	"github.com/patchflow/patchflow-cli/internal/output"
	"github.com/patchflow/patchflow-cli/internal/reachability"
	"github.com/patchflow/patchflow-cli/internal/report"
	"github.com/patchflow/patchflow-cli/internal/risk"
	"github.com/patchflow/patchflow-cli/internal/sast"
	"github.com/patchflow/patchflow-cli/internal/sca"
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

	scanCmd.AddCommand(scanRealCmd)
}

func runScanReal(cmd *cobra.Command, _ []string) error {
	formatter := FormatterFromContext(cmd.Context())
	ctx := cmd.Context()

	// Detect git repository
	repo, err := git.Detect()
	if err != nil {
		return formatter.PrintError(err)
	}
	_ = repo.DetectChangedFiles()
	_ = repo.DetectDiffStats()

	started := time.Now()

	// 1. SCA Analysis
	if !output.IsJSON(formatter) {
		_ = formatter.Print("Running SCA analysis (OSV.dev)...")
	}
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

	scaResult, err := scaAnalyzer.Analyze(ctx, repo.Root)
	if err != nil {
		return formatter.PrintError(fmt.Errorf("SCA analysis failed: %w", err))
	}

	// 2. SAST Analysis
	var sastResult *sast.Result
	var allFindings []analysis.Finding
	allFindings = append(allFindings, scaResult.Findings...)

	analyzersRun := []string{"osv"}

	if !scanNoSAST || !scanNoSecrets {
		if !output.IsJSON(formatter) {
			_ = formatter.Print("Running SAST analysis (local tools)...")
		}
		sastRunner := sast.NewRunner()
		if scanChangedOnly {
			sastRunner.ChangedOnly = true
			sastRunner.ChangedFiles = repo.ChangedFiles
		}

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
		allFindings = append(allFindings, sastResult.Findings...)
		analyzersRun = append(analyzersRun, sastResult.ToolsRun...)
	}

	// 3. Reachability Analysis
	if !scanNoReach && len(scaResult.Findings) > 0 {
		if !output.IsJSON(formatter) {
			_ = formatter.Print("Running reachability analysis...")
		}
		reachAnalyzer := reachability.NewAnalyzer()
		reachResult, err := reachAnalyzer.Analyze(ctx, repo.Root, allFindings, scaResult.Dependencies)
		if err != nil {
			// Non-fatal — continue without reachability data
			if !output.IsJSON(formatter) {
				_ = formatter.Print("  (reachability analysis skipped: " + err.Error() + ")")
			}
		} else {
			allFindings = reachResult.Findings
		}
	}

	// 4. Risk Scoring
	riskEngine := risk.NewEngine()
	riskScore := riskEngine.Compute(risk.ScoreInput{
		Findings:              allFindings,
		FilesChanged:          len(repo.ChangedFiles),
		AddedLines:            repo.AddedLines,
		DeletedLines:          repo.DeletedLines,
		DependencyFilesChanged: hasDependencyFiles(repo.ChangedFiles),
		CIWorkflowChanged:     hasCIWorkflow(repo.ChangedFiles),
		AuthFilesChanged:      hasAuthFiles(repo.ChangedFiles),
	})

	completed := time.Now()

	// Build analysis result
	manifestPaths := make([]string, 0, len(scaResult.Manifests))
	for _, m := range scaResult.Manifests {
		manifestPaths = append(manifestPaths, m.Path)
	}

	result := &analysis.AnalysisResult{
		ProjectRoot:  repo.Root,
		Branch:       repo.CurrentBranch,
		CommitSHA:    repo.CommitSHA,
		BaseBranch:   repo.BaseBranch,
		StartedAt:    started,
		CompletedAt:  completed,
		Findings:     allFindings,
		Dependencies: scaResult.Dependencies,
		RiskScore:    riskScore.Score,
		RiskLevel:    riskScore.Level,
		FilesChanged: len(repo.ChangedFiles),
		AddedLines:   repo.AddedLines,
		DeletedLines: repo.DeletedLines,
		Manifests:    manifestPaths,
		Analyzers:    analyzersRun,
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

// Ensure context is used
var _ = context.Background
