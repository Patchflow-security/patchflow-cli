package cmd

import (
	"fmt"
	"strings"
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
	prReviewBase      string
	prReviewHead      string
	prReviewFormat    string
	prReviewOutput    string
	prReviewNoSAST    bool
	prReviewNoSecrets bool
	prReviewNoReach   bool
)

var prReviewCmd = &cobra.Command{
	Use:   "pr-review",
	Short: "Simulate a PR risk review before opening a pull request",
	Long: `Analyze your current branch changes and compute a risk score, vulnerability
findings, reachability data, and recommendations — all locally, before you open a PR.

This is the PatchFlow "is this change safe?" command. It runs SCA (OSV.dev),
SAST (local tools), reachability analysis, and risk scoring, then produces a
terminal summary or a report file (markdown/json/sarif).`,
	RunE: runPRReview,
}

func init() {
	prReviewCmd.Flags().StringVar(&prReviewBase, "base", "", "Base branch (auto-detected if omitted)")
	prReviewCmd.Flags().StringVar(&prReviewHead, "head", "", "Head branch (current branch if omitted)")
	prReviewCmd.Flags().StringVar(&prReviewFormat, "format", "", "Report format: markdown, json, sarif")
	prReviewCmd.Flags().StringVar(&prReviewOutput, "output", "", "Write report to file (stdout if omitted)")
	prReviewCmd.Flags().BoolVar(&prReviewNoSAST, "no-sast", false, "Skip SAST analysis")
	prReviewCmd.Flags().BoolVar(&prReviewNoSecrets, "no-secrets", false, "Skip secret detection")
	prReviewCmd.Flags().BoolVar(&prReviewNoReach, "no-reachability", false, "Skip reachability analysis")

	rootCmd.AddCommand(prReviewCmd)
}

func runPRReview(cmd *cobra.Command, _ []string) error {
	formatter := FormatterFromContext(cmd.Context())
	ctx := cmd.Context()

	// Detect git repository and collect context
	repo, err := git.Detect()
	if err != nil {
		return formatter.PrintError(err)
	}
	if err := repo.DetectChangedFiles(); err != nil {
		return formatter.PrintError(fmt.Errorf("failed to detect changed files: %w", err))
	}
	if err := repo.DetectDiffStats(); err != nil {
		return formatter.PrintError(fmt.Errorf("failed to detect diff stats: %w", err))
	}

	if !output.IsJSON(formatter) {
		_ = formatter.Print("PatchFlow PR Risk Review")
		_ = formatter.Print("")
		_ = formatter.Print(fmt.Sprintf("  Branch: %s → %s", repo.BaseBranch, repo.CurrentBranch))
		_ = formatter.Print(fmt.Sprintf("  Commit: %s", shortenSHA(repo.CommitSHA)))
		_ = formatter.Print(fmt.Sprintf("  Files:  %d changed (+%d / -%d)", len(repo.ChangedFiles), repo.AddedLines, repo.DeletedLines))
		_ = formatter.Print("")
	}

	started := time.Now()

	// 1. SCA — full dependency baseline. PR review keeps SAST scoped to changed
	// files, but dependency risk should not disappear when manifests are not in
	// the diff.
	if !output.IsJSON(formatter) {
		_ = formatter.Print("Analyzing dependencies (SCA via OSV.dev)...")
	}
	scaAnalyzer := sca.NewAnalyzer()
	scaAnalyzer.MaxDepth = 3

	scaResult, err := scaAnalyzer.Analyze(ctx, repo.Root)
	if err != nil {
		return formatter.PrintError(fmt.Errorf("SCA analysis failed: %w", err))
	}

	var allFindings []analysis.Finding
	allFindings = append(allFindings, scaResult.Findings...)
	analyzersRun := []string{"osv"}

	// 2. SAST — only on changed files
	if !prReviewNoSAST || !prReviewNoSecrets {
		if !output.IsJSON(formatter) {
			_ = formatter.Print("Running SAST (local tools)...")
		}
		sastRunner := sast.NewRunner()
		sastRunner.ChangedOnly = true
		sastRunner.ChangedFiles = repo.ChangedFiles
		sastRunner.IncludeTests = false

		if prReviewNoSAST {
			sastRunner.NoEmbeddedGo = true
			sastRunner.NoEmbeddedPatterns = true
		}
		if prReviewNoSecrets {
			sastRunner.NoEmbeddedSecrets = true
		}

		if prReviewNoSAST && !prReviewNoSecrets {
			var filtered []sast.Tool
			for _, t := range sastRunner.Tools {
				if t.Name == "gitleaks" {
					filtered = append(filtered, t)
				}
			}
			sastRunner.Tools = filtered
		} else if !prReviewNoSAST && prReviewNoSecrets {
			var filtered []sast.Tool
			for _, t := range sastRunner.Tools {
				if t.Name != "gitleaks" {
					filtered = append(filtered, t)
				}
			}
			sastRunner.Tools = filtered
		} else if prReviewNoSAST && prReviewNoSecrets {
			sastRunner.Tools = nil
		}

		sastResult, err := sastRunner.Analyze(ctx, repo.Root)
		if err != nil {
			if !output.IsJSON(formatter) {
				_ = formatter.Print("  (SAST skipped: " + err.Error() + ")")
			}
		} else {
			allFindings = append(allFindings, sastResult.Findings...)
			analyzersRun = append(analyzersRun, sastResult.ToolsRun...)
		}
	}

	// 3. Reachability
	if !prReviewNoReach && len(scaResult.Findings) > 0 {
		if !output.IsJSON(formatter) {
			_ = formatter.Print("Analyzing reachability...")
		}
		reachAnalyzer := reachability.NewAnalyzer()
		reachResult, err := reachAnalyzer.Analyze(ctx, repo.Root, allFindings, scaResult.Dependencies)
		if err == nil {
			allFindings = reachResult.Findings
		}
	}

	// 4. Risk scoring
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

	// Build result
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
	if prReviewFormat != "" || prReviewOutput != "" {
		fmtStr := prReviewFormat
		if fmtStr == "" {
			fmtStr = "markdown"
		}
		if prReviewOutput != "" {
			if err := gen.WriteFile(fmtStr, prReviewOutput); err != nil {
				return formatter.PrintError(fmt.Errorf("failed to write report: %w", err))
			}
			if !output.IsJSON(formatter) {
				_ = formatter.PrintSuccess("Report written to " + prReviewOutput)
			}
		}
	}

	// Also write to .patchflow/reports/ if initialized
	if _, err := getRepoRoot(); err == nil {
		if repoRoot, _ := getRepoRoot(); repoRoot != "" {
			if writtenPath, err := gen.WriteToReportsDir(repoRoot, "markdown"); err == nil {
				if !output.IsJSON(formatter) {
					_ = formatter.Print("  Report saved: " + writtenPath)
				}
			}
		}
	}

	if output.IsJSON(formatter) {
		return formatter.Print(struct {
			*analysis.AnalysisResult `json:"analysis"`
			Risk                     *risk.ScoreOutput `json:"risk"`
		}{
			AnalysisResult: result,
			Risk:           &riskScore,
		})
	}

	// Terminal output
	_ = formatter.Print("")
	riskLabel := strings.ToUpper(riskScore.Level)
	_ = formatter.Print(fmt.Sprintf("Risk Score: %d/100 — %s", riskScore.Score, riskLabel))
	_ = formatter.Print("")

	// Severity breakdown
	if len(riskScore.FindingsBySeverity) > 0 {
		_ = formatter.Print("Findings by severity:")
		for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
			if count, ok := riskScore.FindingsBySeverity[sev]; ok && count > 0 {
				_ = formatter.Print(fmt.Sprintf("  %-10s  %d", sev, count))
			}
		}
		_ = formatter.Print("")
	}

	// Top findings
	if len(riskScore.TopFindings) > 0 {
		_ = formatter.Print("Top findings:")
		for i, f := range riskScore.TopFindings {
			_ = formatter.Print(fmt.Sprintf("  %d. [%s] %s", i+1, strings.ToUpper(string(f.Severity)), f.Title))
			if f.PackageName != "" {
				_ = formatter.Print(fmt.Sprintf("     Package: %s@%s", f.PackageName, f.PackageVersion))
			}
			if f.FilePath != "" {
				_ = formatter.Print(fmt.Sprintf("     File:    %s:%d", f.FilePath, f.LineStart))
			}
			if f.Recommendation != "" {
				_ = formatter.Print(fmt.Sprintf("     Fix:     %s", f.Recommendation))
			}
			if f.Reachability != "" {
				_ = formatter.Print(fmt.Sprintf("     Reach:   %s", f.Reachability))
			}
		}
		_ = formatter.Print("")
	}

	// Recommendations
	recs := gen.GenerateRecommendationsPublic()
	if len(recs) > 0 {
		_ = formatter.Print("Recommended before PR:")
		for i, rec := range recs {
			_ = formatter.Print(fmt.Sprintf("  %d. %s", i+1, rec))
		}
		_ = formatter.Print("")
	}

	// Status
	status := "Ready for review"
	if riskScore.Score >= 80 {
		status = "BLOCKING — fix critical issues before opening a PR"
	} else if riskScore.Score >= 60 {
		status = "Warning — address high-severity findings before opening a PR"
	} else if riskScore.Score >= 40 {
		status = "Caution — review findings before opening a PR"
	}
	_ = formatter.Print("Status: " + status)

	return nil
}
