package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/git"
	"github.com/Patchflow-security/patchflow-cli/internal/output"
	"github.com/Patchflow-security/patchflow-cli/internal/reachability"
	"github.com/Patchflow-security/patchflow-cli/internal/report"
	"github.com/Patchflow-security/patchflow-cli/internal/risk"
	"github.com/Patchflow-security/patchflow-cli/internal/sast"
	"github.com/Patchflow-security/patchflow-cli/internal/sca"
	"github.com/spf13/cobra"
)

var (
	reportFormat string
	reportOutput string
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a security analysis report",
	Long: `Run a full analysis and generate a report in the specified format.
Supported formats: markdown, json, sarif.

The report includes all findings (SCA, SAST, secrets), dependency list,
risk score breakdown, and recommendations.`,
	RunE: runReport,
}

func init() {
	reportCmd.Flags().StringVar(&reportFormat, "format", "markdown", "Report format: markdown, json, sarif")
	reportCmd.Flags().StringVar(&reportOutput, "output", "", "Output file path (stdout if omitted)")

	rootCmd.AddCommand(reportCmd)
}

func runReport(cmd *cobra.Command, _ []string) error {
	formatter := FormatterFromContext(cmd.Context())
	ctx := cmd.Context()

	// Validate format
	switch reportFormat {
	case "markdown", "md", "json", "sarif":
	default:
		return formatter.PrintError(fmt.Errorf("unsupported format: %s (supported: markdown, json, sarif)", reportFormat))
	}

	// Detect project context. Report generation supports non-git directories;
	// diff stats are included only when available.
	repo, isGitRepo, err := git.DetectOrLocal()
	if err != nil {
		return formatter.PrintError(err)
	}
	if isGitRepo {
		_ = repo.DetectChangedFiles()
		_ = repo.DetectDiffStats()
	}

	started := time.Now()

	// Run SCA
	if !output.IsJSON(formatter) {
		_ = formatter.Print("Running SCA analysis...")
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

	// Run SAST
	if !output.IsJSON(formatter) {
		_ = formatter.Print("Running SAST analysis...")
	}
	sastRunner := sast.NewRunner()
	sastResult, err := sastRunner.Analyze(ctx, repo.Root)
	if err == nil {
		allFindings = append(allFindings, sastResult.Findings...)
		analyzersRun = append(analyzersRun, sastResult.ToolsRun...)
	}

	// Run reachability
	if len(scaResult.Findings) > 0 {
		if !output.IsJSON(formatter) {
			_ = formatter.Print("Running reachability analysis...")
		}
		reachAnalyzer := reachability.NewAnalyzer()
		reachResult, err := reachAnalyzer.Analyze(ctx, repo.Root, allFindings, scaResult.Dependencies)
		if err == nil {
			allFindings = reachResult.Findings
		}
	}

	// Risk scoring
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

	gen := report.NewGenerator(result, &riskScore)

	// Normalize format
	fmtStr := reportFormat
	if fmtStr == "md" {
		fmtStr = "markdown"
	}

	// Write to file or stdout
	if reportOutput != "" {
		if err := gen.WriteFile(fmtStr, reportOutput); err != nil {
			return formatter.PrintError(fmt.Errorf("failed to write report: %w", err))
		}
		if !output.IsJSON(formatter) {
			_ = formatter.PrintSuccess("Report written to " + reportOutput)
		}
		return nil
	}

	// Write to stdout
	switch fmtStr {
	case "markdown":
		fmt.Println(gen.Markdown())
	case "json":
		data, err := gen.JSON()
		if err != nil {
			return formatter.PrintError(err)
		}
		fmt.Println(string(data))
	case "sarif":
		sarifReport := gen.SARIF("0.1.2")
		data, err := json.MarshalIndent(sarifReport, "", "  ")
		if err != nil {
			return formatter.PrintError(err)
		}
		fmt.Println(string(data))
	}

	// Also save to .patchflow/reports/ if initialized
	pfReportsDir := filepath.Join(repo.Root, ".patchflow", "reports")
	if _, err := os.Stat(pfReportsDir); err == nil {
		if savedPath, err := gen.WriteToReportsDir(repo.Root, fmtStr); err == nil {
			if !output.IsJSON(formatter) {
				_ = formatter.Print("Report saved: " + savedPath)
			}
		}
	}

	return nil
}
