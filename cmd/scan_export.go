package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/patchflow/patchflow-cli/internal/analysis"
	"github.com/patchflow/patchflow-cli/internal/git"
	"github.com/patchflow/patchflow-cli/internal/reachability"
	"github.com/patchflow/patchflow-cli/internal/report"
	"github.com/patchflow/patchflow-cli/internal/risk"
	"github.com/patchflow/patchflow-cli/internal/sast"
	"github.com/patchflow/patchflow-cli/internal/sca"
	"github.com/spf13/cobra"
)

var scanExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export scan results with real vulnerability findings",
	Long: `Run a full security analysis and export results in SARIF or JSON format.
This performs SCA (OSV.dev), SAST (local tools), reachability analysis, and risk scoring,
then exports the findings in the specified format.`,
	RunE: runScanExport,
}

func init() {
	scanExportCmd.Flags().String("format", "json", "Export format (json, sarif)")
	scanExportCmd.Flags().String("output", "", "Output file path (stdout if omitted)")
}

func runScanExport(cmd *cobra.Command, _ []string) error {
	format, _ := cmd.Flags().GetString("format")
	outputPath, _ := cmd.Flags().GetString("output")
	formatter := FormatterFromContext(cmd.Context())
	ctx := cmd.Context()

	// Validate format
	switch format {
	case "json", "sarif":
	default:
		return fmt.Errorf("unsupported format: %q (supported: json, sarif)", format)
	}

	// Detect project context. Export can run on unpacked source trees that are
	// not git repositories; diff stats are included only when available.
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
	sastRunner := sast.NewRunner()
	sastResult, err := sastRunner.Analyze(ctx, repo.Root)
	if err == nil {
		allFindings = append(allFindings, sastResult.Findings...)
		analyzersRun = append(analyzersRun, sastResult.ToolsRun...)
	}

	// Run reachability
	if len(scaResult.Findings) > 0 {
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

	var data []byte
	switch format {
	case "sarif":
		sarifReport := gen.SARIF("0.1.0")
		data, err = json.MarshalIndent(sarifReport, "", "  ")
		if err != nil {
			return formatter.PrintError(err)
		}
	case "json":
		data, err = gen.JSON()
		if err != nil {
			return formatter.PrintError(err)
		}
	}

	if outputPath != "" {
		if err := os.WriteFile(outputPath, data, 0644); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		return formatter.PrintSuccess("Report written to " + outputPath)
	}

	_, err = fmt.Fprintln(os.Stdout, string(data))
	return err
}
