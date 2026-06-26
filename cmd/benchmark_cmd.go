package cmd

import (
	"context"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/patchflow/patchflow-cli/internal/benchmark"
	"github.com/patchflow/patchflow-cli/internal/output"
	"github.com/spf13/cobra"
)

var (
	benchConfigPath string
	benchNoTools    bool
	benchNoWarm     bool
	benchTimeout    time.Duration
	benchResultsDir string
	benchReportFmt  string
)

var benchmarkCmd = &cobra.Command{
	Use:   "benchmark",
	Short: "Run and report scanner benchmarks against open-source repositories",
	Long: `Benchmark PatchFlow (and optional comparison tools) against a declared suite
of open-source repositories to measure detection, false positives, performance,
SARIF quality, and CI behavior.

Subcommands:
  run      Execute a benchmark suite from a benchmark.yaml config.
  compare  Compare summary.json results across multiple runs.
  report   Regenerate a summary report from existing results.

The benchmark invokes PatchFlow as a real subprocess so it measures actual CLI
behavior (startup, exit codes, SARIF). Comparison tools (semgrep, trivy,
gitleaks, osv-scanner) run when installed.

Responsible disclosure: findings from active/maintained repos are never
published in detail. Only intentionally-vulnerable and historical repos expose
per-finding detail.`,
}

var benchmarkRunCmd = &cobra.Command{
	Use:   "run [benchmark.yaml]",
	Short: "Execute a benchmark suite",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runBenchmarkRun,
}

var benchmarkCompareCmd = &cobra.Command{
	Use:   "compare [results-dir]",
	Short: "Compare summary results across multiple benchmark runs",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runBenchmarkCompare,
}

var benchmarkReportCmd = &cobra.Command{
	Use:   "report [results-dir]",
	Short: "Regenerate a summary report from existing benchmark results",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runBenchmarkReport,
}

func init() {
	benchmarkRunCmd.Flags().BoolVar(&benchNoTools, "no-tools", false, "Skip comparison tools (only run PatchFlow)")
	benchmarkRunCmd.Flags().BoolVar(&benchNoWarm, "no-warm", false, "Skip the warm (cached) second run")
	benchmarkRunCmd.Flags().DurationVar(&benchTimeout, "timeout", 15*time.Minute, "Per-scan timeout")
	benchmarkRunCmd.Flags().StringVar(&benchResultsDir, "results-dir", "", "Override results directory (default: results/<YYYY-MM>/)")

	benchmarkReportCmd.Flags().StringVar(&benchReportFmt, "format", "markdown", "Report format: markdown, json")

	benchmarkCmd.AddCommand(benchmarkRunCmd)
	benchmarkCmd.AddCommand(benchmarkCompareCmd)
	benchmarkCmd.AddCommand(benchmarkReportCmd)
	rootCmd.AddCommand(benchmarkCmd)
}

func runBenchmarkRun(cmd *cobra.Command, args []string) error {
	formatter := FormatterFromContext(cmd.Context())
	cfgPath := benchConfigPath
	if len(args) > 0 {
		cfgPath = args[0]
	}
	if cfgPath == "" {
		return formatter.PrintError(fmt.Errorf("benchmark run requires a config path (positional arg or --config)"))
	}

	cfg, err := benchmark.Load(cfgPath)
	if err != nil {
		return formatter.PrintError(err)
	}
	if benchResultsDir != "" {
		cfg.ResultsDir = benchResultsDir
	}

	runner := benchmark.NewRunner(cfg)
	runner.NoTools = benchNoTools
	runner.NoWarm = benchNoWarm
	runner.Timeout = benchTimeout
	if !output.IsJSON(formatter) {
		runner.Out = func(msg string) { _ = formatter.Print(msg) }
	}

	if output.IsJSON(formatter) {
		_, summary, err := runner.Run(context.Background())
		if err != nil {
			return formatter.PrintError(err)
		}
		return formatter.Print(summary)
	}

	_, summary, err := runner.Run(context.Background())
	if err != nil {
		return formatter.PrintError(err)
	}

	_ = formatter.Print("")
	_ = formatter.Print("PatchFlow Benchmark Summary")
	_ = formatter.Print("============================")
	_ = formatter.Print(fmt.Sprintf("Repos scanned: %d", summary.ReposScanned))
	_ = formatter.Print(fmt.Sprintf("Total LOC: %s", formatBenchInt(summary.TotalLOC)))
	_ = formatter.Print(fmt.Sprintf("Total findings: %d", summary.TotalFindings))
	_ = formatter.Print(fmt.Sprintf("Confirmed true positives: %d", summary.ConfirmedTruePos))
	_ = formatter.Print(fmt.Sprintf("False positives: %d", summary.FalsePositives))
	_ = formatter.Print(fmt.Sprintf("Unknown/unreviewed: %d", summary.UnknownUnreviewed))
	_ = formatter.Print(fmt.Sprintf("Average scan time: %s", summary.AvgScanTime.Round(time.Millisecond)))
	_ = formatter.Print(fmt.Sprintf("Cache warm speedup: %.1f%%", summary.CacheWarmSpeedup))
	_ = formatter.Print(fmt.Sprintf("SARIF valid: %d/%d", summary.SARIFValidCount, summary.SARIFTotalCount))
	_ = formatter.Print(fmt.Sprintf("Results: %s", cfg.ResultsRoot()))
	return nil
}

func runBenchmarkCompare(cmd *cobra.Command, args []string) error {
	formatter := FormatterFromContext(cmd.Context())
	root := "."
	if len(args) > 0 {
		root = args[0]
	}
	summaries, err := benchmark.CompareSummaries(root)
	if err != nil {
		return formatter.PrintError(fmt.Errorf("compare: %w", err))
	}
	if len(summaries) == 0 {
		return formatter.PrintError(fmt.Errorf("no summary.json files found under %s", root))
	}

	// Sort by run dir name (YYYY-MM) ascending.
	dirs := make([]string, 0, len(summaries))
	for d := range summaries {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)

	if output.IsJSON(formatter) {
		return formatter.Print(summaries)
	}

	_ = formatter.Print("Benchmark run comparison")
	_ = formatter.Print("=========================")
	rows := make([][]string, 0, len(dirs))
	for _, d := range dirs {
		s := summaries[d]
		rows = append(rows, []string{
			d, fmt.Sprintf("%d", s.ReposScanned), fmt.Sprintf("%d", s.TotalFindings),
			fmt.Sprintf("%d", s.FalsePositives), s.AvgScanTime.Round(time.Millisecond).String(),
			fmt.Sprintf("%.1f%%", s.CacheWarmSpeedup), fmt.Sprintf("%d/%d", s.SARIFValidCount, s.SARIFTotalCount),
		})
	}
	_ = formatter.PrintTable([]string{"Run", "Repos", "Findings", "FP", "AvgTime", "Cache", "SARIF"}, rows)
	return nil
}

func runBenchmarkReport(cmd *cobra.Command, args []string) error {
	formatter := FormatterFromContext(cmd.Context())
	root := "."
	if len(args) > 0 {
		root = args[0]
	}
	summaryPath := root
	if fi, err := os.Stat(root); err == nil && fi.IsDir() {
		summaryPath = root + "/summary.json"
	}
	summary, err := benchmark.LoadSummary(summaryPath)
	if err != nil {
		return formatter.PrintError(fmt.Errorf("load summary: %w", err))
	}

	switch benchReportFmt {
	case "json":
		return formatter.Print(summary)
	case "markdown", "md":
		// Re-render markdown from the loaded summary.
		results := make([]benchmark.RepoResult, 0, len(summary.PerRepo))
		for _, m := range summary.PerRepo {
			results = append(results, benchmark.RepoResult{PatchFlow: m})
		}
		outPath := root + "/summary.md"
		if fi, err := os.Stat(root); err == nil && !fi.IsDir() {
			outPath = root
		}
		if err := benchmark.WriteSummaryMarkdown(summary, results, outPath); err != nil {
			return formatter.PrintError(err)
		}
		_ = formatter.PrintSuccess("Report written to " + outPath)
		return nil
	default:
		return formatter.PrintError(fmt.Errorf("unsupported format: %s (markdown, json)", benchReportFmt))
	}
}

func formatBenchInt(n int) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	in := fmt.Sprintf("%d", n)
	var out []byte
	for i, c := range []byte(in) {
		if i > 0 && (len(in)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}
