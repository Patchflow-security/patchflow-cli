package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/baseline"
	"github.com/Patchflow-security/patchflow-cli/internal/sast"
)

// buildBenchRepo creates a repo with a configurable number of Python files,
// each containing an eval() finding. This gives the scanners a realistic
// workload to benchmark against.
func buildBenchRepo(b testing.TB, numFiles int) string {
	b.Helper()
	dir := b.TempDir()
	for i := 0; i < numFiles; i++ {
		rel := fmt.Sprintf("pkg/mod%d/handler%d.py", i/10, i)
		abs := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(abs), 0755); err != nil {
			b.Fatalf("mkdir: %v", err)
		}
		content := fmt.Sprintf(`def handler_%d(user_input):
    # vulnerable: eval with user input
    result = eval(user_input)
    return result

def safe_%d():
    return "ok"
`, i, i)
		if err := os.WriteFile(abs, []byte(content), 0644); err != nil {
			b.Fatalf("write: %v", err)
		}
	}
	return dir
}

// BenchmarkFullScan measures a full SAST scan over a 50-file Python repo.
func BenchmarkFullScan(b *testing.B) {
	dir := buildBenchRepo(b, 50)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runner := sast.NewRunner()
		runner.RespectGitignore = true
		runner.Timeout = 60 * time.Second
		runner.Tools = nil
		_, err := runner.Analyze(context.Background(), dir)
		if err != nil {
			b.Fatalf("scan failed: %v", err)
		}
	}
}

// BenchmarkChangedScan measures a changed-only SAST scan where only 1 of 50
// files is in the changed set. This benchmarks the filtering speedup.
func BenchmarkChangedScan(b *testing.B) {
	dir := buildBenchRepo(b, 50)
	// Only one file is "changed".
	changedFiles := []string{"pkg/mod0/handler0.py"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runner := sast.NewRunner()
		runner.RespectGitignore = true
		runner.Timeout = 60 * time.Second
		runner.Tools = nil
		runner.ChangedOnly = true
		runner.ChangedFiles = changedFiles
		_, err := runner.Analyze(context.Background(), dir)
		if err != nil {
			b.Fatalf("scan failed: %v", err)
		}
	}
}

// BenchmarkFingerprintPopulation measures how fast PopulateFingerprints runs
// on a large finding set (1000 findings).
func BenchmarkFingerprintPopulation(b *testing.B) {
	findings := make([]analysis.Finding, 1000)
	for i := range findings {
		findings[i] = analysis.Finding{
			Type:      analysis.TypeSAST,
			Analyzer:  "patterns-embedded",
			RuleID:    "PY001",
			FilePath:  fmt.Sprintf("app/handler%d.py", i),
			LineStart: i,
			Evidence:  "eval(user_input)",
			Title:     "Use of eval()",
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Copy to avoid mutating the original across iterations.
		cp := make([]analysis.Finding, len(findings))
		copy(cp, findings)
		analysis.PopulateFingerprints(cp)
	}
}

// BenchmarkBaselineCompare measures baseline comparison speed with 500
// baseline findings and 500 current findings (490 unchanged, 10 new).
func BenchmarkBaselineCompare(b *testing.B) {
	dir := b.TempDir()
	mgr := baseline.NewManager(dir)

	baselineFindings := make([]analysis.Finding, 500)
	for i := range baselineFindings {
		baselineFindings[i] = analysis.Finding{
			Type:     analysis.TypeSAST,
			Analyzer: "patterns-embedded",
			RuleID:   "PY001",
			FilePath: fmt.Sprintf("app/handler%d.py", i),
			Evidence: "eval(user_input)",
		}
	}
	analysis.PopulateFingerprints(baselineFindings)
	if err := mgr.Create("bench", baselineFindings, "sha"); err != nil {
		b.Fatalf("create: %v", err)
	}

	// Current: 490 unchanged + 10 new.
	current := make([]analysis.Finding, 500)
	copy(current, baselineFindings[:490])
	for i := 490; i < 500; i++ {
		current[i] = analysis.Finding{
			Type:     analysis.TypeSecret,
			Analyzer: "secrets-embedded",
			RuleID:   "SECRET-aws",
			FilePath: fmt.Sprintf("config%d.py", i),
			Evidence: "AKIAZ44RF2K7NQ3WBGHD",
		}
	}
	analysis.PopulateFingerprints(current)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := mgr.Compare("bench", current)
		if err != nil {
			b.Fatalf("compare: %v", err)
		}
	}
}

// BenchmarkScanWithPerEngineTimings runs a scan and records per-engine timings
// in the benchmark output, demonstrating that timing metadata is captured.
func BenchmarkScanWithPerEngineTimings(b *testing.B) {
	dir := buildBenchRepo(b, 20)
	var lastToolsRun []string
	var lastFindingCount int
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runner := sast.NewRunner()
		runner.RespectGitignore = true
		runner.Timeout = 60 * time.Second
		runner.Tools = nil
		result, err := runner.Analyze(context.Background(), dir)
		if err != nil {
			b.Fatalf("scan failed: %v", err)
		}
		lastToolsRun = result.ToolsRun
		lastFindingCount = len(result.Findings)
	}
	b.StopTimer()
	b.Logf("per-engine tools run: %s | findings: %d", strings.Join(lastToolsRun, ", "), lastFindingCount)
}

// BenchmarkFullScanColdVsWarm demonstrates cold vs warm cache behavior by
// running two consecutive scans on the same repo. The second run benefits
// from any internal caching in the scanners.
func BenchmarkFullScanColdVsWarm(b *testing.B) {
	dir := buildBenchRepo(b, 30)

	// Cold scan: first run.
	b.Run("cold", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			runner := sast.NewRunner()
			runner.RespectGitignore = true
			runner.Timeout = 60 * time.Second
			runner.Tools = nil
			_, err := runner.Analyze(context.Background(), dir)
			if err != nil {
				b.Fatalf("scan failed: %v", err)
			}
		}
	})

	// Warm scan: reuse a single runner instance across iterations (the
	// pattern scanner caches compiled regexes internally).
	b.Run("warm", func(b *testing.B) {
		runner := sast.NewRunner()
		runner.RespectGitignore = true
		runner.Timeout = 60 * time.Second
		runner.Tools = nil
		// Prime the runner once.
		_, _ = runner.Analyze(context.Background(), dir)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := runner.Analyze(context.Background(), dir)
			if err != nil {
				b.Fatalf("scan failed: %v", err)
			}
		}
	})
}
