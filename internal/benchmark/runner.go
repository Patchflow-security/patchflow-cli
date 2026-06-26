package benchmark

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// pfJSONOutput mirrors the JSON that `patchflow scan run --json` prints to
// stdout. We only decode the fields needed for metrics so the benchmark is
// resilient to additive schema changes.
type pfJSONOutput struct {
	Analysis struct {
		Findings      []pfFinding      `json:"findings"`
		EngineTimings []pfEngineTiming `json:"engine_timings"`
		Analyzers     []string         `json:"analyzers"`
		Duration      time.Duration    `json:"duration"`
		ExitCode      int              `json:"exit_code"`
		Profile       string           `json:"profile"`
		Mode          string           `json:"mode"`
		Version       string           `json:"version"`
	} `json:"analysis"`
	Risk struct {
		FindingsBySeverity map[string]int `json:"findings_by_severity"`
	} `json:"risk"`
}

type pfFinding struct {
	Type       string `json:"type"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	RuleID     string `json:"rule_id"`
	CVEID      string `json:"cve_id"`
	Analyzer   string `json:"analyzer"`
}

type pfEngineTiming struct {
	Engine   string        `json:"engine"`
	Duration time.Duration `json:"duration"`
	Findings int           `json:"findings"`
}

// Runner orchestrates a benchmark run across all repos in a config.
type Runner struct {
	Config   *Config
	Out      func(string) // progress logger (human-readable)
	NoTools  bool         // skip comparison tools
	NoWarm   bool         // skip the warm (cached) second run
	Timeout  time.Duration // per-scan timeout (default 15m)
}

// NewRunner creates a benchmark runner.
func NewRunner(cfg *Config) *Runner {
	return &Runner{Config: cfg, Timeout: 15 * time.Minute}
}

// Run executes the full benchmark suite and returns per-repo results plus an
// aggregate summary. It creates the results directory tree:
//
//	<results>/
//	  sarif/<repo>.sarif
//	  raw/<repo>.json
//	  markdown/<repo>.md
//	  summary.json
//	  summary.md
func (r *Runner) Run(ctx context.Context) ([]RepoResult, *Summary, error) {
	resultsDir := r.Config.ResultsRoot()
	if err := os.MkdirAll(filepath.Join(resultsDir, "sarif"), 0755); err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(filepath.Join(resultsDir, "raw"), 0755); err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(filepath.Join(resultsDir, "markdown"), 0755); err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(r.Config.WorkRoot(), 0755); err != nil {
		return nil, nil, err
	}

	var results []RepoResult
	for _, spec := range r.Config.Repos {
		r.logf("=== %s [%s] ===", spec.Name, spec.Type)
		res, err := r.runRepo(ctx, spec, resultsDir)
		if err != nil {
			r.logf("  ERROR: %v", err)
			res = &RepoResult{Repo: spec, Error: err.Error()}
		}
		results = append(results, *res)
	}

	summary := Aggregate(results, r.Config)
	summary.PatchFlowVersion = patchflowVersion(r.Config)
	summary.Hardware = detectHardware()

	// Write summary artifacts.
	if err := WriteSummaryJSON(summary, filepath.Join(resultsDir, "summary.json")); err != nil {
		return results, summary, err
	}
	if err := WriteSummaryMarkdown(summary, results, filepath.Join(resultsDir, "summary.md")); err != nil {
		return results, summary, err
	}

	return results, summary, nil
}

// runRepo prepares a repo and runs PatchFlow (cold + warm) plus comparison tools.
func (r *Runner) runRepo(ctx context.Context, spec RepoSpec, resultsDir string) (*RepoResult, error) {
	repoPath, err := r.prepareRepo(ctx, spec)
	if err != nil {
		return nil, fmt.Errorf("prepare repo %q: %w", spec.Name, err)
	}

	// Count LOC once (independent of scan).
	loc, err := CountLOC(repoPath)
	if err != nil {
		return nil, fmt.Errorf("count LOC for %q: %w", spec.Name, err)
	}
	r.logf("  LOC: %d across %d files", loc.LOC, loc.FilesScanned)

	sarifPath := filepath.Join(resultsDir, "sarif", spec.Name+".sarif")
	jsonPath := filepath.Join(resultsDir, "raw", spec.Name+".json")
	mdPath := filepath.Join(resultsDir, "markdown", spec.Name+".md")

	// Cold run: clear the patchflow cache so OSV/SAST caches start empty.
	coldOut, coldDur, coldExit, coldMem, err := r.runPatchFlow(ctx, repoPath, sarifPath, jsonPath, mdPath, true)
	if err != nil {
		return nil, fmt.Errorf("cold scan %q: %w", spec.Name, err)
	}

	// Warm run: reuse the cache populated by the cold run. Measures cache speedup.
	warmDur := coldDur
	if !r.NoWarm {
		_, wd, _, _, werr := r.runPatchFlow(ctx, repoPath, "", "", "", false)
		if werr != nil {
			r.logf("  warm run failed (using cold only): %v", werr)
		} else {
			warmDur = wd
		}
	}

	m := buildMetrics(spec, coldOut, loc, coldDur, warmDur, coldExit, coldMem)

	// SARIF validation.
	if _, statErr := os.Stat(sarifPath); statErr == nil {
		m.SARIFGenerated = true
		if vErr := ValidateSARIF(sarifPath); vErr != nil {
			r.logf("  SARIF invalid: %v", vErr)
		} else {
			m.SARIFValid = true
		}
	}

	// Recall against expected findings.
	applyExpected(&m, coldOut, spec)

	res := &RepoResult{
		Repo:         spec,
		PatchFlow:    m,
		SARIFPath:    sarifPath,
		JSONPath:     jsonPath,
		MarkdownPath: mdPath,
	}

	// Comparison tools.
	if !r.NoTools && len(r.Config.Tools) > 0 {
		res.Tools = r.runComparisonTools(ctx, spec, repoPath, resultsDir)
		m.ToolFindings = make(map[string]int, len(res.Tools))
		for name, tr := range res.Tools {
			if tr.Available {
				m.ToolFindings[name] = tr.Findings
			}
		}
	}

	r.logf("  findings: %d (exit %d) | cold %s warm %s | sarif valid=%v",
		m.TotalFindings, m.ExitCode, coldDur.Round(time.Millisecond),
		warmDur.Round(time.Millisecond), m.SARIFValid)
	return res, nil
}

// runPatchFlow invokes the patchflow binary as a subprocess. When clearCache is
// true, the .patchflow/cache directory is removed first to force a cold scan.
// sarifPath/jsonPath/mdPath are optional; when empty, no report file is written
// (used for the warm run which only needs stdout JSON for timing).
func (r *Runner) runPatchFlow(ctx context.Context, repoPath, sarifPath, jsonPath, mdPath string, clearCache bool) (*pfJSONOutput, time.Duration, int, int, error) {
	if clearCache {
		_ = os.RemoveAll(filepath.Join(repoPath, ".patchflow", "cache"))
	}

	args := []string{"scan", "run", "--json", "--profile", r.Config.PatchFlow.Profile}
	if r.Config.PatchFlow.NoReach {
		args = append(args, "--no-reachability")
	}
	if r.Config.PatchFlow.FailOn != "" {
		args = append(args, "--fail-on", r.Config.PatchFlow.FailOn)
	}
	if sarifPath != "" {
		args = append(args, "--format", "sarif", "--output", sarifPath)
	}
	args = append(args, r.Config.PatchFlow.ExtraArgs...)

	binary := r.Config.PatchFlow.Binary
	timeout := r.Timeout
	if timeout == 0 {
		timeout = 15 * time.Minute
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	out, exitCode, memMB, runErr := runWithMemory(runCtx, binary, args, repoPath)
	dur := time.Since(start)

	// A non-zero exit from --fail-on is expected; only treat exit >= 2 or a
	// context/execution error as a real failure.
	if runErr != nil {
		if exitCode == 1 {
			// --fail-on triggered; scan still produced valid output.
		} else if exitCode >= 2 || exitCode < 0 {
			return nil, dur, exitCode, memMB, fmt.Errorf("patchflow exited %d: %w (stderr: %s)", exitCode, runErr, truncate(out, 500))
		}
	}

	pf, parseErr := parsePatchFlowJSON(out)
	if parseErr != nil {
		// Even if stdout JSON is missing/unparseable, we may have a SARIF file.
		// Return a zero-value struct so SARIF validation can still run.
		pf = &pfJSONOutput{}
	}
	pf.Analysis.ExitCode = exitCode

	// Persist the raw JSON output for archival/audit.
	if jsonPath != "" && len(out) > 0 {
		_ = os.WriteFile(jsonPath, out, 0644)
	}
	// Persist a markdown report via a second lightweight invocation only when a
	// path is requested AND we did not already produce one. The scan run command
	// auto-saves markdown to .patchflow/reports/, so copy that if present.
	if mdPath != "" {
		_ = copyAutoMarkdown(repoPath, mdPath)
	}

	return pf, dur, exitCode, memMB, parseErr
}

// prepareRepo returns a local directory for the repo, cloning if needed.
func (r *Runner) prepareRepo(ctx context.Context, spec RepoSpec) (string, error) {
	if spec.Path != "" {
		abs, err := filepath.Abs(spec.Path)
		if err != nil {
			return "", err
		}
		if _, err := os.Stat(abs); err != nil {
			return "", fmt.Errorf("local path %q: %w", spec.Path, err)
		}
		return abs, nil
	}

	dest := filepath.Join(r.Config.WorkRoot(), spec.Name)
	// If already cloned and pinned, reuse. We don't re-clone to keep reruns fast.
	if _, err := os.Stat(filepath.Join(dest, ".git")); err == nil {
		// If a ref is pinned, checkout it.
		if spec.Ref != "" {
			_ = exec.CommandContext(ctx, "git", "-C", dest, "checkout", spec.Ref).Run()
		}
		return dest, nil
	}

	_ = os.RemoveAll(dest)
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return "", err
	}
	cloneCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	args := []string{"clone", "--depth", "1"}
	if spec.Ref != "" {
		// For tags/commits, shallow clone then checkout. --depth 1 with a tag
		// works via --branch <tag>.
		args = append(args, "--branch", spec.Ref)
	}
	args = append(args, spec.URL, dest)
	cmd := exec.CommandContext(cloneCtx, "git", args...)
	if combined, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("git clone: %w (%s)", err, truncate(combined, 300))
	}
	return dest, nil
}

func (r *Runner) logf(format string, args ...any) {
	if r.Out != nil {
		r.Out(fmt.Sprintf(format, args...))
	}
}

// buildMetrics converts a patchflow JSON output into a Metrics struct.
func buildMetrics(spec RepoSpec, pf *pfJSONOutput, loc LOCStats, coldDur, warmDur time.Duration, exitCode, memMB int) Metrics {
	m := Metrics{
		RepoName:     spec.Name,
		RepoType:     spec.Type,
		Language:     spec.Language,
		LOC:          loc.LOC,
		FilesScanned: loc.FilesScanned,
		ScanDuration: coldDur,
		ColdDuration: coldDur,
		WarmDuration: warmDur,
		ExitCode:     exitCode,
		MemoryMB:     memMB,
		BySeverity:   map[string]int{},
		ByConfidence: map[string]int{},
		ByType:       map[string]int{},
	}
	if pf == nil {
		pf = &pfJSONOutput{}
	}
	for _, et := range pf.Analysis.EngineTimings {
		m.EnginesUsed = append(m.EnginesUsed, et.Engine)
	}
	if len(m.EnginesUsed) == 0 {
		m.EnginesUsed = pf.Analysis.Analyzers
	}
	m.TotalFindings = len(pf.Analysis.Findings)
	for _, f := range pf.Analysis.Findings {
		m.BySeverity[strings.ToLower(f.Severity)]++
		m.ByConfidence[strings.ToLower(f.Confidence)]++
		m.ByType[strings.ToLower(f.Type)]++
	}
	// Cache speedup: (cold - warm) / cold * 100. Negative or zero when no cache.
	if coldDur > 0 && warmDur > 0 && warmDur < coldDur {
		m.CacheSpeedup = float64(coldDur-warmDur) / float64(coldDur) * 100
	}
	return m
}

// applyExpected computes recall against the curated ExpectedFindings list by
// matching rule IDs and CVE IDs found in the scan output.
func applyExpected(m *Metrics, pf *pfJSONOutput, spec RepoSpec) {
	if len(spec.ExpectedFindings) == 0 || pf == nil {
		return
	}
	found := map[string]bool{}
	for _, f := range pf.Analysis.Findings {
		if f.RuleID != "" {
			found[f.RuleID] = true
		}
		if f.CVEID != "" {
			found[f.CVEID] = true
		}
	}
	for _, exp := range spec.ExpectedFindings {
		if found[exp] {
			m.ExpectedDetected = append(m.ExpectedDetected, exp)
		} else {
			m.ExpectedMissed = append(m.ExpectedMissed, exp)
		}
	}
	if len(spec.ExpectedFindings) > 0 {
		m.Recall = float64(len(m.ExpectedDetected)) / float64(len(spec.ExpectedFindings))
	}
}

// parsePatchFlowJSON decodes the JSON printed to stdout by `patchflow scan run --json`.
func parsePatchFlowJSON(stdout []byte) (*pfJSONOutput, error) {
	stdout = bytes.TrimSpace(stdout)
	if len(stdout) == 0 {
		return nil, fmt.Errorf("empty stdout from patchflow")
	}
	var pf pfJSONOutput
	if err := json.Unmarshal(stdout, &pf); err != nil {
		return nil, fmt.Errorf("decode patchflow JSON: %w", err)
	}
	return &pf, nil
}

func patchflowVersion(cfg *Config) string {
	binary := cfg.PatchFlow.Binary
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, _, _, err := runWithMemory(ctx, binary, []string{"version", "--json"}, "")
	if err != nil {
		return "unknown"
	}
	var v struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(bytes.TrimSpace(out), &v) == nil && v.Version != "" {
		return v.Version
	}
	return "unknown"
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}

func copyAutoMarkdown(repoPath, dest string) error {
	src := filepath.Join(repoPath, ".patchflow", "reports")
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	// Pick the most recently modified .md file.
	var newest os.DirEntry
	var newestTime int64
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		if info.ModTime().Unix() > newestTime {
			newestTime = info.ModTime().Unix()
			newest = e
		}
	}
	if newest == nil {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(src, newest.Name()))
	if err != nil {
		return err
	}
	return os.WriteFile(dest, data, 0644)
}
