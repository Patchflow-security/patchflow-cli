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
	CWEID      string `json:"cwe_id"`
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

	// Convert to absolute paths because patchflow runs with cmd.Dir = repoPath,
	// so relative paths would resolve against the clone dir, not the CWD.
	// However, patchflow validates that --output stays within the project dir.
	// So we write to a temp dir inside the repo, then copy to results after.
	sarifPath, _ := filepath.Abs(filepath.Join(resultsDir, "sarif", spec.Name+".sarif"))
	jsonPath, _ := filepath.Abs(filepath.Join(resultsDir, "raw", spec.Name+".json"))
	mdPath, _ := filepath.Abs(filepath.Join(resultsDir, "markdown", spec.Name+".md"))

	// Temp output paths inside the repo (will be copied to final locations after scan).
	// Must be absolute because patchflow runs with cmd.Dir = repoPath.
	absRepo, _ := filepath.Abs(repoPath)
	tmpDir := filepath.Join(absRepo, ".patchflow", "bench-out")
	_ = os.MkdirAll(tmpDir, 0755)
	tmpSarif := filepath.Join(tmpDir, "out.sarif")
	tmpJSON := filepath.Join(tmpDir, "out.json")
	tmpMD := filepath.Join(tmpDir, "out.md")

	// Cold run: clear the patchflow cache so OSV/SAST caches start empty.
	coldOut, coldDur, coldExit, coldMem, scanErr := r.runPatchFlow(ctx, repoPath, tmpSarif, tmpJSON, tmpMD, true)
	if scanErr != nil {
		// Record the error but still produce a result with 0 findings so the
		// repo appears in the report with its error noted. This handles cases
		// like SCA API failures that abort the scan before SAST runs.
		r.logf("  scan error: %v", scanErr)
		loc, _ := CountLOC(repoPath)
		m := buildMetrics(spec, &pfJSONOutput{}, loc, coldDur, coldDur, coldExit, coldMem)
		return &RepoResult{Repo: spec, PatchFlow: m, Error: scanErr.Error()}, nil
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

	// Copy temp output files to their final destinations in the results dir.
	copyFileIfExists(tmpSarif, sarifPath)
	copyFileIfExists(tmpJSON, jsonPath)
	copyFileIfExists(tmpMD, mdPath)
	_ = os.RemoveAll(tmpDir)

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
		if err := os.WriteFile(jsonPath, out, 0600); err != nil {
			return pf, dur, exitCode, memMB, fmt.Errorf("write JSON artifact %s: %w", jsonPath, err)
		}
	}
	// Persist a markdown report via a second lightweight invocation only when a
	// path is requested AND we did not already produce one. The scan run command
	// auto-saves markdown to .patchflow/reports/, so copy that if present.
	if mdPath != "" {
		if err := copyAutoMarkdown(repoPath, mdPath); err != nil {
			return pf, dur, exitCode, memMB, fmt.Errorf("copy markdown artifact to %s: %w", mdPath, err)
		}
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
		// If a ref is pinned, checkout it. A failed checkout means the cached
		// repo is not at the requested revision, so surface the error rather
		// than silently measuring the wrong code.
		if spec.Ref != "" {
			if out, err := exec.CommandContext(ctx, "git", "-C", dest, "checkout", spec.Ref).CombinedOutput(); err != nil {
				return "", fmt.Errorf("checkout %s in %s: %w (%s)", spec.Ref, dest, err, truncate(out, 200))
			}
		}
		return dest, nil
	}

	_ = os.RemoveAll(dest)
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return "", err
	}
	cloneCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	// Clone with --depth 1. If a ref is specified, try --branch first (works
	// for branches and tags). If that fails, fall back to a full clone + checkout.
	args := []string{"clone", "--depth", "1"}
	if spec.Ref != "" {
		args = append(args, "--branch", spec.Ref)
	}
	args = append(args, spec.URL, dest)
	cmd := exec.CommandContext(cloneCtx, "git", args...)
	if combined, err := cmd.CombinedOutput(); err != nil {
		// Fallback: clone default branch, then checkout the ref (handles tags
		// that aren't directly cloneable with --depth 1, and renamed default
		// branches like main vs master).
		if spec.Ref != "" {
			_ = os.RemoveAll(dest)
			fbCmd := exec.CommandContext(cloneCtx, "git", "clone", "--depth", "50", spec.URL, dest)
			if fbErr := fbCmd.Run(); fbErr != nil {
				return "", fmt.Errorf("git clone: %w (initial: %s)", fbErr, truncate(combined, 200))
			}
			coCmd := exec.CommandContext(cloneCtx, "git", "-C", dest, "checkout", spec.Ref)
			if coErr := coCmd.Run(); coErr != nil {
				return "", fmt.Errorf("git checkout %s: %w (clone: %s)", spec.Ref, coErr, truncate(combined, 200))
			}
		} else {
			return "", fmt.Errorf("git clone: %w (%s)", err, truncate(combined, 300))
		}
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
// matching rule IDs, CVE IDs, and CWE IDs found in the scan output.
//
// Matching logic:
//   - Exact match on rule ID, CVE ID, or CWE ID
//   - CWE prefix match: a finding with CWE-79 matches an expected CWE-79-XSS
//     (the dash-suffix is treated as a subcategory of the base CWE)
func applyExpected(m *Metrics, pf *pfJSONOutput, spec RepoSpec) {
	if len(spec.ExpectedFindings) == 0 || pf == nil {
		return
	}
	found := map[string]bool{}
	foundCWEs := []string{}
	for _, f := range pf.Analysis.Findings {
		if f.RuleID != "" {
			found[f.RuleID] = true
		}
		if f.CVEID != "" {
			found[f.CVEID] = true
		}
		if f.CWEID != "" {
			found[f.CWEID] = true
			foundCWEs = append(foundCWEs, f.CWEID)
		}
	}
	for _, exp := range spec.ExpectedFindings {
		if found[exp] {
			m.ExpectedDetected = append(m.ExpectedDetected, exp)
			continue
		}
		// CWE prefix match: if the expected finding is a CWE subcategory
		// (e.g., "CWE-79-XSS"), check if any found CWE is a prefix of it.
		// "CWE-79" matches "CWE-79-XSS" but not vice versa.
		matched := false
		for _, cwe := range foundCWEs {
			if strings.HasPrefix(exp, cwe+"-") {
				matched = true
				break
			}
		}
		if matched {
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
// It also detects the error format `{"error": "..."}` that the CLI emits when a
// scan fails (e.g. SCA API error), returning an error so the runner can record
// it instead of silently treating it as 0 findings.
func parsePatchFlowJSON(stdout []byte) (*pfJSONOutput, error) {
	stdout = bytes.TrimSpace(stdout)
	if len(stdout) == 0 {
		return nil, fmt.Errorf("empty stdout from patchflow")
	}
	// Detect CLI error responses before attempting to parse as analysis output.
	var errProbe struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(stdout, &errProbe) == nil && errProbe.Error != "" {
		return nil, fmt.Errorf("patchflow scan error: %s", errProbe.Error)
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

// copyFileIfExists copies src to dst if src exists. Silent no-op if src is missing.
func copyFileIfExists(src, dst string) {
	data, err := os.ReadFile(src)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(dst), 0755)
	_ = os.WriteFile(dst, data, 0644)
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
	return os.WriteFile(dest, data, 0600)
}
