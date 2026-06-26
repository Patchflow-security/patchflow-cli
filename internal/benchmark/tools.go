package benchmark

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ComparisonTool is the interface implemented by each external scanner wrapper.
// Run executes the tool against repoPath and returns a finding count plus the
// path to the raw output artifact. Available reports whether the tool binary
// is installed and should be invoked.
type ComparisonTool interface {
	Name() string
	Available() bool
	Run(ctx context.Context, repoPath, outDir string) (ToolResult, error)
}

// allTools returns the registered comparison tools keyed by name.
func allTools() map[string]ComparisonTool {
	tools := []ComparisonTool{
		&semgrepTool{},
		&trivyTool{},
		&gitleaksTool{},
		&osvScannerTool{},
	}
	m := make(map[string]ComparisonTool, len(tools))
	for _, t := range tools {
		m[t.Name()] = t
	}
	return m
}

// runComparisonTools runs each requested tool that is installed against the repo.
func (r *Runner) runComparisonTools(ctx context.Context, spec RepoSpec, repoPath, resultsDir string) map[string]ToolResult {
	registry := allTools()
	rawDir := filepath.Join(resultsDir, "raw")
	out := make(map[string]ToolResult, len(r.Config.Tools))
	for _, name := range r.Config.Tools {
		tool, ok := registry[name]
		if !ok {
			out[name] = ToolResult{Tool: name, Available: false, Error: "unknown tool"}
			continue
		}
		if !tool.Available() {
			out[name] = ToolResult{Tool: name, Available: false}
			r.logf("  [compare] %s: not installed, skipping", name)
			continue
		}
		r.logf("  [compare] running %s...", name)
		runCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		tr, err := tool.Run(runCtx, repoPath, rawDir)
		cancel()
		if err != nil {
			tr.Error = err.Error()
			r.logf("  [compare] %s error: %v", name, err)
		} else {
			r.logf("  [compare] %s: %d findings in %s", name, tr.Findings, tr.Duration.Round(time.Millisecond))
		}
		out[name] = tr
	}
	return out
}

// --- Semgrep ---

type semgrepTool struct{}

func (s *semgrepTool) Name() string    { return "semgrep" }
func (s *semgrepTool) Available() bool { _, err := exec.LookPath("semgrep"); return err == nil }

func (s *semgrepTool) Run(ctx context.Context, repoPath, outDir string) (ToolResult, error) {
	outFile := filepath.Join(outDir, "semgrep-"+filepath.Base(repoPath)+".json")
	args := []string{"--json", "--quiet", "--config", "auto", "--output", outFile, repoPath}
	start := time.Now()
	cmd := exec.CommandContext(ctx, "semgrep", args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	dur := time.Since(start)
	exit := exitCodeFromErr(runErr)
	// Semgrep returns exit 1 when findings are found; that is not an error here.
	if runErr != nil && exit != 1 {
		return ToolResult{Tool: "semgrep", Duration: dur, ExitCode: exit, Error: runErr.Error()}, runErr
	}
	count := countSemgrepResults(outFile)
	return ToolResult{Tool: "semgrep", Findings: count, Duration: dur, ExitCode: exit, OutputPath: outFile, Available: true}, nil
}

func countSemgrepResults(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var rep struct {
		Results []json.RawMessage `json:"results"`
	}
	if json.Unmarshal(data, &rep) != nil {
		return 0
	}
	return len(rep.Results)
}

// --- Trivy ---

type trivyTool struct{}

func (t *trivyTool) Name() string    { return "trivy" }
func (t *trivyTool) Available() bool { _, err := exec.LookPath("trivy"); return err == nil }

func (t *trivyTool) Run(ctx context.Context, repoPath, outDir string) (ToolResult, error) {
	outFile := filepath.Join(outDir, "trivy-"+filepath.Base(repoPath)+".json")
	// fs scan of the repo root, output JSON. --skip-dirs avoids heavy dirs.
	args := []string{"fs", "--quiet", "--format", "json", "--skip-dirs", "node_modules,vendor,.git",
		"--output", outFile, repoPath}
	start := time.Now()
	cmd := exec.CommandContext(ctx, "trivy", args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	dur := time.Since(start)
	exit := exitCodeFromErr(runErr)
	if runErr != nil && exit != 1 {
		return ToolResult{Tool: "trivy", Duration: dur, ExitCode: exit, Error: runErr.Error()}, runErr
	}
	count := countTrivyResults(outFile)
	return ToolResult{Tool: "trivy", Findings: count, Duration: dur, ExitCode: exit, OutputPath: outFile, Available: true}, nil
}

func countTrivyResults(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var rep struct {
		Results []struct {
			Vulnerabilities []json.RawMessage `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	if json.Unmarshal(data, &rep) != nil {
		return 0
	}
	count := 0
	for _, r := range rep.Results {
		count += len(r.Vulnerabilities)
	}
	return count
}

// --- Gitleaks ---

type gitleaksTool struct{}

func (g *gitleaksTool) Name() string    { return "gitleaks" }
func (g *gitleaksTool) Available() bool { _, err := exec.LookPath("gitleaks"); return err == nil }

func (g *gitleaksTool) Run(ctx context.Context, repoPath, outDir string) (ToolResult, error) {
	outFile := filepath.Join(outDir, "gitleaks-"+filepath.Base(repoPath)+".json")
	args := []string{"detect", "--source", repoPath, "--report-format", "json", "--report-path", outFile, "--no-banner"}
	start := time.Now()
	cmd := exec.CommandContext(ctx, "gitleaks", args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	dur := time.Since(start)
	exit := exitCodeFromErr(runErr)
	// Gitleaks returns exit 1 when leaks are found.
	if runErr != nil && exit != 1 {
		return ToolResult{Tool: "gitleaks", Duration: dur, ExitCode: exit, Error: runErr.Error()}, runErr
	}
	count := countGitleaksResults(outFile)
	return ToolResult{Tool: "gitleaks", Findings: count, Duration: dur, ExitCode: exit, OutputPath: outFile, Available: true}, nil
}

func countGitleaksResults(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	// gitleaks v8 emits a JSON array of findings.
	var findings []json.RawMessage
	if json.Unmarshal(data, &findings) != nil {
		return 0
	}
	return len(findings)
}

// --- OSV-Scanner ---

type osvScannerTool struct{}

func (o *osvScannerTool) Name() string    { return "osv-scanner" }
func (o *osvScannerTool) Available() bool { _, err := exec.LookPath("osv-scanner"); return err == nil }

func (o *osvScannerTool) Run(ctx context.Context, repoPath, outDir string) (ToolResult, error) {
	outFile := filepath.Join(outDir, "osv-scanner-"+filepath.Base(repoPath)+".json")
	args := []string{"scan", "--recursive", "--format", "json", "--output", outFile, repoPath}
	start := time.Now()
	cmd := exec.CommandContext(ctx, "osv-scanner", args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	dur := time.Since(start)
	exit := exitCodeFromErr(runErr)
	// osv-scanner returns exit 1 when vulnerabilities are found.
	if runErr != nil && exit != 1 {
		return ToolResult{Tool: "osv-scanner", Duration: dur, ExitCode: exit, Error: fmt.Sprintf("%s: %s", runErr, stderr.String())}, runErr
	}
	count := countOSVResults(outFile)
	return ToolResult{Tool: "osv-scanner", Findings: count, Duration: dur, ExitCode: exit, OutputPath: outFile, Available: true}, nil
}

func countOSVResults(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var rep struct {
		Results []struct {
			Packages []struct {
				Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
			} `json:"packages"`
		} `json:"results"`
	}
	if json.Unmarshal(data, &rep) != nil {
		return 0
	}
	count := 0
	for _, r := range rep.Results {
		for _, p := range r.Packages {
			count += len(p.Vulnerabilities)
		}
	}
	return count
}
