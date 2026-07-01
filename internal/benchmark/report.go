package benchmark

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// WriteSummaryJSON writes the summary as indented JSON.
func WriteSummaryJSON(s *Summary, path string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling benchmark summary: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("writing benchmark summary to %s: %w", path, err)
	}
	return nil
}

// WriteSummaryMarkdown writes a human-readable benchmark report. It respects
// the responsible-disclosure policy: per-finding detail is only included for
// repos where PublishDetailFor() is true. For clean real-world repos, only
// aggregate counts and a disclosure note are emitted.
func WriteSummaryMarkdown(s *Summary, results []RepoResult, path string) error {
	var sb strings.Builder

	sb.WriteString("# PatchFlow CLI Benchmark Report\n\n")
	sb.WriteString(fmt.Sprintf("**Suite:** %s  \n", s.Suite))
	sb.WriteString(fmt.Sprintf("**Date:** %s  \n", s.Date))
	sb.WriteString(fmt.Sprintf("**PatchFlow version:** %s  \n", s.PatchFlowVersion))
	if s.Hardware != "" {
		sb.WriteString(fmt.Sprintf("**Hardware:** %s  \n", s.Hardware))
	}
	sb.WriteString("\n")

	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("| Metric | Value |\n| --- | --- |\n"))
	sb.WriteString(fmt.Sprintf("| Repos scanned | %d |\n", s.ReposScanned))
	sb.WriteString(fmt.Sprintf("| Total LOC | %s |\n", formatInt(s.TotalLOC)))
	sb.WriteString(fmt.Sprintf("| Total findings | %d |\n", s.TotalFindings))
	sb.WriteString(fmt.Sprintf("| Framework findings | %d |\n", s.TotalFrameworkFindings))
	sb.WriteString(fmt.Sprintf("| Confirmed true positives | %d |\n", s.ConfirmedTruePos))
	sb.WriteString(fmt.Sprintf("| False positives | %d |\n", s.FalsePositives))
	sb.WriteString(fmt.Sprintf("| Unknown / unreviewed | %d |\n", s.UnknownUnreviewed))
	sb.WriteString(fmt.Sprintf("| Average scan time | %s |\n", s.AvgScanTime.Round(time.Millisecond)))
	sb.WriteString(fmt.Sprintf("| Cache warm speedup | %.1f%% |\n", s.CacheWarmSpeedup))
	sb.WriteString(fmt.Sprintf("| SARIF valid | %d/%d |\n", s.SARIFValidCount, s.SARIFTotalCount))
	if s.AvgPrecision > 0 {
		sb.WriteString(fmt.Sprintf("| Average precision | %.1f%% |\n", s.AvgPrecision*100))
	}
	if s.AvgRecall > 0 {
		sb.WriteString(fmt.Sprintf("| Average recall | %.1f%% |\n", s.AvgRecall*100))
	}
	if s.AvgFrameworkRecall > 0 {
		sb.WriteString(fmt.Sprintf("| Average framework recall | %.1f%% |\n", s.AvgFrameworkRecall*100))
	}
	if s.AvgNoiseRate > 0 {
		sb.WriteString(fmt.Sprintf("| Average noise rate | %.1f%% |\n", s.AvgNoiseRate*100))
	}
	sb.WriteString("\n")

	// Per-repo results table.
	sb.WriteString("## Per-repository results\n\n")
	sb.WriteString("| Repo | Type | Language | LOC | Files | Findings | Framework | Cold | Warm | Speedup | SARIF | Exit |\n")
	sb.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, m := range s.PerRepo {
		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %d | %d | %d | %s | %s | %.0f%% | %s | %d |\n",
			m.RepoName, m.RepoType, m.Language, formatInt(m.LOC), m.FilesScanned,
			m.TotalFindings, m.FrameworkFindings, m.ColdDuration.Round(time.Millisecond), m.WarmDuration.Round(time.Millisecond),
			m.CacheSpeedup, sarifCell(m), m.ExitCode))
	}
	sb.WriteString("\n")

	// Findings by severity across all repos.
	bySev := map[string]int{}
	for _, m := range s.PerRepo {
		for sev, n := range m.BySeverity {
			bySev[sev] += n
		}
	}
	if len(bySev) > 0 {
		sb.WriteString("### Findings by severity\n\n")
		sb.WriteString("| Severity | Count |\n| --- | --- |\n")
		for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
			if n, ok := bySev[sev]; ok && n > 0 {
				sb.WriteString(fmt.Sprintf("| %s | %d |\n", sev, n))
			}
		}
		sb.WriteString("\n")
	}

	// Tool comparison.
	if len(s.ToolComparison) > 0 {
		sb.WriteString("## Tool comparison\n\n")
		sb.WriteString("PatchFlow is not trying to replace every specialized scanner. It gives developers one\n")
		sb.WriteString("local-first workflow for actionable findings, explainable results, baselines, CI exit\ncodes, and SARIF.\n\n")
		sb.WriteString("| Tool | Total findings (all repos) |\n| --- | --- |\n")
		// PatchFlow first.
		sb.WriteString(fmt.Sprintf("| patchflow | %d |\n", s.TotalFindings))
		for tool, n := range s.ToolComparison {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", tool, n))
		}
		sb.WriteString("\n")
	}

	// Recall detail for repos with expected findings.
	hasRecall := false
	for _, res := range results {
		if len(res.Repo.ExpectedFindings) > 0 {
			hasRecall = true
			break
		}
	}
	if hasRecall {
		sb.WriteString("## Recall (known-vulnerable repos)\n\n")
		sb.WriteString("| Repo | Expected | Detected | Missed | Recall |\n| --- | --- | --- | --- | --- |\n")
		for _, res := range results {
			if len(res.Repo.ExpectedFindings) == 0 {
				continue
			}
			m := res.PatchFlow
			sb.WriteString(fmt.Sprintf("| %s | %d | %d | %d | %.0f%% |\n",
				res.Repo.Name, len(res.Repo.ExpectedFindings), len(m.ExpectedDetected),
				len(m.ExpectedMissed), m.Recall*100))
		}
		sb.WriteString("\n")
	}

	hasFrameworkRecall := false
	for _, res := range results {
		if len(res.Repo.ExpectedFrameworkFindings) > 0 {
			hasFrameworkRecall = true
			break
		}
	}
	if hasFrameworkRecall {
		sb.WriteString("## Framework recall\n\n")
		sb.WriteString("| Repo | Expected | Detected | Missed | Recall | Framework findings |\n| --- | --- | --- | --- | --- | --- |\n")
		for _, res := range results {
			if len(res.Repo.ExpectedFrameworkFindings) == 0 {
				continue
			}
			m := res.PatchFlow
			sb.WriteString(fmt.Sprintf("| %s | %d | %d | %d | %.0f%% | %d |\n",
				res.Repo.Name, len(res.Repo.ExpectedFrameworkFindings), len(m.ExpectedFrameworkDetected),
				len(m.ExpectedFrameworkMissed), m.FrameworkRecall*100, m.FrameworkFindings))
		}
		sb.WriteString("\n")
	}

	// Responsible disclosure note.
	hasClean := false
	for _, res := range results {
		if !res.Repo.PublishDetailFor() {
			hasClean = true
			break
		}
	}
	if hasClean {
		sb.WriteString("## Responsible disclosure\n\n")
		sb.WriteString("PatchFlow found issues in active, maintained repositories. Details were **not**\n")
		sb.WriteString("published. Maintainers were contacted privately where appropriate. Only\n")
		sb.WriteString("intentionally-vulnerable and historical repos expose per-finding detail.\n\n")
	}

	// Limitations.
	if len(s.Limitations) > 0 {
		sb.WriteString("## Limitations\n\n")
		for _, l := range s.Limitations {
			sb.WriteString(fmt.Sprintf("- %s\n", l))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("## Methodology\n\n")
	sb.WriteString("- PatchFlow is invoked as a real subprocess (`patchflow scan run --json`) so the\n  benchmark measures actual CLI behavior including startup, exit codes, and SARIF.\n")
	sb.WriteString("- Cold runs clear `.patchflow/cache/`; warm runs reuse it to measure cache speedup.\n")
	sb.WriteString("- LOC counts non-blank lines in scannable source files, excluding vendor/build dirs.\n")
	sb.WriteString("- SARIF validity checks the 2.1.0 schema, run presence, and driver name.\n")
	sb.WriteString("- Comparison tools run with their native JSON output and best-effort parsing.\n")
	sb.WriteString("- Tool versions and exact commands are recorded in `raw/` for reproducibility.\n")

	return os.WriteFile(path, []byte(sb.String()), 0600)
}

func sarifCell(m Metrics) string {
	if !m.SARIFGenerated {
		return "no"
	}
	if m.SARIFValid {
		return "valid"
	}
	return "invalid"
}

func formatInt(n int) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	// thousands separator
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

// LoadSummary reads a previously written summary.json.
func LoadSummary(path string) (*Summary, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Summary
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// CompareSummaries loads all summary.json files under a results root (one per
// month/run) and returns them keyed by their directory name, so trends across
// runs can be inspected.
func CompareSummaries(resultsRoot string) (map[string]*Summary, error) {
	entries, err := os.ReadDir(resultsRoot)
	if err != nil {
		return nil, err
	}
	out := map[string]*Summary{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		p := filepath.Join(resultsRoot, e.Name(), "summary.json")
		if s, err := LoadSummary(p); err == nil {
			out[e.Name()] = s
		}
	}
	return out, nil
}
