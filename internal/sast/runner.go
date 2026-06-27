// Package sast runs static analysis security tools on the repository.
// It uses embedded scanners (Go SAST, secret scanner, multi-language pattern
// scanner) that require no external installation, and supplements them with
// external tools (gosec, bandit, semgrep, gitleaks) when available.
//
// The embedded scanners run first and always provide baseline coverage.
// External tools run second and add deeper analysis when installed.
package sast

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/patchflow/patchflow-cli/internal/analysis"
	"github.com/patchflow/patchflow-cli/internal/ignore"
	"github.com/patchflow/patchflow-cli/internal/sast/customrules"
	"github.com/patchflow/patchflow-cli/internal/sast/gosast"
	"github.com/patchflow/patchflow-cli/internal/sast/incremental"
	"github.com/patchflow/patchflow-cli/internal/sast/patterns"
	"github.com/patchflow/patchflow-cli/internal/sast/secrets"
	"github.com/patchflow/patchflow-cli/internal/sast/suppression"
	"github.com/patchflow/patchflow-cli/internal/sast/taint"
	"github.com/patchflow/patchflow-cli/internal/sast/taintpatterns"
	"github.com/patchflow/patchflow-cli/internal/sast/treesitter"
)

// Tool represents an external SAST tool that can be invoked via subprocess.
type Tool struct {
	Name        string
	Binary      string
	Language    string // primary language (go, python, multi, secrets)
	IsAvailable func() bool
	Run         func(ctx context.Context, root string) ([]analysis.Finding, error)
}

// Runner manages embedded scanners and external SAST tools.
type Runner struct {
	// Embedded scanners (always available, no installation required)
	gosastAnalyzer     *gosast.Analyzer
	secretScanner      *secrets.Scanner
	patternScanner     *patterns.Scanner
	taintAnalyzer      *taint.Analyzer
	treesitterAnalyzer *treesitter.Analyzer
	taintPatternAnalyzer *taintpatterns.Analyzer

	// Suppression manager for //patchflow:ignore directives
	suppressionMgr *suppression.Manager

	// External tools (optional, supplement embedded scanners)
	Tools        []Tool
	ChangedOnly  bool
	ChangedFiles []string
	Timeout      time.Duration

	// Flags to control which scanners run
	NoEmbeddedGo           bool
	NoEmbeddedSecrets      bool
	NoEmbeddedPatterns     bool
	NoEmbeddedTaint        bool
	NoEmbeddedTreeSitter   bool
	NoEmbeddedTaintPatterns bool

	// ShowSuppressed controls whether suppressed findings are included in output
	ShowSuppressed bool

	// IncludeTests controls whether findings from test files are included.
	IncludeTests bool

	// CustomRulesPath is the path to a custom rules YAML file.
	// If empty, the runner looks for .patchflow/rules.yaml in the project root.
	CustomRulesPath string

	// IncrementalScan enables incremental scanning: only files that changed
	// since the last scan (tracked via .patchflow/cache/sast_state.json) are
	// re-scanned by the file-based scanners (patterns, secrets, tree-sitter).
	// Go SAST and taint analysis always run fully (they use go/packages).
	IncrementalScan bool

	// GitChangedFiles is the list of files changed according to git diff.
	// When set, the incremental scanner uses this as a pre-filter instead of
	// walking the entire tree. This gives the fastest incremental scans.
	GitChangedFiles []string

	// RespectGitignore controls whether .gitignore patterns are loaded and
	// used to skip files during scanning. When true, a .gitignore matcher is
	// initialized on first use and shared across all embedded scanners.
	RespectGitignore bool
}

// NewRunner creates a SAST runner with embedded scanners and external tools.
func NewRunner() *Runner {
	r := &Runner{
		Timeout:               120 * time.Second,
		gosastAnalyzer:        gosast.NewAnalyzer(),
		secretScanner:         secrets.NewScanner(),
		patternScanner:        patterns.NewScanner(),
		taintAnalyzer:         taint.NewAnalyzer(),
		treesitterAnalyzer:    treesitter.NewAnalyzer(),
		taintPatternAnalyzer:  taintpatterns.NewAnalyzer(),
		suppressionMgr:        suppression.NewManager(),
	}

	r.Tools = []Tool{
		{
			Name:        "gosec",
			Binary:      "gosec",
			Language:    "go",
			IsAvailable: func() bool { return commandExists("gosec") },
			Run:         runGosec,
		},
		{
			Name:        "bandit",
			Binary:      "bandit",
			Language:    "python",
			IsAvailable: func() bool { return commandExists("bandit") },
			Run:         runBandit,
		},
		{
			Name:        "semgrep",
			Binary:      "semgrep",
			Language:    "multi",
			IsAvailable: func() bool { return commandExists("semgrep") },
			Run:         runSemgrep,
		},
		{
			Name:        "gitleaks",
			Binary:      "gitleaks",
			Language:    "secrets",
			IsAvailable: func() bool { return commandExists("gitleaks") },
			Run:         runGitleaks,
		},
	}

	return r
}

// loadCustomRules loads custom rules from a YAML file and adds them to the
// pattern scanner. If CustomRulesPath is set, it loads from that path.
// Otherwise, it looks for .patchflow/rules.yaml in the project root.
func (r *Runner) loadCustomRules(root string) error {
	var rules []patterns.PatternRule
	var err error

	if r.CustomRulesPath != "" {
		rules, err = customrules.LoadFromFile(r.CustomRulesPath)
	} else {
		rules, err = customrules.LoadFromDir(root)
	}
	if err != nil {
		return err
	}
	if len(rules) > 0 {
		r.patternScanner.AddRules(rules)
	}
	return nil
}

// RuleGroup represents a group of rules from a specific scanner.
type RuleGroup struct {
	Scanner   string // "gosast-embedded", "secrets-embedded", "patterns-embedded"
	Language  string // "go", "multi", "secrets"
	RuleCount int
	Rules     []RuleEntry
}

// RuleEntry represents a single rule for display purposes.
type RuleEntry struct {
	ID       string
	Title    string
	Severity string
}

// AllRules returns all registered rules from all embedded scanners.
// Custom rules loaded from YAML are included if LoadCustomRules was called.
func (r *Runner) AllRules() []RuleGroup {
	var groups []RuleGroup

	// Go SAST rules
	if !r.NoEmbeddedGo {
		gosastRules := r.gosastAnalyzer.Rules()
		entries := make([]RuleEntry, 0, len(gosastRules))
		for _, ri := range gosastRules {
			entries = append(entries, RuleEntry{
				ID:       ri.ID,
				Title:    ri.What,
				Severity: string(ri.Severity),
			})
		}
		groups = append(groups, RuleGroup{
			Scanner:   "gosast-embedded",
			Language:  "go",
			RuleCount: len(entries),
			Rules:     entries,
		})
	}

	// Secret scanner rules
	if !r.NoEmbeddedSecrets {
		secretRules := r.secretScanner.Rules()
		entries := make([]RuleEntry, 0, len(secretRules))
		for _, si := range secretRules {
			entries = append(entries, RuleEntry{
				ID:       "SECRET-" + si.Name,
				Title:    si.Name,
				Severity: string(si.Severity),
			})
		}
		groups = append(groups, RuleGroup{
			Scanner:   "secrets-embedded",
			Language:  "secrets",
			RuleCount: len(entries),
			Rules:     entries,
		})
	}

	// Pattern scanner rules (includes custom rules if loaded)
	if !r.NoEmbeddedPatterns {
		patternRules := r.patternScanner.Rules()
		entries := make([]RuleEntry, 0, len(patternRules))
		for _, pr := range patternRules {
			entries = append(entries, RuleEntry{
				ID:       pr.ID,
				Title:    pr.Title,
				Severity: string(pr.Severity),
			})
		}
		groups = append(groups, RuleGroup{
			Scanner:   "patterns-embedded",
			Language:  "multi",
			RuleCount: len(entries),
			Rules:     entries,
		})
	}

	// Taint analysis rules (SSA-based, Go only)
	if !r.NoEmbeddedTaint && !r.NoEmbeddedGo {
		taintRules := r.taintAnalyzer.Rules()
		entries := make([]RuleEntry, 0, len(taintRules))
		for _, tr := range taintRules {
			entries = append(entries, RuleEntry{
				ID:       tr.ID,
				Title:    tr.Title,
				Severity: tr.Severity,
			})
		}
		groups = append(groups, RuleGroup{
			Scanner:   "taint-ssa",
			Language:  "go",
			RuleCount: len(entries),
			Rules:     entries,
		})
	}

	// Tree-sitter AST rules (non-Go languages)
	if !r.NoEmbeddedTreeSitter {
		tsRules := r.treesitterAnalyzer.Rules()
		entries := make([]RuleEntry, 0, len(tsRules))
		for _, tr := range tsRules {
			entries = append(entries, RuleEntry{
				ID:       tr.ID,
				Title:    tr.Title,
				Severity: tr.Severity,
			})
		}
		groups = append(groups, RuleGroup{
			Scanner:   "treesitter-ast",
			Language:  "multi",
			RuleCount: len(entries),
			Rules:     entries,
		})
	}

	// Taint pattern rules (Python and JS/TS source-sink analysis)
	if !r.NoEmbeddedTaintPatterns {
		tpRules := r.taintPatternAnalyzer.Rules()
		entries := make([]RuleEntry, 0, len(tpRules))
		for _, tr := range tpRules {
			entries = append(entries, RuleEntry{
				ID:       tr.ID,
				Title:    tr.Title,
				Severity: string(tr.Severity),
			})
		}
		groups = append(groups, RuleGroup{
			Scanner:   "taint-patterns",
			Language:  "multi",
			RuleCount: len(entries),
			Rules:     entries,
		})
	}

	return groups
}

// LoadCustomRules loads custom rules from the specified path or from
// .patchflow/rules.yaml in the given root directory. This is public so
// commands like `rules list` can load custom rules without running a full scan.
func (r *Runner) LoadCustomRules(root string) error {
	return r.loadCustomRules(root)
}

// AvailableTools returns the names of external tools that are installed and ready to run.
func (r *Runner) AvailableTools() []string {
	var available []string
	for _, t := range r.Tools {
		if t.IsAvailable() {
			available = append(available, t.Name)
		}
	}
	return available
}

// EmbeddedTools returns the names of embedded scanners that are always available.
func (r *Runner) EmbeddedTools() []string {
	return []string{"gosast-embedded", "secrets-embedded", "patterns-embedded", "taint-ssa", "treesitter-ast", "taint-patterns"}
}

// Result is the output of a SAST analysis run.
type Result struct {
	Findings        []analysis.Finding `json:"findings"`
	ToolsRun        []string           `json:"tools_run"`
	ToolsSkipped    []string           `json:"tools_skipped"`
	Errors          []string           `json:"errors,omitempty"`
	SuppressedCount int                `json:"suppressed_count,omitempty"`
}

// Analyze runs all embedded scanners first, then external tools as supplements.
func (r *Runner) Analyze(ctx context.Context, root string) (*Result, error) {
	result := &Result{}

	// --- Phase 0: Load custom rules from YAML ---
	if err := r.loadCustomRules(root); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("custom-rules: %v", err))
	}

	// --- Phase 0b: Load .gitignore matcher if enabled ---
	var ignoreMatcher *ignore.Matcher
	if r.RespectGitignore {
		ignoreCache := ignore.NewCache(root)
		if matcher := ignoreCache.Get(); !matcher.IsEmpty() {
			ignoreMatcher = matcher
			r.secretScanner.SetIgnoreMatcher(matcher)
			r.patternScanner.SetIgnoreMatcher(matcher)
			r.treesitterAnalyzer.SetIgnoreMatcher(matcher)
		}
	}

	// --- Phase 1: Embedded scanners ---
	//
	// Go SAST and taint analysis use go/packages (not file-by-file), so they
	// run as separate goroutines. Pattern, secrets, and tree-sitter scanners
	// use the single-pass parallel file collector for ~4x speedup.
	//
	// Two parallel groups:
	//   Group A: Go SAST + Taint (goroutines, use go/packages)
	//   Group B: Single-pass file dispatch (patterns + secrets + tree-sitter)

	type scannerResult struct {
		name     string
		findings []analysis.Finding
		err      error
	}

	var wg sync.WaitGroup
	// Buffer must be large enough for all possible results:
	// Go SAST (1) + Taint SSA (1) + up to 4 parallel scanners + errors
	resultCh := make(chan scannerResult, 16)

	// Build the git changed file set early — used for Go SAST skip logic
	// and for the file-based scanner pre-filter.
	gitChangedSet := map[string]bool{}
	for _, f := range r.GitChangedFiles {
		gitChangedSet[filepath.Join(root, f)] = true
	}

	// 1a. Embedded Go SAST (gosec rules ported to library)
	// In changed-only mode, skip Go SAST if no .go files changed — it
	// always loads the full module graph via go/packages, so running it
	// when only non-Go files changed is pure waste.
	goFilesChanged := false
	for p := range gitChangedSet {
		if strings.HasSuffix(p, ".go") {
			goFilesChanged = true
			break
		}
	}
	skipGoSAST := r.NoEmbeddedGo || (r.ChangedOnly && len(gitChangedSet) > 0 && !goFilesChanged)

	if !skipGoSAST {
		wg.Add(1)
		go func() {
			defer wg.Done()
			toolCtx, cancel := context.WithTimeout(ctx, r.Timeout)
			findings, err := r.gosastAnalyzer.Analyze(toolCtx, root)
			cancel()
			resultCh <- scannerResult{name: "gosast-embedded", findings: findings, err: err}
		}()
	}

	// 1b. Embedded SSA-based taint analysis (Go only)
	if !r.NoEmbeddedTaint && !skipGoSAST {
		wg.Add(1)
		go func() {
			defer wg.Done()
			toolCtx, cancel := context.WithTimeout(ctx, r.Timeout)
			findings, err := r.taintAnalyzer.Analyze(toolCtx, root)
			cancel()
			resultCh <- scannerResult{name: "taint-ssa", findings: findings, err: err}
		}()
	}

	// 1c. Single-pass parallel scanning for patterns + secrets + tree-sitter + taint-patterns
	// This walks the file tree once and dispatches files to all scanners
	// in parallel using a worker pool, eliminating redundant tree walks.
	// When incremental scanning is enabled, only changed files are processed.
	scanPatterns := !r.NoEmbeddedPatterns
	scanSecrets := !r.NoEmbeddedSecrets
	scanTreeSitter := !r.NoEmbeddedTreeSitter
	scanTaintPatterns := !r.NoEmbeddedTaintPatterns

	// Load incremental state if enabled
	var incState *incremental.State
	if r.IncrementalScan {
		incState = incremental.LoadState(root)
	}

	// Build the set of files to scan. Three modes:
	// 1. GitChangedFiles pre-filter (fastest): only scan files from git diff.
	// 2. Incremental hash-based: walk tree, hash-check each file.
	// 3. Full scan: walk tree, scan everything.
	// (gitChangedSet was built above before the Go SAST section.)

	if scanPatterns || scanSecrets || scanTreeSitter {
		wg.Add(1)
		go func() {
			defer wg.Done()
			scanCtx, cancel := context.WithTimeout(ctx, r.Timeout)
			defer cancel()

			results, errors := runParallelScanners(
				scanCtx, root, ignoreMatcher,
				r.patternScanner, r.secretScanner, r.treesitterAnalyzer, r.taintPatternAnalyzer,
				scanPatterns, scanSecrets, scanTreeSitter, scanTaintPatterns,
				r.IncludeTests, r.Timeout, incState, gitChangedSet,
			)

			for _, e := range errors {
				resultCh <- scannerResult{name: "parallel-scanner", err: fmt.Errorf("%s", e)}
			}
			for scannerName, findings := range results {
				resultCh <- scannerResult{name: scannerName, findings: findings}
			}
		}()
	}

	// Save incremental state after scanning completes
	if r.IncrementalScan && incState != nil {
		defer func() {
			_ = incState.SaveState(root)
		}()
	}

	// Close the result channel in a separate goroutine after all scanners
	// finish. This allows us to drain the channel concurrently with the
	// scanners running, avoiding a deadlock when the channel buffer fills up.
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	for sr := range resultCh {
		if sr.err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", sr.name, sr.err))
		} else {
			if r.ChangedOnly && len(r.ChangedFiles) > 0 {
				sr.findings = filterFindingsToChanged(sr.findings, r.ChangedFiles)
			}
			if !r.IncludeTests {
				sr.findings = filterFindingsToNonTests(sr.findings)
			}
			result.Findings = append(result.Findings, sr.findings...)
			result.ToolsRun = append(result.ToolsRun, sr.name)
		}
	}

	// Deduplicate cross-scanner findings: when two scanners detect the same
	// issue at the same file+line, keep only the one with higher confidence
	// (preferring AST-confirmed tree-sitter findings over regex patterns).
	result.Findings = dedupFindings(result.Findings)

	// --- Phase 2: External tools (supplement embedded scanners) ---

	for _, tool := range r.Tools {
		if !tool.IsAvailable() {
			result.ToolsSkipped = append(result.ToolsSkipped, tool.Name)
			continue
		}

		toolCtx, cancel := context.WithTimeout(ctx, r.Timeout)
		findings, err := tool.Run(toolCtx, root)
		cancel()

		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", tool.Name, err))
			result.ToolsSkipped = append(result.ToolsSkipped, tool.Name)
			continue
		}

		// Filter to changed files if requested
		if r.ChangedOnly && len(r.ChangedFiles) > 0 {
			findings = filterFindingsToChanged(findings, r.ChangedFiles)
		}
		if !r.IncludeTests {
			findings = filterFindingsToNonTests(findings)
		}

		result.Findings = append(result.Findings, findings...)
		result.ToolsRun = append(result.ToolsRun, tool.Name)

	// --- Phase 2b: Apply severity overrides for external tool findings ---
	// External tools (gosec, bandit) may report high severity for rules we
	// intentionally demoted in our embedded scanners. Apply our severity
	// policy to their findings to keep noise consistent.
	result.Findings = applySeverityFindings(result.Findings)
	}

	// --- Phase 3: Apply suppression directives (//patchflow:ignore) ---
	if !r.ShowSuppressed {
		var filtered []analysis.Finding
		suppressedCount := 0
		for _, f := range result.Findings {
			if r.suppressionMgr.IsSuppressed(f.FilePath, f.LineStart, f.RuleID) {
				suppressedCount++
				continue
			}
			filtered = append(filtered, f)
		}
		if suppressedCount > 0 {
			result.SuppressedCount = suppressedCount
		}
		result.Findings = filtered
	}

	return result, nil
}

// dedupFindings removes duplicate findings at the same file+line+rule, keeping
// the one with higher confidence. This prevents both the regex pattern scanner
// and the tree-sitter AST scanner from reporting the same issue twice.
// AST-confirmed findings (treesitter-ast) are preferred over regex-based
// findings (patterns-embedded) when confidence is equal.
//
// The dedup key includes the RuleID so that two different vulnerability types
// on the same line are both kept (e.g., a SQL injection and a hardcoded
// password on the same line should not be deduplicated).
//
// Uses a hash map for O(n) dedup with a slice for order preservation.
func dedupFindings(findings []analysis.Finding) []analysis.Finding {
	type key struct {
		file   string
		line   int
		ruleID string
	}
	best := make(map[key]analysis.Finding)
	var order []key // slice preserves insertion order in O(1) per append
	prio := map[string]int{
		"treesitter-ast":    3, // AST-confirmed findings have highest priority
		"taint-ssa":         3, // SSA-based taint analysis is also high-confidence
		"taint-patterns":    3, // Source-sink taint analysis is high-confidence
		"gosast-embedded":   2, // embedded rules take precedence over external
		"secrets-embedded":  2,
		"patterns-embedded": 2, // embedded patterns are tuned for low noise
		"gosec":             1, // external gosec is noisy, prefer embedded
		"bandit":            1,
		"semgrep":           1,
		"gitleaks":          1,
	}

	for _, f := range findings {
		// Normalize path for dedup key — different scanners may report
		// absolute vs relative paths for the same file. Use the last two
		// path components as a balance between uniqueness and robustness.
		normalizedPath := f.FilePath
		parts := strings.Split(filepath.ToSlash(normalizedPath), "/")
		if len(parts) >= 2 {
			normalizedPath = parts[len(parts)-2] + "/" + parts[len(parts)-1]
		} else if len(parts) == 1 {
			normalizedPath = parts[0]
		}
		// Include RuleID in the key so different vulnerability types on the
		// same line are both kept. Also normalize equivalent rule IDs across
		// scanners (e.g., a tree-sitter rule and pattern rule detecting the
		// same issue may have different IDs — match on title as a fallback).
		ruleKey := f.RuleID
		if ruleKey == "" {
			ruleKey = f.Title
		}
		k := key{file: normalizedPath, line: f.LineStart, ruleID: ruleKey}
		existing, ok := best[k]
		if !ok {
			best[k] = f
			order = append(order, k)
			continue
		}
		// Prefer higher confidence (ConfidenceHigh > ConfidenceMedium > ConfidenceLow)
		if confidenceRank(f.Confidence) > confidenceRank(existing.Confidence) {
			best[k] = f
			continue
		}
		// If same confidence, prefer higher-priority analyzer
		if f.Confidence == existing.Confidence {
			if prio[f.Analyzer] > prio[existing.Analyzer] {
				best[k] = f
			}
		}
	}

	// Preserve insertion order — O(n) via slice iteration
	result := make([]analysis.Finding, 0, len(order))
	for _, k := range order {
		result = append(result, best[k])
	}
	return result
}

// severityOverrides maps rule IDs to the severity that PatchFlow assigns
// intentionally (lower than the external tool's default). This keeps noise
// consistent between embedded and external scanners.
var severityOverrides = map[string]analysis.Severity{
	"G104": analysis.SeverityInfo, // unchecked errors: audit-only
	"G115": analysis.SeverityLow,  // integer overflow: most conversions are safe
}

// applySeverityOverrides adjusts the severity of external tool findings to
// match PatchFlow's intentional severity policy for noisy rules.
func applySeverityFindings(findings []analysis.Finding) []analysis.Finding {
	for i := range findings {
		override, ok := severityOverrides[findings[i].RuleID]
		if !ok {
			continue
		}
		// Only downgrade, never upgrade.
		if severityRank(findings[i].Severity) > severityRank(override) {
			findings[i].Severity = override
		}
	}
	return findings
}

func severityRank(s analysis.Severity) int {
	switch s {
	case analysis.SeverityCritical:
		return 4
	case analysis.SeverityHigh:
		return 3
	case analysis.SeverityMedium:
		return 2
	case analysis.SeverityLow:
		return 1
	default:
		return 0
	}
}

// confidenceRank converts a Confidence string to a numeric rank for comparison.
func confidenceRank(c analysis.Confidence) int {
	switch c {
	case analysis.ConfidenceHigh:
		return 3
	case analysis.ConfidenceMedium:
		return 2
	case analysis.ConfidenceLow:
		return 1
	default:
		return 0
	}
}

func filterFindingsToChanged(findings []analysis.Finding, changedFiles []string) []analysis.Finding {
	changedSet := make(map[string]bool, len(changedFiles))
	for _, f := range changedFiles {
		changedSet[f] = true
	}

	var filtered []analysis.Finding
	for _, f := range findings {
		// Normalize paths for comparison
		normalized := filepath.ToSlash(f.FilePath)
		normalized = strings.TrimPrefix(normalized, "./")
		if changedSet[normalized] {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

func filterFindingsToNonTests(findings []analysis.Finding) []analysis.Finding {
	var filtered []analysis.Finding
	for _, f := range findings {
		if isTestPath(f.FilePath) {
			continue
		}
		filtered = append(filtered, f)
	}
	return filtered
}

func isTestPath(path string) bool {
	normalized := filepath.ToSlash(strings.TrimPrefix(path, "./"))
	lower := strings.ToLower(normalized)
	base := filepath.Base(lower)

	if strings.Contains(lower, "/test/") ||
		strings.Contains(lower, "/tests/") ||
		strings.Contains(lower, "/__tests__/") ||
		strings.Contains(lower, "/spec/") ||
		strings.Contains(lower, "/specs/") {
		return true
	}

	// Build scripts: setup.py commonly uses exec()/os.system() for build steps
	// and is not application code. conftest.py is pytest configuration.
	if base == "setup.py" || base == "conftest.py" || base == "setup.cfg" {
		return true
	}

	return strings.HasSuffix(base, "_test.go") ||
		strings.HasSuffix(base, "_test.py") ||
		(strings.HasPrefix(base, "test_") && strings.HasSuffix(base, ".py")) ||
		strings.HasSuffix(base, ".test.js") ||
		strings.HasSuffix(base, ".spec.js") ||
		strings.HasSuffix(base, ".test.jsx") ||
		strings.HasSuffix(base, ".spec.jsx") ||
		strings.HasSuffix(base, ".test.ts") ||
		strings.HasSuffix(base, ".spec.ts") ||
		strings.HasSuffix(base, ".test.tsx") ||
		strings.HasSuffix(base, ".spec.tsx")
}

// commandExists checks if a binary is available on the PATH.
func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// parseIntSafe converts a string to an int, returning 0 on failure.
// gosec outputs line numbers as strings in its JSON format.
func parseIntSafe(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}

// --- gosec ---

type gosecReport struct {
	Issues []gosecIssue         `json:"Issues"`
	Rules  map[string]gosecRule `json:"Rules"`
}

type gosecIssue struct {
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	RuleID     string `json:"rule_id"`
	Details    string `json:"details"`
	File       string `json:"file"`
	Line       string `json:"line"`
	Col        string `json:"column"`
	What       string `json:"what"`
	Code       string `json:"code"`
}

type gosecRule struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

func runGosec(ctx context.Context, root string) ([]analysis.Finding, error) {
	cmd := exec.CommandContext(ctx, "gosec", "-fmt=json", "-quiet", "./...")
	cmd.Dir = root
	output, err := cmd.Output()
	if err != nil {
		// gosec returns non-zero exit code when issues are found
		if len(output) > 0 {
			// parse the output anyway
		} else {
			return nil, fmt.Errorf("gosec execution failed: %w", err)
		}
	}

	var report gosecReport
	if err := json.Unmarshal(output, &report); err != nil {
		return nil, fmt.Errorf("failed to parse gosec output: %w", err)
	}

	var findings []analysis.Finding
	for _, issue := range report.Issues {
		rule, hasRule := report.Rules[issue.RuleID]
		title := issue.What
		desc := issue.Details
		if hasRule {
			if title == "" {
				title = rule.Title
			}
			if desc == "" {
				desc = rule.Description
			}
		}
		// Fall back to details or rule_id if title is still empty
		if title == "" {
			title = desc
		}
		if title == "" {
			title = issue.RuleID
		}

		lineNum := parseIntSafe(issue.Line)

		findings = append(findings, analysis.Finding{
			ID:          fmt.Sprintf("sast-gosec-%s-%s-%d", issue.RuleID, filepath.Base(issue.File), lineNum),
			Type:        analysis.TypeSAST,
			Analyzer:    "gosec",
			Severity:    normalizeGosecSeverity(issue.Severity),
			Confidence:  normalizeGosecConfidence(issue.Confidence),
			Title:       title,
			Description: desc,
			FilePath:    issue.File,
			LineStart:   lineNum,
			RuleID:      issue.RuleID,
			Evidence:    issue.Code,
			DetectedAt:  time.Now(),
		})
	}

	return findings, nil
}

func normalizeGosecSeverity(s string) analysis.Severity {
	switch strings.ToUpper(s) {
	case "HIGH":
		return analysis.SeverityHigh
	case "MEDIUM":
		return analysis.SeverityMedium
	case "LOW":
		return analysis.SeverityLow
	default:
		return analysis.SeverityInfo
	}
}

func normalizeGosecConfidence(s string) analysis.Confidence {
	switch strings.ToUpper(s) {
	case "HIGH":
		return analysis.ConfidenceHigh
	case "MEDIUM":
		return analysis.ConfidenceMedium
	case "LOW":
		return analysis.ConfidenceLow
	default:
		return analysis.ConfidenceLow
	}
}

// --- bandit ---

type banditReport struct {
	Results []banditResult `json:"results"`
	Errors  []interface{}  `json:"errors"`
}

type banditResult struct {
	TestID          string `json:"test_id"`
	TestName        string `json:"test_name"`
	IssueSeverity   string `json:"issue_severity"`
	IssueConfidence string `json:"issue_confidence"`
	IssueText       string `json:"issue_text"`
	Filename        string `json:"filename"`
	LineNumber      int    `json:"line_number"`
	ColNumber       int    `json:"col_number"`
	MoreInfo        string `json:"more_info"`
	Code            string `json:"issue_cwe"`
}

func runBandit(ctx context.Context, root string) ([]analysis.Finding, error) {
	// Find Python files to scan
	cmd := exec.CommandContext(ctx, "bandit", "-r", ".", "-f", "json", "-q")
	cmd.Dir = root
	output, err := cmd.Output()
	if err != nil {
		if len(output) > 0 {
			// bandit returns non-zero when issues found
		} else {
			return nil, fmt.Errorf("bandit execution failed: %w", err)
		}
	}

	var report banditReport
	if err := json.Unmarshal(output, &report); err != nil {
		return nil, fmt.Errorf("failed to parse bandit output: %w", err)
	}

	var findings []analysis.Finding
	for _, r := range report.Results {
		findings = append(findings, analysis.Finding{
			ID:          fmt.Sprintf("sast-bandit-%s-%s-%d", r.TestID, filepath.Base(r.Filename), r.LineNumber),
			Type:        analysis.TypeSAST,
			Analyzer:    "bandit",
			Severity:    normalizeBanditSeverity(r.IssueSeverity),
			Confidence:  normalizeBanditConfidence(r.IssueConfidence),
			Title:       r.TestName,
			Description: r.IssueText,
			FilePath:    r.Filename,
			LineStart:   r.LineNumber,
			RuleID:      r.TestID,
			AdvisoryURL: r.MoreInfo,
			DetectedAt:  time.Now(),
		})
	}

	return findings, nil
}

func normalizeBanditSeverity(s string) analysis.Severity {
	switch strings.ToUpper(s) {
	case "HIGH":
		return analysis.SeverityHigh
	case "MEDIUM":
		return analysis.SeverityMedium
	case "LOW":
		return analysis.SeverityLow
	default:
		return analysis.SeverityInfo
	}
}

func normalizeBanditConfidence(s string) analysis.Confidence {
	switch strings.ToUpper(s) {
	case "HIGH":
		return analysis.ConfidenceHigh
	case "MEDIUM":
		return analysis.ConfidenceMedium
	case "LOW":
		return analysis.ConfidenceLow
	default:
		return analysis.ConfidenceLow
	}
}

// --- semgrep ---

type semgrepReport struct {
	Results []semgrepResult `json:"results"`
	Errors  []interface{}   `json:"errors"`
}

type semgrepResult struct {
	CheckID string          `json:"check_id"`
	Path    string          `json:"path"`
	Start   semgrepPosition `json:"start"`
	End     semgrepPosition `json:"end"`
	Extra   semgrepExtra    `json:"extra"`
}

type semgrepPosition struct {
	Line   int `json:"line"`
	Col    int `json:"col"`
	Offset int `json:"offset"`
}

type semgrepExtra struct {
	Message  string                 `json:"message"`
	Severity string                 `json:"severity"`
	Lines    string                 `json:"lines"`
	Metadata map[string]interface{} `json:"metadata"`
}

func runSemgrep(ctx context.Context, root string) ([]analysis.Finding, error) {
	cmd := exec.CommandContext(ctx, "semgrep", "--json", "--quiet", root)
	cmd.Dir = root
	output, err := cmd.Output()
	if err != nil {
		if len(output) > 0 {
			// semgrep returns non-zero when findings exist
		} else {
			return nil, fmt.Errorf("semgrep execution failed: %w", err)
		}
	}

	var report semgrepReport
	if err := json.Unmarshal(output, &report); err != nil {
		return nil, fmt.Errorf("failed to parse semgrep output: %w", err)
	}

	var findings []analysis.Finding
	for _, r := range report.Results {
		severity := analysis.SeverityInfo
		if s, ok := r.Extra.Metadata["severity"]; ok {
			if sv, ok := s.(string); ok {
				severity = normalizeSemgrepSeverity(sv)
			}
		}
		if severity == analysis.SeverityInfo && r.Extra.Severity != "" {
			severity = normalizeSemgrepSeverity(r.Extra.Severity)
		}

		cwe := ""
		if c, ok := r.Extra.Metadata["cwe"]; ok {
			if cv, ok := c.(string); ok {
				cwe = cv
			}
		}

		advisory := ""
		if ref, ok := r.Extra.Metadata["references"]; ok {
			if refs, ok := ref.([]interface{}); ok && len(refs) > 0 {
				if refStr, ok := refs[0].(string); ok {
					advisory = refStr
				}
			}
		}

		findings = append(findings, analysis.Finding{
			ID:          fmt.Sprintf("sast-semgrep-%s-%s-%d", r.CheckID, filepath.Base(r.Path), r.Start.Line),
			Type:        analysis.TypeSAST,
			Analyzer:    "semgrep",
			Severity:    severity,
			Confidence:  analysis.ConfidenceMedium,
			Title:       r.CheckID,
			Description: r.Extra.Message,
			FilePath:    r.Path,
			LineStart:   r.Start.Line,
			LineEnd:     r.End.Line,
			RuleID:      r.CheckID,
			CWEID:       cwe,
			AdvisoryURL: advisory,
			Evidence:    r.Extra.Lines,
			DetectedAt:  time.Now(),
		})
	}

	return findings, nil
}

func normalizeSemgrepSeverity(s string) analysis.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "ERROR", "HIGH", "CRITICAL":
		if strings.ToUpper(s) == "CRITICAL" {
			return analysis.SeverityCritical
		}
		return analysis.SeverityHigh
	case "WARNING", "MEDIUM":
		return analysis.SeverityMedium
	case "INFO", "LOW":
		return analysis.SeverityLow
	default:
		return analysis.SeverityInfo
	}
}

// --- gitleaks ---

type gitleaksReport []gitleaksFinding

type gitleaksFinding struct {
	Description string `json:"Description"`
	RuleID      string `json:"RuleID"`
	RuleName    string `json:"RuleName"`
	Secret      string `json:"Secret"`
	File        string `json:"File"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
	StartColumn int    `json:"StartColumn"`
	EndColumn   int    `json:"EndColumn"`
	Match       string `json:"Match"`
}

func runGitleaks(ctx context.Context, root string) ([]analysis.Finding, error) {
	// gitleaks detect --source . --report-format json --report-path -
	cmd := exec.CommandContext(ctx, "gitleaks", "detect", "--source", root, "--report-format", "json", "--report-path", "-", "--no-banner")
	cmd.Dir = root
	output, err := cmd.Output()
	if err != nil {
		if len(output) > 0 {
			// gitleaks returns non-zero when secrets are found
		} else {
			return nil, fmt.Errorf("gitleaks execution failed: %w", err)
		}
	}

	var report gitleaksReport
	if err := json.Unmarshal(output, &report); err != nil {
		return nil, fmt.Errorf("failed to parse gitleaks output: %w", err)
	}

	var findings []analysis.Finding
	for _, f := range report {
		// Mask the secret value — never expose it in findings
		maskedSecret := maskSecret(f.Secret)
		title := f.RuleName
		if title == "" {
			title = f.Description
		}
		if title == "" {
			title = f.RuleID
		}

		findings = append(findings, analysis.Finding{
			ID:             fmt.Sprintf("secret-gitleaks-%s-%s-%d", f.RuleID, filepath.Base(f.File), f.StartLine),
			Type:           analysis.TypeSecret,
			Analyzer:       "gitleaks",
			Severity:       analysis.SeverityHigh, // secrets are always high severity
			Confidence:     analysis.ConfidenceHigh,
			Title:          fmt.Sprintf("Secret detected: %s", title),
			Description:    fmt.Sprintf("Potential secret matching rule %s detected. Value masked: %s", f.RuleID, maskedSecret),
			FilePath:       f.File,
			LineStart:      f.StartLine,
			LineEnd:        f.EndLine,
			RuleID:         f.RuleID,
			Evidence:       maskSecret(f.Match),
			Recommendation: "Remove the secret from the code, rotate it immediately, and use environment variables or a secrets manager.",
			DetectedAt:     time.Now(),
		})
	}

	return findings, nil
}

// maskSecret masks a secret value, showing only the first and last 2 characters.
func maskSecret(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 4 {
		return strings.Repeat("*", len(s))
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}

// PlatformBinaryName returns the platform-specific binary name for a tool.
func PlatformBinaryName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}
