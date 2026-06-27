package sast

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/odvcencio/gotreesitter/grammars"
	"github.com/patchflow/patchflow-cli/internal/analysis"
	"github.com/patchflow/patchflow-cli/internal/ignore"
	"github.com/patchflow/patchflow-cli/internal/sast/incremental"
	"github.com/patchflow/patchflow-cli/internal/sast/patterns"
	"github.com/patchflow/patchflow-cli/internal/sast/secrets"
	"github.com/patchflow/patchflow-cli/internal/sast/taintpatterns"
	"github.com/patchflow/patchflow-cli/internal/sast/treesitter"
)

// fileTask represents a single file to be scanned by one or more scanners.
type fileTask struct {
	path    string
	root    string
	info    os.FileInfo
	pattern patterns.Language
	tsEntry *grammars.LangEntry
}

// collectedFiles holds the result of a single-pass file tree walk.
type collectedFiles struct {
	tasks []fileTask
	total int
}

// collectFiles walks the file tree once and categorizes each file for the
// scanners that should process it. This replaces the per-scanner filepath.Walk
// calls, eliminating redundant tree traversals (4x reduction in I/O).
//
// The ignoreMatcher is used to skip gitignored files/directories.
// maxFileSize limits files to prevent memory exhaustion (0 = no limit).
// includeTests controls whether test files are included.
func collectFiles(root string, ignoreMatcher *ignore.Matcher, maxFileSize int64, includeTests bool, tsAnalyzer *treesitter.Analyzer) (*collectedFiles, error) {
	cf := &collectedFiles{}

	ignoredDirs := map[string]bool{
		".git":          true,
		"node_modules":  true,
		"vendor":        true,
		"dist":          true,
		"build":         true,
		"__pycache__":   true,
		".next":         true,
		".nuxt":         true,
		"target":        true,
		".gradle":       true,
		".idea":         true,
		".vscode":       true,
		"bin":           true,
		"obj":           true,
		".cache":        true,
		".pytest_cache": true,
		".mypy_cache":   true,
		".ruff_cache":   true,
		"coverage":      true,
		".turbo":        true,
		".svelte-kit":   true,
	}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			name := filepath.Base(path)
			if ignoredDirs[name] {
				return filepath.SkipDir
			}
			if ignoreMatcher != nil && !ignoreMatcher.IsEmpty() {
				if ignoreMatcher.Match(path, true) {
					return filepath.SkipDir
				}
			}
			return nil
		}

		// Check .gitignore for files
		if ignoreMatcher != nil && !ignoreMatcher.IsEmpty() {
			if ignoreMatcher.Match(path, false) {
				return nil
			}
		}

		// Size check
		if maxFileSize > 0 && info.Size() > maxFileSize {
			return nil
		}

		// Skip test files if not included
		if !includeTests && isTestPath(path) {
			return nil
		}

		task := fileTask{
			path: path,
			root: root,
			info: info,
		}

		// Determine which scanners should process this file
		// Pattern scanner: language detection via file extension
		task.pattern = patterns.DetectLanguagePublic(path)

		// Tree-sitter: language detection via grammars
		// Only set tsEntry if the tree-sitter analyzer has rules for this language,
		// otherwise we waste time parsing files (e.g. .rst, .html, .json) that no
		// rule will ever match.
		entry := grammars.DetectLanguage(path)
		if entry != nil && tsAnalyzer.HasRulesForLanguage(entry.Name) {
			task.tsEntry = entry
		}

		// Secrets scanner: processes all text files (not just specific extensions)
		// — it has its own internal filtering for binary/lockfile/example files

		// Only add tasks for files that at least one scanner can process
		if task.pattern != "" || task.tsEntry != nil || isTextFile(path) {
			cf.tasks = append(cf.tasks, task)
			cf.total++
		}

		return nil
	})

	if err != nil {
		return nil, err
	}
	return cf, nil
}

// isTextFile does a quick check to see if a file is likely text (for secrets scanner).
func isTextFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	// Skip known binary extensions
	switch ext {
	case ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp",
		".mp3", ".mp4", ".avi", ".mov", ".wav", ".flv",
		".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
		".pdf", ".doc", ".docx", ".xls", ".xlsx",
		".exe", ".dll", ".so", ".dylib", ".o", ".a",
		".class", ".jar", ".war",
		".woff", ".woff2", ".ttf", ".eot", ".otf",
		".pyc", ".pyo", ".wasm",
		".min.js", ".min.css",
		".lock",
		".svg":
		return false
	}
	return true
}

// scanResult holds findings from a single scanner for a single file.
type scanResult struct {
	scanner  string
	findings []analysis.Finding
	err      error
	dur      time.Duration
}

// parallelScanFiles processes collected file tasks through the scanners in
// parallel using a worker pool. Each file is scanned by all applicable scanners.
// The number of workers is runtime.NumCPU() by default.
//
// This replaces the sequential per-scanner file walking with a single
// parallel dispatch, providing ~4x speedup on 8-core machines.
func parallelScanFiles(
	ctx context.Context,
	cf *collectedFiles,
	patternScanner *patterns.Scanner,
	secretScanner *secrets.Scanner,
	tsAnalyzer *treesitter.Analyzer,
	tpAnalyzer *taintpatterns.Analyzer,
	scanPatterns, scanSecrets, scanTreeSitter, scanTaintPatterns bool,
) (map[string][]analysis.Finding, []string) {
	numWorkers := runtime.NumCPU()
	if numWorkers < 2 {
		numWorkers = 2
	}
	if numWorkers > 16 {
		numWorkers = 16 // cap to avoid excessive goroutines
	}

	taskCh := make(chan fileTask, len(cf.tasks))
	resultCh := make(chan scanResult, len(cf.tasks)*4) // up to 4 scanners per file

	var wg sync.WaitGroup

	// Launch workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range taskCh {
				if ctx.Err() != nil {
					return
				}

				// Pattern scanner
				if scanPatterns && task.pattern != "" {
					sc := time.Now()
					findings, err := patternScanner.ScanFilePublic(task.path, task.root, task.pattern)
					resultCh <- scanResult{scanner: "patterns-embedded", findings: findings, err: err, dur: time.Since(sc)}
				}

				// Secrets scanner
				if scanSecrets && isTextFile(task.path) {
					sc := time.Now()
					findings, err := secretScanner.ScanFilePublic(task.path, task.root)
					resultCh <- scanResult{scanner: "secrets-embedded", findings: findings, err: err, dur: time.Since(sc)}
				}

				// Tree-sitter scanner
				if scanTreeSitter && task.tsEntry != nil {
					sc := time.Now()
					findings, err := tsAnalyzer.ScanFilePublic(task.path, task.root, task.tsEntry)
					resultCh <- scanResult{scanner: "treesitter-ast", findings: findings, err: err, dur: time.Since(sc)}
				}

				// Taint patterns scanner (Python and JS/TS only)
				if scanTaintPatterns && task.tsEntry != nil {
					sc := time.Now()
					findings, err := tpAnalyzer.ScanFilePublic(task.path, task.root, task.tsEntry)
					resultCh <- scanResult{scanner: "taint-patterns", findings: findings, err: err, dur: time.Since(sc)}
				}
			}
		}()
	}

	// Feed tasks to workers
	go func() {
		for _, task := range cf.tasks {
			taskCh <- task
		}
		close(taskCh)
	}()

	// Wait for all workers to finish, then close results
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Collect results grouped by scanner
	results := make(map[string][]analysis.Finding)
	scannerTimings := make(map[string]time.Duration)
	var errors []string

	for sr := range resultCh {
		scannerTimings[sr.scanner] += sr.dur
		if sr.err != nil {
			errors = append(errors, sr.scanner+": "+sr.err.Error())
			continue
		}
		results[sr.scanner] = append(results[sr.scanner], sr.findings...)
	}

	// Log per-scanner timings for debugging.
	for scanner, dur := range scannerTimings {
		log.Printf("[sast] %s total: %v", scanner, dur)
	}

	return results, errors
}

// runParallelScanners is the entry point for single-pass parallel scanning.
// It collects files once, then dispatches them to all applicable scanners
// in parallel. Returns findings grouped by scanner name.
//
// When incrementalState is non-nil, only files that changed since the last
// scan are processed. The state is updated with new hashes after scanning.
func runParallelScanners(
	ctx context.Context,
	root string,
	ignoreMatcher *ignore.Matcher,
	patternScanner *patterns.Scanner,
	secretScanner *secrets.Scanner,
	tsAnalyzer *treesitter.Analyzer,
	tpAnalyzer *taintpatterns.Analyzer,
	scanPatterns, scanSecrets, scanTreeSitter, scanTaintPatterns bool,
	includeTests bool,
	timeout time.Duration,
	incrementalState *incremental.State,
	gitChangedSet map[string]bool,
) (map[string][]analysis.Finding, []string) {
	// Phase 1: Single-pass file collection
	cf, err := collectFiles(root, ignoreMatcher, 2*1024*1024, includeTests, tsAnalyzer) // 2MB max
	if err != nil {
		return nil, []string{"file-collector: " + err.Error()}
	}

	// Filter to changed files. Two strategies:
	// a) GitChangedFiles pre-filter (fastest): skip the hash check entirely
	//    and only scan files that git says changed.
	// b) Incremental hash-based: use mtime+size fast-path, fall back to SHA256.
	if len(gitChangedSet) > 0 {
		var filtered []fileTask
		for _, task := range cf.tasks {
			if gitChangedSet[task.path] {
				filtered = append(filtered, task)
			}
		}
		cf.tasks = filtered
		cf.total = len(filtered)
	} else if incrementalState != nil {
		var filtered []fileTask
		for _, task := range cf.tasks {
			if incrementalState.HasChanged(task.path, task.info) {
				filtered = append(filtered, task)
			}
		}
		cf.tasks = filtered
		cf.total = len(filtered)
	}

	// Phase 2: Parallel file scanning with timeout
	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	results, errors := parallelScanFiles(
		scanCtx, cf,
		patternScanner, secretScanner, tsAnalyzer, tpAnalyzer,
		scanPatterns, scanSecrets, scanTreeSitter, scanTaintPatterns,
	)

	// Phase 3: Update incremental state with new file hashes
	if incrementalState != nil {
		for _, task := range cf.tasks {
			incrementalState.UpdateHashFromInfo(task.path, task.info)
		}
	}

	return results, errors
}
