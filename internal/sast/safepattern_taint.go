package sast

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	fwpatterns "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

// suppressTaintWithSafePatterns suppresses taint-mode findings whose
// containing function also contains a safe pattern match. This bridges
// the gap between pattern-mode safe patterns (which work in the matcher)
// and taint-mode rules (which bypass the matcher).
//
// The algorithm:
//  1. Group findings by file
//  2. For each file, read the source and detect function boundaries
//  3. For each taint finding, find its containing function
//  4. Check if any safe pattern regex matches within that function's line range
//  5. If yes, suppress the finding (drop it)
//
// Only findings with a rule ID in the safePatterns map are considered.
// Non-taint findings and findings without safe patterns are passed through.
func suppressTaintWithSafePatterns(findings []analysis.Finding, safePatterns map[string][]fwpatterns.SafePattern, root string) []analysis.Finding {
	if len(safePatterns) == 0 {
		return findings
	}

	// Group findings by file for efficient batch processing
	byFile := make(map[string][]int) // file → indices into findings
	for i, f := range findings {
		if f.RuleID == "" {
			continue
		}
		if _, has := safePatterns[f.RuleID]; !has {
			continue
		}
		// Only suppress taint-patterns and framework-taint findings
		if f.Analyzer != "taint-patterns" && f.Analyzer != "framework-taint" {
			continue
		}
		byFile[f.FilePath] = append(byFile[f.FilePath], i)
	}

	if len(byFile) == 0 {
		return findings
	}

	suppressed := make(map[int]bool) // indices to suppress

	for file, indices := range byFile {
		fullPath := file
		if !filepath.IsAbs(fullPath) {
			fullPath = filepath.Join(root, file)
		}

		// Read source lines
		lines, err := readSourceLines(fullPath)
		if err != nil {
			continue
		}

		// Detect function boundaries
		boundaries := detectFunctionBoundaries(fullPath)
		if len(boundaries) == 0 {
			continue
		}

		for _, idx := range indices {
			f := findings[idx]
			// Find the function containing this finding
			fnBoundary := findFunctionForLine(boundaries, f.LineStart)
			if fnBoundary == nil {
				continue
			}

			// Determine the function's line range
			fnStart := fnBoundary.line
			fnEnd := len(lines)
			// Find the next function boundary after this one
			for _, b := range boundaries {
				if b.line > fnStart {
					fnEnd = b.line - 1
					break
				}
			}

			// Check if any safe pattern matches within the function's line range
			patterns := safePatterns[f.RuleID]
			for _, sp := range patterns {
				if sp.Regex == nil {
					continue
				}
				if safePatternMatchesInRange(sp.Regex, lines, fnStart, fnEnd) {
					suppressed[idx] = true
					break
				}
			}
		}
	}

	if len(suppressed) == 0 {
		return findings
	}

	result := make([]analysis.Finding, 0, len(findings)-len(suppressed))
	for i, f := range findings {
		if !suppressed[i] {
			result = append(result, f)
		}
	}
	return result
}

// readSourceLines reads a file and returns its lines as a slice.
func readSourceLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// safePatternMatchesInRange checks if a regex matches any line in the
// given 1-based line range [start, end] inclusive.
func safePatternMatchesInRange(re *regexp.Regexp, lines []string, start, end int) bool {
	if start < 1 {
		start = 1
	}
	if end > len(lines) {
		end = len(lines)
	}
	for i := start - 1; i < end && i < len(lines); i++ {
		if re.MatchString(lines[i]) {
			return true
		}
	}
	return false
}
