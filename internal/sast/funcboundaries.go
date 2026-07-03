package sast

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// functionBoundary represents a function/method/class definition found
// in a source file. Line is the 1-based line number where the function
// starts. Name is the function or method name.
type functionBoundary struct {
	line int
	name string
}

// funcDefPatterns matches common function/method/class definition patterns
// across supported languages. The regex is anchored at the start of the
// trimmed line. Keywords use non-capturing groups so the first capture group
// is always the function/method/class name.
var funcDefPatterns = regexp.MustCompile(
	// Python/Ruby: def method_name, class ClassName
	`^(?:def|class)\s+(\w+)` +
		// Go: func methodName, func (recv) methodName
		`|^func\s+(?:\([^)]*\)\s+)?(\w+)` +
		// JavaScript/TypeScript: function methodName
		`|^function\s+(\w+)` +
		// Java: public/private/protected static? ReturnType methodName(
		`|^(?:public|private|protected)\s+(?:static\s+)?(?:\w+(?:<[^>]*>)?\s+)?(\w+)\s*\(` +
		// Ruby: def self.method_name (already covered by def above, but
		// handle the self. prefix explicitly)
		`|^def\s+(?:self\.)?(\w+)`,
)

// detectFunctionBoundaries reads a source file and returns a sorted list
// of function boundaries. Each boundary marks the start of a new function,
// method, or class definition. If the file cannot be read, returns nil.
func detectFunctionBoundaries(path string) []functionBoundary {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var boundaries []functionBoundary
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
			continue
		}
		m := funcDefPatterns.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		// Extract the name from whichever capture group matched
		var name string
		for _, g := range m[1:] {
			if g != "" {
				name = g
				break
			}
		}
		if name == "" {
			continue
		}
		boundaries = append(boundaries, functionBoundary{line: lineNum, name: name})
	}
	return boundaries
}

// findFunctionForLine returns the function boundary that contains the given
// line number. A finding at line L belongs to the function whose start line
// is the largest value <= L. Returns nil if no enclosing function is found.
func findFunctionForLine(boundaries []functionBoundary, line int) *functionBoundary {
	var result *functionBoundary
	for i := range boundaries {
		if boundaries[i].line <= line {
			result = &boundaries[i]
		} else {
			break
		}
	}
	return result
}

// resolveFilePath resolves a finding's file path relative to the scan root.
// Findings may have absolute or relative paths depending on the scanner.
func resolveFilePath(filePath, root string) string {
	if filepath.IsAbs(filePath) {
		return filePath
	}
	return filepath.Join(root, filePath)
}
