// Package ignore provides .gitignore pattern matching for file walkers.
// It implements a subset of the gitignore specification sufficient for
// security scanning: glob patterns with *, **, and ? wildcards, directory
// anchoring with leading /, directory-only patterns with trailing /,
// negation with leading !, and nested .gitignore files in subdirectories.
//
// The matcher is designed to be fast and allocation-light for the common
// case of scanning a repository tree. It does not require git to be
// installed and works on any directory tree.
package ignore

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Matcher holds compiled gitignore patterns and determines whether a path
// is ignored. A single Matcher is safe for concurrent read access after
// initialization.
type Matcher struct {
	root    string
	pattern []pattern
	// If true, no .gitignore was found and Match always returns false.
	empty bool
}

type pattern struct {
	negate    bool
	dirOnly   bool
	anchored  bool // pattern starts with /
	segments  []string // path segments with wildcards
	raw       string
}

// NewMatcher loads .gitignore files from the given root directory and all
// its subdirectories. It reads the root .gitignore first, then walks the
// tree to find nested .gitignore files. Patterns from parent directories
// apply to children; patterns from nested .gitignore files are relative to
// the directory containing them.
//
// If no .gitignore file exists at the root, the matcher is empty and Match
// always returns false.
func NewMatcher(root string) *Matcher {
	m := &Matcher{root: root}

	// Load root .gitignore
	rootGitignore := filepath.Join(root, ".gitignore")
	if _, err := os.Stat(rootGitignore); err == nil {
		m.loadFile(rootGitignore, root)
	}

	// Walk for nested .gitignore files
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if info.IsDir() {
			name := info.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if info.Name() == ".gitignore" && path != rootGitignore {
			dir := filepath.Dir(path)
			m.loadFile(path, dir)
		}
		return nil
	})

	if len(m.pattern) == 0 {
		m.empty = true
	}
	return m
}

// NewMatcherFromBytes creates a matcher from raw .gitignore content,
// anchored at the given root. This is useful for testing or when the
// gitignore content is already available.
func NewMatcherFromBytes(root string, content []byte) *Matcher {
	m := &Matcher{root: root}
	m.parseLines(content, root)
	if len(m.pattern) == 0 {
		m.empty = true
	}
	return m
}

func (m *Matcher) loadFile(path, baseDir string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	for _, line := range lines {
		m.parseLine(line, baseDir)
	}
}

func (m *Matcher) parseLines(content []byte, baseDir string) {
	for _, line := range strings.Split(string(content), "\n") {
		m.parseLine(line, baseDir)
	}
}

func (m *Matcher) parseLine(line, baseDir string) {
	// Strip trailing whitespace (but not leading — spaces are significant
	// in gitignore only when escaped, which we don't support)
	line = strings.TrimRight(line, " \t\r")

	// Skip empty lines and comments
	if line == "" || strings.HasPrefix(line, "#") {
		return
	}

	p := pattern{raw: line}

	// Negation
	if strings.HasPrefix(line, "!") {
		p.negate = true
		line = line[1:]
	}

	// Escape sequences for leading special chars (we handle the common case)
	if strings.HasPrefix(line, "\\!") || strings.HasPrefix(line, "\\#") {
		line = line[1:]
	}

	// Directory-only pattern
	if strings.HasSuffix(line, "/") {
		p.dirOnly = true
		line = strings.TrimSuffix(line, "/")
	}

	// Anchored pattern (relative to the .gitignore directory)
	if strings.HasPrefix(line, "/") {
		p.anchored = true
		line = strings.TrimPrefix(line, "/")
	}

	// If the pattern contains a / anywhere (not just at the start), it's
	// implicitly anchored per gitignore spec.
	if strings.Contains(line, "/") {
		p.anchored = true
	}

	// Store the relative base directory for this pattern
	relBase, _ := filepath.Rel(m.root, baseDir)
	p.segments = append(p.segments, relBase) // first segment is the base dir
	p.segments = append(p.segments, strings.Split(line, "/")...)

	m.pattern = append(m.pattern, p)
}

// Match returns true if the given path should be ignored according to the
// loaded .gitignore patterns. The path should be an absolute path or a
// path relative to the root. isDir indicates whether the path is a directory.
func (m *Matcher) Match(path string, isDir bool) bool {
	if m.empty {
		return false
	}

	// Normalize to a path relative to root
	relPath, err := filepath.Rel(m.root, path)
	if err != nil {
		return false
	}
	relPath = filepath.ToSlash(relPath) // normalize separators

	// A leading ".." means the path is outside the root — don't ignore
	if strings.HasPrefix(relPath, "..") {
		return false
	}

	pathSegs := strings.Split(relPath, "/")

	ignored := false
	for _, p := range m.pattern {
		result := p.matchSegments(pathSegs, isDir)
		if result == matchIgnore {
			ignored = true
		} else if result == matchUnignore {
			ignored = false
		}
	}

	return ignored
}

type matchResult int

const (
	matchNoMatch   matchResult = 0
	matchIgnore    matchResult = 1
	matchUnignore  matchResult = 2
)

// matchSegments determines whether the pattern matches the given path
// segments. The first element of p.segments is the base directory (relative
// to root); the remaining elements are the pattern path segments.
func (p *pattern) matchSegments(pathSegs []string, isDir bool) matchResult {
	baseDir := p.segments[0]

	// Determine which path segments are within the base directory
	var relSegs []string
	if baseDir == "." || baseDir == "" {
		relSegs = pathSegs
	} else {
		baseSegs := strings.Split(baseDir, "/")
		if len(pathSegs) < len(baseSegs) {
			return matchNoMatch
		}
		for i, bs := range baseSegs {
			if pathSegs[i] != bs {
				return matchNoMatch
			}
		}
		relSegs = pathSegs[len(baseSegs):]
	}

	if len(relSegs) == 0 {
		return matchNoMatch
	}

	matched := false
	if p.anchored {
		// Anchored: pattern must match from the start of the relative path,
		// or the path must be inside a directory that matches the pattern.
		matched = p.matchAnchored(relSegs, isDir)
	} else {
		// Unanchored: pattern can match at any level within the base directory.
		matched = p.matchUnanchored(relSegs, isDir)
	}

	if !matched {
		return matchNoMatch
	}
	if p.negate {
		return matchUnignore
	}
	return matchIgnore
}

// matchAnchored matches an anchored pattern against relative path segments.
// An anchored pattern matches if:
//   - The pattern exactly matches the path (including ** wildcard expansion)
//   - The pattern matches a parent directory of the path (pattern is a prefix)
//
// For dir-only patterns, exact match requires isDir=true, but prefix match
// (path is inside the directory) works regardless of isDir.
func (p *pattern) matchAnchored(relSegs []string, isDir bool) bool {
	patternSegs := p.segments[1:] // pattern path segments

	// Check if pattern contains ** (variable-length matching)
	hasDoubleStar := false
	for _, s := range patternSegs {
		if s == "**" {
			hasDoubleStar = true
			break
		}
	}

	// Case 1: exact match via glob (handles ** matching zero or more segments)
	if hasDoubleStar {
		if p.dirOnly && !isDir {
			// For dir-only with **, still check prefix match below
		} else {
			if matchGlobSegments(patternSegs, relSegs) {
				return true
			}
		}
	} else if len(relSegs) == len(patternSegs) {
		if p.dirOnly && !isDir {
			return false
		}
		return matchGlobSegments(patternSegs, relSegs)
	}

	// Case 2: path is inside a directory matching the pattern (prefix match)
	// Try matching the pattern against progressively shorter prefixes of the path.
	// This handles both regular and ** patterns for directory containment.
	if !hasDoubleStar && len(relSegs) > len(patternSegs) {
		prefix := relSegs[:len(patternSegs)]
		return matchGlobSegments(patternSegs, prefix)
	}

	// For ** patterns, also check prefix matches at various depths
	if hasDoubleStar {
		for cutLen := len(relSegs) - 1; cutLen >= len(patternSegs)-1 && cutLen > 0; cutLen-- {
			prefix := relSegs[:cutLen]
			if matchGlobSegments(patternSegs, prefix) {
				return true
			}
		}
	}

	return false
}

// matchUnanchored matches an unanchored pattern against relative path segments.
// The pattern can match at any segment boundary within the path. When the
// pattern contains ** wildcards, it can match a variable number of segments.
func (p *pattern) matchUnanchored(relSegs []string, isDir bool) bool {
	patternSegs := p.segments[1:]

	// If the pattern contains **, it can match variable-length targets.
	// Try matching the full remaining segments at every starting position.
	hasDoubleStar := false
	for _, s := range patternSegs {
		if s == "**" {
			hasDoubleStar = true
			break
		}
	}

	if hasDoubleStar {
		for i := 0; i < len(relSegs); i++ {
			if matchGlobSegments(patternSegs, relSegs[i:]) {
				return true
			}
		}
		return false
	}

	patternLen := len(patternSegs)
	for i := 0; i <= len(relSegs)-patternLen; i++ {
		suffix := relSegs[i : i+patternLen]
		// For dir-only patterns with exact match, require isDir.
		// For prefix match (path is deeper), it's fine regardless.
		if p.dirOnly && !isDir && i+patternLen == len(relSegs) {
			continue
		}
		if matchGlobSegments(patternSegs, suffix) {
			return true
		}
	}
	return false
}

// matchGlobSegments matches a gitignore-style glob pattern (as segments)
// against path segments. Supports *, **, and ? wildcards. ** matches any
// number of path segments (including zero).
func matchGlobSegments(pattern, target []string) bool {
	// Find ** in the pattern
	for i, seg := range pattern {
		if seg == "**" {
			// ** matches zero or more segments
			// Try matching the rest of the pattern at every possible position
			rest := pattern[i+1:]
			for j := i; j <= len(target); j++ {
				if matchGlobSegments(rest, target[j:]) {
					return true
				}
			}
			return false
		}
	}

	// No ** remaining — lengths must match
	if len(pattern) != len(target) {
		return false
	}

	for i := range pattern {
		if !matchSegment(pattern[i], target[i]) {
			return false
		}
	}
	return true
}

// matchSegment matches a single path segment (no slashes) against a glob
// pattern that may contain * and ? wildcards.
func matchSegment(pattern, segment string) bool {
	// Use filepath.Match for single-segment patterns (handles * and ?)
	matched, err := filepath.Match(pattern, segment)
	if err != nil {
		return false
	}
	return matched
}

// IsEmpty returns true if no .gitignore patterns were loaded.
func (m *Matcher) IsEmpty() bool {
	return m.empty
}

// PatternCount returns the number of loaded patterns (for diagnostics).
func (m *Matcher) PatternCount() int {
	return len(m.pattern)
}

// Cache wraps a Matcher with lazy initialization so the .gitignore files
// are only parsed once per scan. Safe for concurrent use.
type Cache struct {
	once    sync.Once
	matcher *Matcher
	root    string
}

// NewCache creates a lazy gitignore matcher cache for the given root.
func NewCache(root string) *Cache {
	return &Cache{root: root}
}

// Get returns the initialized Matcher, loading it on first access.
func (c *Cache) Get() *Matcher {
	c.once.Do(func() {
		c.matcher = NewMatcher(c.root)
	})
	return c.matcher
}

// Match is a convenience method that initializes the matcher on first call.
func (c *Cache) Match(path string, isDir bool) bool {
	return c.Get().Match(path, isDir)
}
