// Package suppression provides comment-based suppression directive parsing
// for the embedded SAST scanners. Users can suppress false positives by adding
// special comments to their source code:
//
//   //patchflow:ignore G404 -- using math/rand for non-security purpose
//   n := rand.Intn(100)
//
//   # patchflow:ignore PY001 -- eval is safe here, input is sanitized
//   result = eval(user_input)
//
// Suppression directives can be:
//   - Rule-specific: //patchflow:ignore G404 (only suppresses G404)
//   - Blanket: //patchflow:ignore (suppresses all rules on this line)
//
// The directive can appear:
//   - On the same line as the finding (inline)
//   - On the line immediately above the finding
package suppression

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// Directive is the magic comment prefix for suppression.
const Directive = "patchflow:ignore"

// Suppression represents a single suppression directive found in source code.
type Suppression struct {
	RuleID  string // empty means blanket suppression
	Comment string // optional comment text after --
	Line    int    // line number where the directive appears
}

// suppressRe matches the patchflow:ignore directive with optional rule ID and comment.
var suppressRe = regexp.MustCompile(`patchflow:ignore(?:\s+([A-Z]+[A-Z0-9_-]*))?\s*(?:--\s*(.*))?`)

// Manager caches suppression directives per file.
type Manager struct {
	mu      sync.RWMutex
	cache   map[string][]Suppression // file path -> suppressions
}

// NewManager creates a new suppression manager.
func NewManager() *Manager {
	return &Manager{
		cache: make(map[string][]Suppression),
	}
}

// IsSuppressed checks if a finding with the given rule ID at the given line
// in the given file is suppressed by a patchflow:ignore directive.
func (m *Manager) IsSuppressed(filePath string, line int, ruleID string) bool {
	suppressions := m.getSuppressions(filePath)
	for _, sup := range suppressions {
		// Directive on the same line as the finding (inline)
		if sup.Line == line {
			if sup.RuleID == "" || sup.RuleID == ruleID {
				return true
			}
		}
		// Directive on the line immediately above the finding
		if sup.Line == line-1 {
			if sup.RuleID == "" || sup.RuleID == ruleID {
				return true
			}
		}
	}
	return false
}

// getSuppressions returns all suppression directives for a file, loading
// and caching them on first access.
func (m *Manager) getSuppressions(filePath string) []Suppression {
	m.mu.RLock()
	if sups, ok := m.cache[filePath]; ok {
		m.mu.RUnlock()
		return sups
	}
	m.mu.RUnlock()

	// Load and cache
	sups := loadSuppressions(filePath)
	m.mu.Lock()
	m.cache[filePath] = sups
	m.mu.Unlock()
	return sups
}

// loadSuppressions reads a file and extracts all suppression directives.
func loadSuppressions(filePath string) []Suppression {
	file, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer file.Close()

	var suppressions []Suppression
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		sup := parseSuppression(line)
		if sup != nil {
			sup.Line = lineNum
			suppressions = append(suppressions, *sup)
		}
	}

	return suppressions
}

// parseSuppression checks if a line contains a patchflow:ignore directive
// and returns the parsed Suppression if so.
func parseSuppression(line string) *Suppression {
	// Check if the line contains the directive
	if !strings.Contains(line, Directive) {
		return nil
	}

	// Try to match the full pattern
	matches := suppressRe.FindStringSubmatch(line)
	if matches == nil {
		return nil
	}

	sup := &Suppression{
		RuleID:  matches[1], // may be empty for blanket suppression
		Comment: matches[2],  // optional comment
	}
	return sup
}

// FilterFindings removes suppressed findings from the list.
// Each finding must have FilePath, LineStart, and RuleID fields.
type FindingsFilter interface {
	GetFilePath() string
	GetLine() int
	GetRuleID() string
}

// Filter suppresses findings based on the suppression manager.
// It returns the filtered list and the count of suppressed findings.
func (m *Manager) Filter(findings []FindingsFilter) ([]FindingsFilter, int) {
	var result []FindingsFilter
	suppressed := 0
	for _, f := range findings {
		if m.IsSuppressed(f.GetFilePath(), f.GetLine(), f.GetRuleID()) {
			suppressed++
			continue
		}
		result = append(result, f)
	}
	return result, suppressed
}

// ClearCache clears the suppression cache. Useful for testing.
func (m *Manager) ClearCache() {
	m.mu.Lock()
	m.cache = make(map[string][]Suppression)
	m.mu.Unlock()
}

// AbsPath returns the absolute path for a file, handling relative paths.
func AbsPath(base, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(base, path)
}
