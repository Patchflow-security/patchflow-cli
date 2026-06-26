// Package baseline provides finding baseline management for incremental
// vulnerability tracking. A baseline stores a snapshot of known findings
// so that subsequent scans only report new or resolved issues.
package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/patchflow/patchflow-cli/internal/analysis"
)

// Baseline represents a snapshot of findings at a point in time.
type Baseline struct {
	Name      string             `json:"name"`
	CreatedAt time.Time          `json:"created_at"`
	Commit    string             `json:"commit,omitempty"`
	FindingKeys map[string]bool  `json:"finding_keys"`
	Findings  []analysis.Finding `json:"findings"`
}

// Manager handles baseline storage and comparison.
type Manager struct {
	rootDir string
}

// NewManager creates a baseline manager for the given project root.
// Baselines are stored in .patchflow/baselines/.
func NewManager(rootDir string) *Manager {
	return &Manager{rootDir: rootDir}
}

func (m *Manager) baselinesDir() string {
	return filepath.Join(m.rootDir, ".patchflow", "baselines")
}

func (m *Manager) baselinePath(name string) string {
	return filepath.Join(m.baselinesDir(), name+".json")
}

// Create saves a new baseline with the given name and findings.
// If a baseline with the same name exists, it is overwritten.
func (m *Manager) Create(name string, findings []analysis.Finding, commit string) error {
	dir := m.baselinesDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create baselines directory: %w", err)
	}

	bl := &Baseline{
		Name:        name,
		CreatedAt:   time.Now().UTC(),
		Commit:      commit,
		FindingKeys: make(map[string]bool, len(findings)),
		Findings:    findings,
	}
	for _, f := range findings {
		bl.FindingKeys[fingerprint(f)] = true
	}

	data, err := json.MarshalIndent(bl, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal baseline: %w", err)
	}

	if err := os.WriteFile(m.baselinePath(name), data, 0644); err != nil {
		return fmt.Errorf("failed to write baseline: %w", err)
	}
	return nil
}

// Load reads a baseline by name.
func (m *Manager) Load(name string) (*Baseline, error) {
	data, err := os.ReadFile(m.baselinePath(name))
	if err != nil {
		return nil, fmt.Errorf("baseline %q not found: %w", name, err)
	}
	var bl Baseline
	if err := json.Unmarshal(data, &bl); err != nil {
		return nil, fmt.Errorf("failed to parse baseline: %w", err)
	}
	return &bl, nil
}

// List returns all saved baseline names, sorted alphabetically.
func (m *Manager) List() ([]string, error) {
	entries, err := os.ReadDir(m.baselinesDir())
	if err != nil {
		return nil, nil // no baselines dir = no baselines
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if filepath.Ext(name) == ".json" {
			names = append(names, name[:len(name)-len(".json")])
		}
	}
	sort.Strings(names)
	return names, nil
}

// Delete removes a baseline by name.
func (m *Manager) Delete(name string) error {
	err := os.Remove(m.baselinePath(name))
	if err != nil {
		return fmt.Errorf("failed to delete baseline %q: %w", name, err)
	}
	return nil
}

// Diff represents the difference between a baseline and current findings.
type Diff struct {
	BaselineName string             `json:"baseline_name"`
	New          []analysis.Finding `json:"new_findings"`
	Resolved     []analysis.Finding `json:"resolved_findings"`
	Unchanged    []analysis.Finding `json:"unchanged_findings"`
	NewCount     int                `json:"new_count"`
	ResolvedCount int               `json:"resolved_count"`
	UnchangedCount int              `json:"unchanged_count"`
}

// Compare diffs current findings against a saved baseline.
// Findings are matched by fingerprint (rule_id + file + line).
func (m *Manager) Compare(name string, current []analysis.Finding) (*Diff, error) {
	bl, err := m.Load(name)
	if err != nil {
		return nil, err
	}

	currentMap := make(map[string]analysis.Finding, len(current))
	for _, f := range current {
		currentMap[fingerprint(f)] = f
	}

	var diff Diff
	diff.BaselineName = name

	// Find new and unchanged findings
	for _, f := range current {
		fp := fingerprint(f)
		if bl.FindingKeys[fp] {
			diff.Unchanged = append(diff.Unchanged, f)
		} else {
			diff.New = append(diff.New, f)
		}
	}

	// Find resolved findings (in baseline but not in current)
	for _, f := range bl.Findings {
		fp := fingerprint(f)
		if _, exists := currentMap[fp]; !exists {
			diff.Resolved = append(diff.Resolved, f)
		}
	}

	diff.NewCount = len(diff.New)
	diff.ResolvedCount = len(diff.Resolved)
	diff.UnchangedCount = len(diff.Unchanged)

	return &diff, nil
}

// fingerprint creates a unique key for a finding based on rule ID, file, and line.
// This is used for baseline comparison — two findings with the same fingerprint
// are considered the same issue.
func fingerprint(f analysis.Finding) string {
	return fmt.Sprintf("%s:%s:%d", f.RuleID, f.FilePath, f.LineStart)
}
