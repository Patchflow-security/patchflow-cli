package baseline

import (
	"testing"

	"github.com/patchflow/patchflow-cli/internal/analysis"
)

func TestCreateAndLoad(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)

	findings := []analysis.Finding{
		{RuleID: "PY001", FilePath: "app.py", LineStart: 10, Title: "eval() usage"},
		{RuleID: "GEN010", FilePath: "config.py", LineStart: 5, Title: "Hardcoded password"},
	}

	if err := mgr.Create("v1.0", findings, "abc123"); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	bl, err := mgr.Load("v1.0")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if bl.Name != "v1.0" {
		t.Errorf("expected name v1.0, got %s", bl.Name)
	}
	if bl.Commit != "abc123" {
		t.Errorf("expected commit abc123, got %s", bl.Commit)
	}
	if len(bl.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(bl.Findings))
	}
	if len(bl.FindingKeys) != 2 {
		t.Errorf("expected 2 finding keys, got %d", len(bl.FindingKeys))
	}
}

func TestCompareNewFindings(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)

	baselineFindings := []analysis.Finding{
		{RuleID: "PY001", FilePath: "app.py", LineStart: 10, Title: "eval()"},
	}
	mgr.Create("v1.0", baselineFindings, "")

	// Current scan has the baseline finding plus a new one
	current := []analysis.Finding{
		{RuleID: "PY001", FilePath: "app.py", LineStart: 10, Title: "eval()"},
		{RuleID: "GEN010", FilePath: "config.py", LineStart: 5, Title: "password"},
	}

	diff, err := mgr.Compare("v1.0", current)
	if err != nil {
		t.Fatalf("Compare failed: %v", err)
	}
	if diff.NewCount != 1 {
		t.Errorf("expected 1 new finding, got %d", diff.NewCount)
	}
	if diff.UnchangedCount != 1 {
		t.Errorf("expected 1 unchanged finding, got %d", diff.UnchangedCount)
	}
	if diff.ResolvedCount != 0 {
		t.Errorf("expected 0 resolved findings, got %d", diff.ResolvedCount)
	}
}

func TestCompareResolvedFindings(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)

	baselineFindings := []analysis.Finding{
		{RuleID: "PY001", FilePath: "app.py", LineStart: 10, Title: "eval()"},
		{RuleID: "GEN010", FilePath: "config.py", LineStart: 5, Title: "password"},
	}
	mgr.Create("v1.0", baselineFindings, "")

	// Current scan only has one of the baseline findings — the other was fixed
	current := []analysis.Finding{
		{RuleID: "PY001", FilePath: "app.py", LineStart: 10, Title: "eval()"},
	}

	diff, err := mgr.Compare("v1.0", current)
	if err != nil {
		t.Fatalf("Compare failed: %v", err)
	}
	if diff.NewCount != 0 {
		t.Errorf("expected 0 new findings, got %d", diff.NewCount)
	}
	if diff.UnchangedCount != 1 {
		t.Errorf("expected 1 unchanged finding, got %d", diff.UnchangedCount)
	}
	if diff.ResolvedCount != 1 {
		t.Errorf("expected 1 resolved finding, got %d", diff.ResolvedCount)
	}
	if diff.Resolved[0].RuleID != "GEN010" {
		t.Errorf("expected resolved finding GEN010, got %s", diff.Resolved[0].RuleID)
	}
}

func TestList(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)

	mgr.Create("alpha", []analysis.Finding{}, "")
	mgr.Create("beta", []analysis.Finding{}, "")
	mgr.Create("gamma", []analysis.Finding{}, "")

	names, err := mgr.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(names) != 3 {
		t.Fatalf("expected 3 baselines, got %d", len(names))
	}
	// Should be sorted alphabetically
	if names[0] != "alpha" || names[1] != "beta" || names[2] != "gamma" {
		t.Errorf("expected alpha,beta,gamma; got %v", names)
	}
}

func TestDelete(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)

	mgr.Create("temp", []analysis.Finding{}, "")
	if err := mgr.Delete("temp"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, err := mgr.Load("temp")
	if err == nil {
		t.Error("expected error loading deleted baseline")
	}
}

func TestCompareNoBaseline(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)

	_, err := mgr.Compare("nonexistent", []analysis.Finding{})
	if err == nil {
		t.Error("expected error comparing against non-existent baseline")
	}
}

func TestListEmptyDir(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)

	names, err := mgr.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(names) != 0 {
		t.Errorf("expected 0 baselines, got %d", len(names))
	}
}
