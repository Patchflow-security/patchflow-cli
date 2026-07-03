package sast

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
)

func TestDedupBaseVsInterprocedural(t *testing.T) {
	findings := []analysis.Finding{
		{RuleID: "TP-JS001", FilePath: "src/app.js", LineStart: 42, Title: "eval with user input"},
		{RuleID: "TP-JS001-IP", FilePath: "src/app.js", LineStart: 42, Title: "eval with user input (interprocedural)"},
		{RuleID: "TP-JS008", FilePath: "src/render.js", LineStart: 10, Title: "template injection"},
		{RuleID: "TP-JS008-IP", FilePath: "src/render.js", LineStart: 10, Title: "template injection (interprocedural)"},
		{RuleID: "TP-JS004", FilePath: "src/db.js", LineStart: 55, Title: "SQL injection"},
	}

	result := dedupBaseVsInterprocedural(findings)
	if len(result) != 3 {
		t.Fatalf("expected 3 findings after dedup (2 base dropped), got %d", len(result))
	}
	for _, f := range result {
		if f.RuleID == "TP-JS001" || f.RuleID == "TP-JS008" {
			t.Errorf("base finding %s should have been dropped (IP variant exists)", f.RuleID)
		}
	}
}

func TestDedupBaseVsInterproceduralKeepsBaseWhenNoIP(t *testing.T) {
	findings := []analysis.Finding{
		{RuleID: "TP-JS001", FilePath: "src/app.js", LineStart: 42, Title: "eval"},
		{RuleID: "TP-JS004", FilePath: "src/db.js", LineStart: 55, Title: "SQLi"},
	}
	result := dedupBaseVsInterprocedural(findings)
	if len(result) != 2 {
		t.Fatalf("expected 2 findings (no IP variants to dedup), got %d", len(result))
	}
}

func TestGroupIssuesSameFunctionViaTitle(t *testing.T) {
	// Findings with function names in the title should group by function
	findings := []analysis.Finding{
		{RuleID: "PF-GRAPHQL-AUTH-001", FilePath: "core/views.py", LineStart: 141, Title: "GraphQL IDOR in EditPaste.mutate"},
		{RuleID: "PF-GRAPHQL-AUTH-001", FilePath: "core/views.py", LineStart: 148, Title: "GraphQL IDOR in EditPaste.mutate"},
	}
	result := groupIssues(findings, "")
	groups := map[string]int{}
	for _, f := range result {
		groups[f.IssueGroupID] = f.OccurrenceCount
	}
	if len(groups) != 1 {
		t.Fatalf("expected 1 issue group (same function via title), got %d", len(groups))
	}
	for _, occ := range groups {
		if occ != 2 {
			t.Errorf("expected occurrence count 2, got %d", occ)
		}
	}
}

func TestGroupIssuesDifferentFunctionsViaTitle(t *testing.T) {
	findings := []analysis.Finding{
		{RuleID: "PF-GRAPHQL-AUTH-001", FilePath: "core/views.py", LineStart: 141, Title: "GraphQL IDOR in EditPaste.mutate"},
		{RuleID: "PF-GRAPHQL-AUTH-001", FilePath: "core/views.py", LineStart: 167, Title: "GraphQL IDOR in DeletePaste.mutate"},
	}
	result := groupIssues(findings, "")
	groups := map[string]int{}
	for _, f := range result {
		groups[f.IssueGroupID] = f.OccurrenceCount
	}
	if len(groups) != 2 {
		t.Fatalf("expected 2 issue groups (different functions), got %d", len(groups))
	}
}

func TestGroupIssuesProximityFallback(t *testing.T) {
	// Without function names in title or source file, proximity is used.
	// Tight 10-line window: lines 141 and 148 (7 apart) group, 167 does not.
	findings := []analysis.Finding{
		{RuleID: "PF-GRAPHQL-AUTH-001", FilePath: "core/views.py", LineStart: 141, Title: "GraphQL authorization"},
		{RuleID: "PF-GRAPHQL-AUTH-001", FilePath: "core/views.py", LineStart: 148, Title: "GraphQL authorization"},
		{RuleID: "PF-GRAPHQL-AUTH-001", FilePath: "core/views.py", LineStart: 167, Title: "GraphQL authorization"},
	}
	result := groupIssues(findings, "")
	groups := map[string]int{}
	for _, f := range result {
		groups[f.IssueGroupID] = f.OccurrenceCount
	}
	if len(groups) != 2 {
		t.Fatalf("expected 2 issue groups (proximity: 141+148 grouped, 167 separate), got %d", len(groups))
	}
}

func TestGroupIssuesFunctionBoundaryDetection(t *testing.T) {
	// Create a temp file with function boundaries and verify grouping
	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "views.py")
	src := `class EditPaste:
    def mutate(self, info, id):
        paste = Paste.query.filter_by(id=id).first()
        Paste.query.filter_by(id=id).update(dict(title=title))

class DeletePaste:
    def mutate(self, info, id):
        Paste.query.filter_by(id=id).delete()
`
	if err := os.WriteFile(srcFile, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	findings := []analysis.Finding{
		{RuleID: "PF-GRAPHQL-AUTH-001", FilePath: srcFile, LineStart: 4, Title: "GraphQL authorization"},
		{RuleID: "PF-GRAPHQL-AUTH-001", FilePath: srcFile, LineStart: 5, Title: "GraphQL authorization"},
		{RuleID: "PF-GRAPHQL-AUTH-001", FilePath: srcFile, LineStart: 9, Title: "GraphQL authorization"},
	}
	result := groupIssues(findings, tmpDir)
	groups := map[string]int{}
	for _, f := range result {
		groups[f.IssueGroupID] = f.OccurrenceCount
	}
	// Lines 4,5 are in mutate (EditPaste) → 1 group
	// Line 9 is in mutate (DeletePaste) → separate group
	if len(groups) != 2 {
		t.Fatalf("expected 2 issue groups (function boundary detection), got %d", len(groups))
	}
	// Find the group with 2 occurrences
	foundGroup := false
	for _, occ := range groups {
		if occ == 2 {
			foundGroup = true
		}
	}
	if !foundGroup {
		t.Error("expected one group with 2 occurrences (lines 4+5 in EditPaste.mutate)")
	}
}

func TestGroupIssuesDifferentRulesNotGrouped(t *testing.T) {
	findings := []analysis.Finding{
		{RuleID: "PF-GRAPHQL-AUTH-001", FilePath: "core/views.py", LineStart: 141, Title: "IDOR"},
		{RuleID: "PF-GRAPHQL-SQLI-001", FilePath: "core/views.py", LineStart: 142, Title: "SQLi"},
	}
	result := groupIssues(findings, "")
	groups := map[string]int{}
	for _, f := range result {
		groups[f.IssueGroupID] = f.OccurrenceCount
	}
	if len(groups) != 2 {
		t.Fatalf("expected 2 issue groups (different rules), got %d", len(groups))
	}
}

func TestGroupIssuesDifferentFilesNotGrouped(t *testing.T) {
	findings := []analysis.Finding{
		{RuleID: "PF-GRAPHQL-AUTH-001", FilePath: "core/views.py", LineStart: 141, Title: "IDOR"},
		{RuleID: "PF-GRAPHQL-AUTH-001", FilePath: "core/other.py", LineStart: 141, Title: "IDOR"},
	}
	result := groupIssues(findings, "")
	groups := map[string]int{}
	for _, f := range result {
		groups[f.IssueGroupID] = f.OccurrenceCount
	}
	if len(groups) != 2 {
		t.Fatalf("expected 2 issue groups (different files), got %d", len(groups))
	}
}

func TestDetectFunctionBoundaries(t *testing.T) {
	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "app.py")
	src := `class MyClass:
    def method_one(self):
        pass

    def method_two(self):
        pass

def standalone_func():
    pass
`
	if err := os.WriteFile(srcFile, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	boundaries := detectFunctionBoundaries(srcFile)
	// class MyClass (1), def method_one (2), def method_two (5), def standalone_func (8)
	if len(boundaries) != 4 {
		t.Fatalf("expected 4 function boundaries, got %d: %+v", len(boundaries), boundaries)
	}
	if boundaries[0].name != "MyClass" || boundaries[0].line != 1 {
		t.Errorf("boundary 0: expected MyClass at line 1, got %s at line %d", boundaries[0].name, boundaries[0].line)
	}
	if boundaries[1].name != "method_one" || boundaries[1].line != 2 {
		t.Errorf("boundary 1: expected method_one at line 2, got %s at line %d", boundaries[1].name, boundaries[1].line)
	}
}

func TestFindFunctionForLine(t *testing.T) {
	boundaries := []functionBoundary{
		{line: 10, name: "func_a"},
		{line: 50, name: "func_b"},
		{line: 100, name: "func_c"},
	}
	tests := []struct {
		line int
		want string
	}{
		{5, ""},      // before any function
		{10, "func_a"},
		{30, "func_a"},
		{50, "func_b"},
		{75, "func_b"},
		{100, "func_c"},
		{200, "func_c"},
	}
	for _, tt := range tests {
		b := findFunctionForLine(boundaries, tt.line)
		if tt.want == "" {
			if b != nil {
				t.Errorf("line %d: expected nil, got %s", tt.line, b.name)
			}
		} else {
			if b == nil {
				t.Errorf("line %d: expected %s, got nil", tt.line, tt.want)
			} else if b.name != tt.want {
				t.Errorf("line %d: expected %s, got %s", tt.line, tt.want, b.name)
			}
		}
	}
}
