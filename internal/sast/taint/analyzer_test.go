package taint

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestTaintSQLInjection(t *testing.T) {
	dir := t.TempDir()

	// Create a Go module with a SQL injection vulnerability
	writeGoFile(t, dir, "go.mod", `module testapp

go 1.25.6
`)
	writeGoFile(t, dir, "main.go", `package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	query := "SELECT * FROM users WHERE name = '" + name + "'"
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
}

func main() {
	http.HandleFunc("/users", handler)
	http.ListenAndServe(":8080", nil)
}
`)

	analyzer := NewAnalyzer()
	findings, err := analyzer.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	foundG701 := false
	for _, f := range findings {
		if f.RuleID == "G701" {
			foundG701 = true
		}
	}
	if !foundG701 {
		t.Errorf("expected G701 (SQL injection) finding, got %d findings: %v", len(findings), findings)
	}
}

func TestTaintCommandInjection(t *testing.T) {
	dir := t.TempDir()

	writeGoFile(t, dir, "go.mod", `module testapp

go 1.25.6
`)
	writeGoFile(t, dir, "main.go", `package main

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	output, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		w.Write([]byte(err.Error()))
		return
	}
	w.Write(output)
}

func main() {}
`)

	analyzer := NewAnalyzer()
	findings, err := analyzer.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	foundG702 := false
	for _, f := range findings {
		if f.RuleID == "G702" {
			foundG702 = true
		}
	}
	if !foundG702 {
		t.Errorf("expected G702 (command injection) finding, got %d findings", len(findings))
	}
}

func TestTaintPathTraversal(t *testing.T) {
	dir := t.TempDir()

	writeGoFile(t, dir, "go.mod", `module testapp

go 1.25.6
`)
	writeGoFile(t, dir, "main.go", `package main

import (
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	data, err := os.ReadFile(filename)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write(data)
}

func main() {}
`)

	analyzer := NewAnalyzer()
	findings, err := analyzer.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	foundG703 := false
	for _, f := range findings {
		if f.RuleID == "G703" {
			foundG703 = true
		}
	}
	if !foundG703 {
		t.Errorf("expected G703 (path traversal) finding, got %d findings", len(findings))
	}
}

func TestTaintNoFalsePositiveWithSanitizer(t *testing.T) {
	dir := t.TempDir()

	writeGoFile(t, dir, "go.mod", `module testapp

go 1.25.6
`)
	writeGoFile(t, dir, "main.go", `package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	cleaned := filepath.Clean(filename)
	data, err := os.ReadFile(cleaned)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write(data)
}

func main() {}
`)

	analyzer := NewAnalyzer()
	findings, err := analyzer.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// filepath.Clean is a sanitizer — should NOT find G703
	for _, f := range findings {
		if f.RuleID == "G703" {
			t.Errorf("false positive: G703 triggered despite filepath.Clean sanitizer at %s:%d",
				f.FilePath, f.LineStart)
		}
	}
}

func TestTaintRules(t *testing.T) {
	analyzer := NewAnalyzer()
	rules := analyzer.Rules()

	expectedRules := []string{"G701", "G702", "G703", "G704", "G705", "G706", "G708", "G709", "G710"}
	ruleMap := make(map[string]bool)
	for _, r := range rules {
		ruleMap[r.ID] = true
	}

	for _, expected := range expectedRules {
		if !ruleMap[expected] {
			t.Errorf("expected rule %s in Rules(), not found", expected)
		}
	}
}

func writeGoFile(t *testing.T, dir, name, content string) {
	t.Helper()
	fullPath := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
}
