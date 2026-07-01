package suppression

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseSuppression_RuleSpecific(t *testing.T) {
	sup := parseSuppression(`	//patchflow:ignore G404 -- using math/rand for non-security purpose`)
	if sup == nil {
		t.Fatal("expected non-nil suppression")
	}
	if sup.RuleID != "G404" {
		t.Errorf("RuleID = %q, want %q", sup.RuleID, "G404")
	}
	if sup.Comment != "using math/rand for non-security purpose" {
		t.Errorf("Comment = %q, want %q", sup.Comment, "using math/rand for non-security purpose")
	}
}

func TestParseSuppression_Blanket(t *testing.T) {
	sup := parseSuppression(`	//patchflow:ignore`)
	if sup == nil {
		t.Fatal("expected non-nil suppression")
	}
	if sup.RuleID != "" {
		t.Errorf("RuleID = %q, want empty", sup.RuleID)
	}
}

func TestParseSuppression_PythonComment(t *testing.T) {
	sup := parseSuppression(`# patchflow:ignore PY001 -- eval is safe here`)
	if sup == nil {
		t.Fatal("expected non-nil suppression")
	}
	if sup.RuleID != "PY001" {
		t.Errorf("RuleID = %q, want %q", sup.RuleID, "PY001")
	}
}

func TestParseSuppression_NoDirective(t *testing.T) {
	sup := parseSuppression(`	// just a regular comment`)
	if sup != nil {
		t.Errorf("expected nil for non-directive comment, got %+v", sup)
	}
}

func TestParseSuppression_Inline(t *testing.T) {
	sup := parseSuppression(`	n := rand.Intn(100) //patchflow:ignore G404`)
	if sup == nil {
		t.Fatal("expected non-nil suppression for inline directive")
	}
	if sup.RuleID != "G404" {
		t.Errorf("RuleID = %q, want %q", sup.RuleID, "G404")
	}
}

func TestManager_IsSuppressed_Inline(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "test.go")
	writeFile(t, filePath, `package main

import "math/rand"

func main() {
	n := rand.Intn(100) //patchflow:ignore G404
	_ = n
}
`)

	mgr := NewManager()
	if !mgr.IsSuppressed(filePath, 6, "G404") {
		t.Errorf("expected G404 on line 6 to be suppressed (inline)")
	}
	if mgr.IsSuppressed(filePath, 6, "G101") {
		t.Errorf("G101 should NOT be suppressed (only G404 is)")
	}
}

func TestManager_IsSuppressed_AboveLine(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "test.go")
	writeFile(t, filePath, `package main

import "math/rand"

func main() {
	//patchflow:ignore G404
	n := rand.Intn(100)
	_ = n
}
`)

	mgr := NewManager()
	if !mgr.IsSuppressed(filePath, 7, "G404") {
		t.Errorf("expected G404 on line 7 to be suppressed (directive on line above)")
	}
}

func TestManager_IsSuppressed_Blanket(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "test.go")
	writeFile(t, filePath, `package main

import "math/rand"

func main() {
	//patchflow:ignore
	n := rand.Intn(100)
	_ = n
}
`)

	mgr := NewManager()
	if !mgr.IsSuppressed(filePath, 7, "G404") {
		t.Errorf("expected G404 on line 7 to be suppressed (blanket)")
	}
	if !mgr.IsSuppressed(filePath, 7, "G101") {
		t.Errorf("expected G101 on line 7 to be suppressed (blanket)")
	}
}

func TestManager_IsSuppressed_NotSuppressed(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "test.go")
	writeFile(t, filePath, `package main

import "math/rand"

func main() {
	n := rand.Intn(100)
	_ = n
}
`)

	mgr := NewManager()
	if mgr.IsSuppressed(filePath, 6, "G404") {
		t.Errorf("expected G404 on line 6 to NOT be suppressed")
	}
}

func TestManager_CacheWorks(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "test.go")
	writeFile(t, filePath, `//patchflow:ignore G404
package main
`)

	mgr := NewManager()
	// First call loads from disk
	if !mgr.IsSuppressed(filePath, 1, "G404") {
		t.Errorf("expected suppression on first call")
	}
	// Second call should use cache
	if !mgr.IsSuppressed(filePath, 1, "G404") {
		t.Errorf("expected suppression on second call (cached)")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
}
