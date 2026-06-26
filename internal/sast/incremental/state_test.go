package incremental

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/patchflow/patchflow-cli/internal/ignore"
)

// writeFile writes content to relPath under dir, creating parent directories.
func writeFile(t *testing.T, dir, relPath, content string) {
	t.Helper()
	full := filepath.Join(dir, relPath)
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", relPath, err)
	}
}

// fileHash returns the expected stored hash for content.
func fileHash(content string) string {
	h := sha256.Sum256([]byte(content))
	return hex.EncodeToString(h[:])
}

func TestFirstRunAllChanged(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.go", "package main\n")
	writeFile(t, dir, "b.py", "print('hi')\n")

	s := LoadState(dir)
	m := ignore.NewMatcher(dir)

	changed := s.GetChangedFiles(dir, m)
	if len(changed) != 2 {
		t.Fatalf("first run: expected 2 changed files, got %d (%v)", len(changed), changed)
	}
}

func TestSecondRunOnlyModifiedChanged(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.go", "package main\n")
	writeFile(t, dir, "b.py", "print('hi')\n")

	m := ignore.NewMatcher(dir)

	// First run: record hashes for all changed files.
	s := LoadState(dir)
	for _, p := range s.GetChangedFiles(dir, m) {
		s.UpdateHash(p, fileHash(mustReadFile(t, p)))
	}
	if err := s.SaveState(dir); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Modify one file.
	writeFile(t, dir, "a.go", "package main\n// changed\n")

	// Second run: load persisted state.
	s2 := LoadState(dir)
	changed := s2.GetChangedFiles(dir, m)
	if len(changed) != 1 {
		t.Fatalf("second run: expected 1 changed file, got %d (%v)", len(changed), changed)
	}
	if !strings.HasSuffix(changed[0], "a.go") {
		t.Fatalf("expected a.go to be changed, got %s", changed[0])
	}

	unchanged := s2.GetUnchangedFiles(dir, m)
	if len(unchanged) != 1 {
		t.Fatalf("second run: expected 1 unchanged file, got %d (%v)", len(unchanged), unchanged)
	}
	if !strings.HasSuffix(unchanged[0], "b.py") {
		t.Fatalf("expected b.py to be unchanged, got %s", unchanged[0])
	}
}

func TestCorruptedStateAllChanged(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.go", "package main\n")

	// Write a corrupted state file.
	cacheDir := filepath.Join(dir, ".patchflow", "cache")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	statePath := filepath.Join(cacheDir, "sast_state.json")
	if err := os.WriteFile(statePath, []byte("{not valid json"), 0644); err != nil {
		t.Fatalf("write corrupt state: %v", err)
	}

	s := LoadState(dir)
	m := ignore.NewMatcher(dir)

	changed := s.GetChangedFiles(dir, m)
	if len(changed) != 1 {
		t.Fatalf("corrupted state: expected 1 changed file, got %d (%v)", len(changed), changed)
	}
}

func TestSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.go", "package main\n")
	writeFile(t, dir, "b.py", "print('hi')\n")

	m := ignore.NewMatcher(dir)

	s := LoadState(dir)
	for _, p := range s.GetChangedFiles(dir, m) {
		s.UpdateHash(p, fileHash(mustReadFile(t, p)))
	}
	if err := s.SaveState(dir); err != nil {
		t.Fatalf("save: %v", err)
	}

	s2 := LoadState(dir)
	if len(s2.files) != 2 {
		t.Fatalf("roundtrip: expected 2 files in state, got %d", len(s2.files))
	}

	// No files should be changed after roundtrip.
	changed := s2.GetChangedFiles(dir, m)
	if len(changed) != 0 {
		t.Fatalf("roundtrip: expected 0 changed files, got %d (%v)", len(changed), changed)
	}
}

func TestDeletedFilesCleanedFromState(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.go", "package main\n")
	writeFile(t, dir, "b.py", "print('hi')\n")

	m := ignore.NewMatcher(dir)

	// Record state.
	s := LoadState(dir)
	for _, p := range s.GetChangedFiles(dir, m) {
		s.UpdateHash(p, fileHash(mustReadFile(t, p)))
	}
	if err := s.SaveState(dir); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Delete one file.
	if err := os.Remove(filepath.Join(dir, "b.py")); err != nil {
		t.Fatalf("remove: %v", err)
	}

	// Reload and prune.
	s2 := LoadState(dir)
	removed := s2.PruneDeleted(dir, m)
	if removed != 1 {
		t.Fatalf("expected 1 pruned entry, got %d", removed)
	}
	if _, ok := s2.files["b.py"]; ok {
		t.Fatal("b.py should have been pruned from state")
	}
	if _, ok := s2.files["a.go"]; !ok {
		t.Fatal("a.go should still be in state")
	}
}

func TestSkipDirsExcluded(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.go", "package main\n")
	writeFile(t, dir, "node_modules/lib.js", "module.exports = 1\n")
	writeFile(t, dir, "vendor/pkg.go", "package pkg\n")

	m := ignore.NewMatcher(dir)
	s := LoadState(dir)

	changed := s.GetChangedFiles(dir, m)
	if len(changed) != 1 {
		t.Fatalf("expected only a.go (skip dirs), got %d (%v)", len(changed), changed)
	}
	if !strings.HasSuffix(changed[0], "a.go") {
		t.Fatalf("expected a.go, got %s", changed[0])
	}
}

func TestLargeFileSkipped(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.go", "package main\n")
	// Create a file larger than 2MB.
	big := strings.Repeat("x", 2*1024*1024+10)
	writeFile(t, dir, "big.txt", big)

	m := ignore.NewMatcher(dir)
	s := LoadState(dir)

	changed := s.GetChangedFiles(dir, m)
	if len(changed) != 1 {
		t.Fatalf("expected only a.go (large file skipped), got %d (%v)", len(changed), changed)
	}
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
