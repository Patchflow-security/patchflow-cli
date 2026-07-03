package ignore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewMatcherFromBytes(t *testing.T) {
	m := NewMatcherFromBytes(".", []byte("*.log\nbuild/\n!important.log\n"))
	if m.IsEmpty() {
		t.Fatal("matcher should not be empty")
	}
	if m.PatternCount() != 3 {
		t.Errorf("expected 3 patterns, got %d", m.PatternCount())
	}
}

func TestMatchSimpleGlob(t *testing.T) {
	m := NewMatcherFromBytes(".", []byte("*.log\n"))
	tests := []struct {
		path string
		want bool
	}{
		{"debug.log", true},
		{"foo/bar.log", true}, // unanchored, matches at any level
		{"notignored.txt", false},
		{"README.md", false},
	}
	for _, tt := range tests {
		got := m.Match(tt.path, false)
		if got != tt.want {
			t.Errorf("Match(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestMatchAnchored(t *testing.T) {
	m := NewMatcherFromBytes(".", []byte("/build\n"))
	tests := []struct {
		path string
		want bool
	}{
		{"build", true},
		{"build/output.o", true},
		{"foo/build", false}, // anchored — only matches at root
	}
	for _, tt := range tests {
		got := m.Match(tt.path, false)
		if got != tt.want {
			t.Errorf("Match(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestMatchDirectoryOnly(t *testing.T) {
	m := NewMatcherFromBytes(".", []byte("build/\n"))
	// Directory-only pattern: matches the directory and everything inside
	if !m.Match("build", true) {
		t.Error("build/ should match directory 'build'")
	}
	if !m.Match("build/output.o", false) {
		t.Error("build/ should match file inside 'build' directory")
	}
	if m.Match("build", false) {
		t.Error("build/ should NOT match when isDir=false (it's dir-only)")
	}
}

func TestMatchNegation(t *testing.T) {
	m := NewMatcherFromBytes(".", []byte("*.log\n!important.log\n"))
	if !m.Match("debug.log", false) {
		t.Error("*.log should match debug.log")
	}
	if m.Match("important.log", false) {
		t.Error("!important.log should negate the *.log match")
	}
}

func TestMatchDoubleStar(t *testing.T) {
	m := NewMatcherFromBytes(".", []byte("**/cache\n"))
	tests := []struct {
		path string
		want bool
	}{
		{"cache", true},
		{"foo/cache", true},
		{"foo/bar/cache", true},
		{"foo/bar/baz.go", false},
	}
	for _, tt := range tests {
		got := m.Match(tt.path, true)
		if got != tt.want {
			t.Errorf("Match(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestMatchPathWithSlash(t *testing.T) {
	// A pattern with a / anywhere is implicitly anchored
	m := NewMatcherFromBytes(".", []byte("foo/bar\n"))
	if !m.Match("foo/bar", false) {
		t.Error("foo/bar should match foo/bar")
	}
	if m.Match("baz/foo/bar", false) {
		t.Error("foo/bar is implicitly anchored, should not match baz/foo/bar")
	}
}

func TestEmptyMatcher(t *testing.T) {
	m := NewMatcherFromBytes(".", []byte("# just a comment\n\n"))
	if !m.IsEmpty() {
		t.Error("matcher with only comments should be empty")
	}
	if m.Match("anything.go", false) {
		t.Error("empty matcher should not match anything")
	}
}

func TestNewMatcherFromDisk(t *testing.T) {
	// Create a temp directory with a .gitignore
	dir := t.TempDir()
	gitignoreContent := "*.tmp\nnode_modules/\n!important.tmp\n"
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(gitignoreContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Create some files
	os.Mkdir(filepath.Join(dir, "node_modules"), 0755)
	os.WriteFile(filepath.Join(dir, "test.tmp"), []byte("test"), 0644)
	os.WriteFile(filepath.Join(dir, "important.tmp"), []byte("important"), 0644)
	os.WriteFile(filepath.Join(dir, "keep.go"), []byte("package main"), 0644)

	m := NewMatcher(dir)
	if m.IsEmpty() {
		t.Fatal("matcher should not be empty when .gitignore exists")
	}

	if !m.Match(filepath.Join(dir, "test.tmp"), false) {
		t.Error("test.tmp should be ignored")
	}
	if m.Match(filepath.Join(dir, "important.tmp"), false) {
		t.Error("important.tmp should NOT be ignored (negated)")
	}
	if !m.Match(filepath.Join(dir, "node_modules"), true) {
		t.Error("node_modules/ should be ignored")
	}
	if m.Match(filepath.Join(dir, "keep.go"), false) {
		t.Error("keep.go should NOT be ignored")
	}
}

func TestNestedGitignore(t *testing.T) {
	dir := t.TempDir()

	// Root .gitignore
	os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("*.log\n"), 0644)

	// Subdirectory with its own .gitignore
	subDir := filepath.Join(dir, "subdir")
	os.Mkdir(subDir, 0755)
	os.WriteFile(filepath.Join(subDir, ".gitignore"), []byte("*.local\n"), 0644)

	m := NewMatcher(dir)

	// Root pattern applies everywhere
	if !m.Match(filepath.Join(dir, "app.log"), false) {
		t.Error("app.log should be ignored by root .gitignore")
	}
	if !m.Match(filepath.Join(subDir, "debug.log"), false) {
		t.Error("subdir/debug.log should be ignored by root .gitignore")
	}

	// Subdirectory pattern only applies within that directory
	if !m.Match(filepath.Join(subDir, "config.local"), false) {
		t.Error("subdir/config.local should be ignored by nested .gitignore")
	}
	if m.Match(filepath.Join(dir, "config.local"), false) {
		t.Error("root config.local should NOT be ignored (nested pattern only)")
	}
}

func TestCacheLazyInit(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("*.bak\n"), 0644)

	c := NewCache(dir)
	if !c.Match(filepath.Join(dir, "backup.bak"), false) {
		t.Error("backup.bak should be ignored via cache")
	}
}

func TestMatchQuestionMark(t *testing.T) {
	m := NewMatcherFromBytes(".", []byte("temp?.txt\n"))
	if !m.Match("temp1.txt", false) {
		t.Error("temp?.txt should match temp1.txt")
	}
	if !m.Match("tempA.txt", false) {
		t.Error("temp?.txt should match tempA.txt")
	}
	if m.Match("temp12.txt", false) {
		t.Error("temp?.txt should NOT match temp12.txt (? = single char)")
	}
}
