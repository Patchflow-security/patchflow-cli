package pathutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateOutputPath_Valid(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name string
		path string
	}{
		{"simple filename", "report.json"},
		{"subdirectory", "reports/scan.json"},
		{"nested subdirectory", "reports/2024/scan.json"},
		{"absolute within base", filepath.Join(dir, "report.json")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateOutputPath(dir, tt.path); err != nil {
				t.Errorf("ValidateOutputPath(%s) failed: %v", tt.path, err)
			}
		})
	}
}

func TestValidateOutputPath_Empty(t *testing.T) {
	dir := t.TempDir()
	err := ValidateOutputPath(dir, "")
	if err == nil {
		t.Error("expected error for empty path")
	}
}

func TestValidateOutputPath_PathTraversal(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name string
		path string
	}{
		{"parent dir", "../report.json"},
		{"deep traversal", "../../../etc/passwd"},
		{"root escape", "../../etc/passwd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateOutputPath(dir, tt.path)
			if err == nil {
				t.Errorf("expected error for path traversal: %s", tt.path)
			}
		})
	}
}

func TestValidateOutputPath_AbsoluteOutsideBase(t *testing.T) {
	dir := t.TempDir()
	evil := t.TempDir()

	err := ValidateOutputPath(dir, filepath.Join(evil, "report.json"))
	if err == nil {
		t.Error("expected error for absolute path outside base")
	}
}

func TestValidateRulesPath_Valid(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name string
		path string
	}{
		{"yaml extension", "rules.yaml"},
		{"yml extension", "rules.yml"},
		{"subdirectory yaml", ".patchflow/rules.yaml"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateRulesPath(dir, tt.path); err != nil {
				t.Errorf("ValidateRulesPath(%s) failed: %v", tt.path, err)
			}
		})
	}
}

func TestValidateRulesPath_InvalidExtension(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name string
		path string
	}{
		{"json file", "rules.json"},
		{"txt file", "rules.txt"},
		{"no extension", "rules"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRulesPath(dir, tt.path)
			if err == nil {
				t.Errorf("expected error for invalid extension: %s", tt.path)
			}
		})
	}
}

func TestValidateRulesPath_PathTraversal(t *testing.T) {
	dir := t.TempDir()
	err := ValidateRulesPath(dir, "../evil.yaml")
	if err == nil {
		t.Error("expected error for path traversal")
	}
}

func TestValidateSuppressPath_Valid(t *testing.T) {
	dir := t.TempDir()
	err := ValidateSuppressPath(dir, ".patchflow/suppressions.yaml")
	if err != nil {
		t.Errorf("ValidateSuppressPath failed: %v", err)
	}
}

func TestValidateSuppressPath_PathTraversal(t *testing.T) {
	dir := t.TempDir()
	err := ValidateSuppressPath(dir, "../evil.yaml")
	if err == nil {
		t.Error("expected error for path traversal")
	}
}

func TestResolveWithinBase_Valid(t *testing.T) {
	dir := t.TempDir()
	resolved, err := ResolveWithinBase(dir, "report.json")
	if err != nil {
		t.Fatalf("ResolveWithinBase failed: %v", err)
	}
	expected := filepath.Join(dir, "report.json")
	if resolved != expected {
		t.Errorf("expected %s, got %s", expected, resolved)
	}
}

func TestResolveWithinBase_PathTraversal(t *testing.T) {
	dir := t.TempDir()
	_, err := ResolveWithinBase(dir, "../evil.txt")
	if err == nil {
		t.Error("expected error for path traversal")
	}
}

func TestResolveWithinBase_AbsoluteOutsideBase(t *testing.T) {
	dir := t.TempDir()
	evil := t.TempDir()
	_, err := ResolveWithinBase(dir, filepath.Join(evil, "evil.txt"))
	if err == nil {
		t.Error("expected error for absolute path outside base")
	}
}

func TestResolveWithinBase_Empty(t *testing.T) {
	dir := t.TempDir()
	_, err := ResolveWithinBase(dir, "")
	if err == nil {
		t.Error("expected error for empty path")
	}
}

func TestValidateOutputPath_SymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	evil := t.TempDir()

	// Create a symlink in dir that points to evil
	linkDir := filepath.Join(dir, "linkdir")
	if err := os.Symlink(evil, linkDir); err != nil {
		t.Skip("cannot create symlink: " + err.Error())
	}

	err := ValidateOutputPath(dir, "linkdir/report.json")
	if err == nil {
		t.Error("expected error for symlink escaping base directory")
	}
}
