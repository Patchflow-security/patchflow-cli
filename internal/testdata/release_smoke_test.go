package testdata

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestReleaseSmoke is the golden release test matrix (B12.9).
// It runs the built patchflow binary against each smoke fixture
// and verifies expected findings counts.
//
// Fixtures are copied to temp directories to avoid the Go SAST
// scanner picking up the patchflow-cli module.
//
// This test requires the patchflow binary at /tmp/patchflow-b12
// or in the project root.

func TestReleaseSmoke(t *testing.T) {
	binary := binaryPath(t)
	if binary == "" {
		t.Skip("patchflow binary not found, skipping release smoke test")
	}

	fixturesDir := fixturesDir(t)

	tests := []struct {
		name        string
		fixture     string
		framework   string
		configPath  string
		minFindings int
		maxFindings int
	}{
		{
			name:        "spring-custom-extension-scoped-sink",
			fixture:     "spring-custom-extension",
			framework:   "spring",
			configPath:  ".patchflow/rules.yaml",
			minFindings: 1,
			maxFindings: 10,
		},
		{
			name:        "graphql-sqli",
			fixture:     "graphql-sqli",
			framework:   "graphql",
			minFindings: 1,
			maxFindings: 10,
		},
		{
			name:        "express-sqli",
			fixture:     "express-sqli",
			framework:   "express",
			minFindings: 1,
			maxFindings: 10,
		},
		{
			name:        "clean-go-no-false-positives",
			fixture:     "clean-go",
			minFindings: 0,
			maxFindings: 0,
		},
		{
			name:        "clean-python-no-false-positives",
			fixture:     "clean-python",
			minFindings: 0,
			maxFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Copy fixture to a temp directory to avoid git/module interference
			srcDir := filepath.Join(fixturesDir, tt.fixture)
			tmpDir := t.TempDir()
			if err := copyDir(srcDir, tmpDir); err != nil {
				t.Fatalf("failed to copy fixture: %v", err)
			}

			args := []string{"scan", "run", "--json", "--quiet", "--offline", "--no-gitignore", "--no-licenses"}
			if tt.framework != "" {
				args = append(args, "--framework", tt.framework)
			}
			if tt.configPath != "" {
				configAbs := filepath.Join(tmpDir, tt.configPath)
				if _, err := os.Stat(configAbs); err == nil {
					args = append(args, "--config", configAbs)
				}
			}

			cmd := exec.Command(binary, args...)
			cmd.Dir = tmpDir
			output, err := cmd.Output()
			if err != nil {
				t.Fatalf("patchflow scan failed: %v\noutput: %s", err, output)
			}

			var result struct {
				Analysis struct {
					Findings []struct {
						RuleID   string `json:"rule_id"`
						Analyzer string `json:"analyzer"`
						FilePath string `json:"file_path"`
					} `json:"findings"`
				} `json:"analysis"`
			}
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatalf("failed to parse JSON output: %v", err)
			}

			// Filter to only SAST findings (exclude SCA, license, secret findings)
			var sastFindings int
			for _, f := range result.Analysis.Findings {
				if f.Analyzer == "taint-patterns" || f.Analyzer == "patterns-embedded" ||
					f.Analyzer == "treesitter-ast" || f.Analyzer == "gosast-embedded" ||
					f.Analyzer == "framework-taint" || f.Analyzer == "framework-pattern" {
					sastFindings++
				}
			}

			if sastFindings < tt.minFindings {
				t.Errorf("expected at least %d SAST findings, got %d", tt.minFindings, sastFindings)
			}
			if sastFindings > tt.maxFindings {
				t.Errorf("expected at most %d SAST findings, got %d (potential false positives)", tt.maxFindings, sastFindings)
			}
		})
	}
}

func binaryPath(t *testing.T) string {
	t.Helper()
	candidates := []string{
		"/tmp/patchflow-b12",
		"../../../patchflow",
		"../../../../patchflow",
	}
	for _, c := range candidates {
		abs, _ := filepath.Abs(c)
		if _, err := os.Stat(abs); err == nil {
			return abs
		}
	}
	return ""
}

func fixturesDir(t *testing.T) string {
	t.Helper()
	// Test runs in internal/testdata/, fixtures are in release-smoke/
	abs, _ := filepath.Abs("release-smoke")
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("fixtures directory not found: %s", abs)
	}
	return abs
}

// copyDir copies a directory recursively.
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		dstPath := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(dstPath, 0755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(dstPath, data, 0644)
	})
}
