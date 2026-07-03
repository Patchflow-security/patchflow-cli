package sast

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestMaskSecret(t *testing.T) {
	tests := []struct {
		input  string
		output string
	}{
		{"abc", "***"},
		{"ab", "**"},
		{"a", "*"},
		{"abcdef", "ab**ef"},
		{"1234567890", "12******90"},
		{"sk-1234567890abcdef", "sk***************ef"}, // 20 chars: first 2 + 16 stars + last 2
		{"  spaced  ", "sp**ed"},                       // trimmed to "spaced" (6 chars)
	}
	for _, tt := range tests {
		if got := maskSecret(tt.input); got != tt.output {
			t.Errorf("maskSecret(%q) = %q, want %q", tt.input, got, tt.output)
		}
	}
}

func TestNormalizeGosecSeverity(t *testing.T) {
	tests := []struct {
		input string
		sev   string
	}{
		{"HIGH", "high"},
		{"MEDIUM", "medium"},
		{"LOW", "low"},
		{"UNKNOWN", "info"},
	}
	for _, tt := range tests {
		if got := normalizeGosecSeverity(tt.input); string(got) != tt.sev {
			t.Errorf("normalizeGosecSeverity(%s) = %s, want %s", tt.input, got, tt.sev)
		}
	}
}

func TestNormalizeBanditSeverity(t *testing.T) {
	tests := []struct {
		input string
		sev   string
	}{
		{"high", "high"},
		{"MEDIUM", "medium"},
		{"low", "low"},
	}
	for _, tt := range tests {
		if got := normalizeBanditSeverity(tt.input); string(got) != tt.sev {
			t.Errorf("normalizeBanditSeverity(%s) = %s, want %s", tt.input, got, tt.sev)
		}
	}
}

func TestNormalizeSemgrepSeverity(t *testing.T) {
	tests := []struct {
		input string
		sev   string
	}{
		{"ERROR", "high"},
		{"WARNING", "medium"},
		{"INFO", "low"},
		{"CRITICAL", "critical"},
	}
	for _, tt := range tests {
		if got := normalizeSemgrepSeverity(tt.input); string(got) != tt.sev {
			t.Errorf("normalizeSemgrepSeverity(%s) = %s, want %s", tt.input, got, tt.sev)
		}
	}
}

func TestPlatformBinaryName(t *testing.T) {
	// Just verify it returns the name (or name.exe on windows)
	result := PlatformBinaryName("gosec")
	if result == "" {
		t.Error("PlatformBinaryName should not return empty string")
	}
}

func TestNewRunner(t *testing.T) {
	runner := NewRunner()
	if len(runner.Tools) != 5 {
		t.Errorf("expected 5 tools, got %d", len(runner.Tools))
	}

	// Check tool names
	names := make(map[string]bool)
	for _, tool := range runner.Tools {
		names[tool.Name] = true
	}
	for _, expected := range []string{"gosec", "bandit", "semgrep", "gitleaks"} {
		if !names[expected] {
			t.Errorf("missing tool: %s", expected)
		}
	}
}

func TestIsTestPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"src/auth.go", false},
		{"src/auth_test.go", true},
		{"tests/test_auth.py", true},
		{"app/test_auth.py", true},
		{"frontend/login.spec.tsx", true},
		{"frontend/__tests__/login.tsx", true},
	}

	for _, tt := range tests {
		if got := isTestPath(tt.path); got != tt.want {
			t.Errorf("isTestPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestAnalyzeLoadsFrameworkPolicyFromRulesYAML(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".patchflow"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".patchflow", "rules.yaml"), []byte(`
frameworks:
  auto_detect: false
  enabled: [rails]

framework_overrides:
  rails:
    severity_overrides:
      PF-RAILS-REDIRECT-001: high
`), 0o644); err != nil {
		t.Fatalf("write rules.yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "controller.rb"), []byte(`redirect_to params[:next_url]`), 0o644); err != nil {
		t.Fatalf("write controller.rb: %v", err)
	}

	runner := NewRunner()
	runner.Tools = nil
	runner.NoEmbeddedGo = true
	runner.NoEmbeddedSecrets = true
	runner.NoEmbeddedTreeSitter = true
	runner.NoEmbeddedTaint = true
	runner.NoEmbeddedTaintPatterns = true

	result, err := runner.Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	var found bool
	for _, finding := range result.Findings {
		if finding.RuleID == "PF-RAILS-REDIRECT-001" {
			found = true
			if finding.Severity != "high" {
				t.Fatalf("severity = %s, want high", finding.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("expected framework finding, got %+v", result.Findings)
	}
}
