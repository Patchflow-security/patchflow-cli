package doctor

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/Patchflow-security/patchflow-cli/internal/git"
	"github.com/Patchflow-security/patchflow-cli/internal/sast"
	"github.com/Patchflow-security/patchflow-cli/pkg/version"
)

// Report contains the results of the environment diagnostic checks.
type Report struct {
	// Version info (B12.8)
	Version    string `json:"version"`
	Commit     string `json:"commit"`
	GoVersion  string `json:"go_version"`
	BuiltAt    string `json:"built_at"`
	Status     string `json:"status"` // "ok", "warning", "error"

	IsGitRepo  bool     `json:"is_git_repo"`
	GitVersion string   `json:"git_version"`
	RepoRoot   string   `json:"repo_root"`
	RemoteURL  string   `json:"remote_url"`
	Errors     []string `json:"errors"`

	// Config checks (B12.8)
	ConfigFound   bool   `json:"config_found"`
	ConfigPath    string `json:"config_path"`
	ConfigValid   bool   `json:"config_valid"`
	ConfigError   string `json:"config_error,omitempty"`

	// Cache checks (B12.8)
	CacheDir      string `json:"cache_dir"`
	CacheWritable bool   `json:"cache_writable"`

	// SARIF output check (B12.8)
	SARIFWritable bool   `json:"sarif_writable"`
	SARIFError    string `json:"sarif_error,omitempty"`

	// Embedded scanners (always available)
	EmbeddedScanners []ScannerInfo `json:"embedded_scanners"`

	// External tools (optional supplements)
	ExternalTools []ToolInfo `json:"external_tools"`
}

// ScannerInfo describes an embedded scanner.
type ScannerInfo struct {
	Name      string `json:"name"`
	Language  string `json:"language"`
	RuleCount int    `json:"rule_count"`
	Status    string `json:"status"` // "available"
}

// ToolInfo describes an external tool.
type ToolInfo struct {
	Name     string `json:"name"`
	Language string `json:"language"`
	Found    bool   `json:"found"`
}

// Run performs environment diagnostics and returns a Report.
func Run() (*Report, error) {
	report := &Report{
		Version:   version.Version,
		Commit:    version.Commit,
		GoVersion: version.GoVersion(),
		BuiltAt:   version.Date,
		Status:    "ok",
		Errors:    []string{},
	}

	// Check git
	executor := &git.ShellExecutor{}
	gitVer, err := executor.Run("", "--version")
	if err != nil {
		report.Errors = append(report.Errors, "git is not installed or not in PATH")
		report.Status = "warning"
	} else {
		report.GitVersion = strings.TrimSpace(gitVer)
	}

	repo, err := git.Detect()
	if err == nil {
		report.IsGitRepo = true
		report.RepoRoot = repo.Root
		report.RemoteURL = repo.RemoteURL
	}

	// Check config file (B12.8)
	configDir := filepath.Join(report.RepoRoot, ".patchflow")
	configPath := filepath.Join(configDir, "rules.yaml")
	if _, err := os.Stat(configPath); err == nil {
		report.ConfigFound = true
		report.ConfigPath = configPath
		// Try to validate by loading
		if data, err := os.ReadFile(configPath); err == nil {
			if isValidConfig(data) {
				report.ConfigValid = true
			} else {
				report.ConfigValid = false
				report.ConfigError = "config file exists but could not be parsed"
				report.Status = "warning"
			}
		}
	} else if report.IsGitRepo {
		// Config not found is not an error, just note it
		report.ConfigFound = false
	}

	// Check cache directory writability (B12.8)
	cacheDir := defaultCacheDir()
	report.CacheDir = cacheDir
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		report.CacheWritable = false
		report.Status = "warning"
	} else {
		testFile := filepath.Join(cacheDir, ".doctor-write-test")
		if err := os.WriteFile(testFile, []byte("ok"), 0644); err != nil {
			report.CacheWritable = false
			report.Status = "warning"
		} else {
			report.CacheWritable = true
			os.Remove(testFile)
		}
	}

	// Check SARIF output writability (B12.8) — just test writing to cwd
	sarifTest := filepath.Join(report.RepoRoot, ".doctor-sarif-test.sarif")
	if err := os.WriteFile(sarifTest, []byte("{}"), 0644); err != nil {
		report.SARIFWritable = false
		report.SARIFError = err.Error()
		report.Status = "warning"
	} else {
		report.SARIFWritable = true
		os.Remove(sarifTest)
	}

	// Check embedded scanners
	runner := sast.NewRunner()
	groups := runner.AllRules()
	for _, g := range groups {
		report.EmbeddedScanners = append(report.EmbeddedScanners, ScannerInfo{
			Name:      g.Scanner,
			Language:  g.Language,
			RuleCount: g.RuleCount,
			Status:    "available",
		})
	}

	// Check external tools
	for _, name := range runner.AvailableTools() {
		report.ExternalTools = append(report.ExternalTools, ToolInfo{
			Name:     name,
			Language: toolLanguage(name),
			Found:    true,
		})
	}
	// Also list tools that are NOT available
	allTools := []string{"gosec", "bandit", "semgrep", "gitleaks"}
	availableSet := make(map[string]bool)
	for _, t := range report.ExternalTools {
		availableSet[t.Name] = true
	}
	for _, name := range allTools {
		if !availableSet[name] {
			report.ExternalTools = append(report.ExternalTools, ToolInfo{
				Name:     name,
				Language: toolLanguage(name),
				Found:    false,
			})
		}
	}

	if len(report.Errors) > 0 && report.Status == "ok" {
		report.Status = "warning"
	}
	return report, nil
}

// isValidConfig does a basic YAML parse check.
func isValidConfig(data []byte) bool {
	// Simple check: non-empty and looks like YAML
	s := strings.TrimSpace(string(data))
	if len(s) == 0 {
		return false
	}
	// If it starts with { or [, it's likely JSON-style YAML
	// Otherwise, check for at least one key: value pair
	if !strings.Contains(s, ":") {
		return false
	}
	return true
}

// defaultCacheDir returns the default cache directory path.
func defaultCacheDir() string {
	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
		return filepath.Join(xdg, "patchflow")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".cache", "patchflow")
	}
	return ".patchflow-cache"
}

func toolLanguage(name string) string {
	switch name {
	case "gosec":
		return "go"
	case "bandit":
		return "python"
	case "semgrep":
		return "multi"
	case "gitleaks":
		return "secrets"
	default:
		return "unknown"
	}
}
