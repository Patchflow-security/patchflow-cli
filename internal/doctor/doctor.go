package doctor

import (
	"strings"

	"github.com/patchflow/patchflow-cli/internal/git"
	"github.com/patchflow/patchflow-cli/internal/sast"
)

// Report contains the results of the environment diagnostic checks.
type Report struct {
	IsGitRepo  bool     `json:"is_git_repo"`
	GitVersion string   `json:"git_version"`
	RepoRoot   string   `json:"repo_root"`
	RemoteURL  string   `json:"remote_url"`
	Errors     []string `json:"errors"`

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
	report := &Report{Errors: []string{}}

	executor := &git.ShellExecutor{}
	version, err := executor.Run("", "--version")
	if err != nil {
		report.Errors = append(report.Errors, "git is not installed or not in PATH")
		return report, nil
	}
	report.GitVersion = strings.TrimSpace(version)

	repo, err := git.Detect()
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report, nil
	}

	report.IsGitRepo = true
	report.RepoRoot = repo.Root
	report.RemoteURL = repo.RemoteURL

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

	return report, nil
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
