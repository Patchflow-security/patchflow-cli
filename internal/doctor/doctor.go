package doctor

import (
	"strings"

	"github.com/patchflow/patchflow-cli/internal/git"
)

// Report contains the results of the environment diagnostic checks.
type Report struct {
	IsGitRepo  bool     `json:"is_git_repo"`
	GitVersion string   `json:"git_version"`
	RepoRoot   string   `json:"repo_root"`
	RemoteURL  string   `json:"remote_url"`
	Errors     []string `json:"errors"`
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

	return report, nil
}
