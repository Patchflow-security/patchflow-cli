package scan

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/git"
)

// GitHubUploadConfig holds the parameters required to upload a SARIF report
// to the GitHub Code Scanning API.
type GitHubUploadConfig struct {
	Owner    string // repository owner
	Repo     string // repository name
	CommitSHA string // commit SHA the scan ran against
	Ref      string // git ref (e.g. refs/heads/main)
	ToolName string // optional tool name reported to GitHub
	Token    string // GitHub authentication token
}

// GitHubUploadResult is the response returned by the GitHub SARIF upload API.
type GitHubUploadResult struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

// sarifUploadRequest is the JSON body sent to the GitHub Code Scanning SARIF API.
type sarifUploadRequest struct {
	CommitSHA string `json:"commit_sha"`
	Ref       string `json:"ref"`
	SARIF     string `json:"sarif"`
	ToolName  string `json:"tool_name,omitempty"`
}

// githubAPIError describes an error response returned by the GitHub API.
type githubAPIError struct {
	Message string `json:"message"`
	Status  string `json:"status"`
}

const (
	githubAPIBase    = "https://api.github.com"
	githubAPIVersion = "2022-11-28"
	uploadTimeout    = 60 * time.Second
)

// UploadSARIF uploads the given SARIF payload to GitHub Code Scanning.
// It returns the upload identifier and status URL on success.
func UploadSARIF(cfg *GitHubUploadConfig, sarifData []byte) (*GitHubUploadResult, error) {
	if cfg == nil {
		return nil, fmt.Errorf("upload config is required")
	}
	if cfg.Owner == "" || cfg.Repo == "" {
		return nil, fmt.Errorf("GitHub owner and repo are required for SARIF upload")
	}
	if cfg.CommitSHA == "" {
		return nil, fmt.Errorf("commit SHA is required for SARIF upload")
	}
	if cfg.Ref == "" {
		return nil, fmt.Errorf("git ref is required for SARIF upload")
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("GitHub token is required for SARIF upload (set GITHUB_TOKEN or PATCHFLOW_GITHUB_TOKEN)")
	}
	if len(sarifData) == 0 {
		return nil, fmt.Errorf("SARIF data is empty")
	}

	toolName := cfg.ToolName
	if toolName == "" {
		toolName = "PatchFlow CLI"
	}

	body := &sarifUploadRequest{
		CommitSHA: cfg.CommitSHA,
		Ref:       cfg.Ref,
		SARIF:     base64.StdEncoding.EncodeToString(sarifData),
		ToolName:  toolName,
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SARIF upload request: %w", err)
	}

	url := fmt.Sprintf("%s/repos/%s/%s/code-scanning/sarifs", githubAPIBase, cfg.Owner, cfg.Repo)

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create upload request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: uploadTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to upload SARIF to GitHub: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr githubAPIError
		if jsonErr := json.Unmarshal(respBody, &apiErr); jsonErr == nil && apiErr.Message != "" {
			return nil, fmt.Errorf("GitHub SARIF upload failed (HTTP %d): %s", resp.StatusCode, apiErr.Message)
		}
		return nil, fmt.Errorf("GitHub SARIF upload failed (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var result GitHubUploadResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse GitHub upload response: %w", err)
	}

	return &result, nil
}

// ResolveGitHubUploadConfig builds a GitHubUploadConfig from environment
// variables and git metadata. Environment variables set by GitHub Actions
// (GITHUB_REPOSITORY, GITHUB_SHA, GITHUB_REF) take precedence, falling back
// to git remote/branch/sha detection.
func ResolveGitHubUploadConfig(repo *git.Repository) (*GitHubUploadConfig, error) {
	cfg := &GitHubUploadConfig{}

	// Owner/repo resolution.
	if ghRepo := os.Getenv("GITHUB_REPOSITORY"); ghRepo != "" {
		owner, name, ok := splitOwnerRepo(ghRepo)
		if ok {
			cfg.Owner = owner
			cfg.Repo = name
		}
	}
	if cfg.Owner == "" && repo != nil && repo.RemoteURL != "" {
		owner, name, ok := parseGitHubRemote(repo.RemoteURL)
		if ok {
			cfg.Owner = owner
			cfg.Repo = name
		}
	}
	if cfg.Owner == "" {
		return nil, fmt.Errorf("could not determine GitHub owner/repo: set GITHUB_REPOSITORY or configure a git origin remote")
	}

	// Commit SHA resolution.
	if sha := os.Getenv("GITHUB_SHA"); sha != "" {
		cfg.CommitSHA = sha
	} else if repo != nil && repo.CommitSHA != "" {
		cfg.CommitSHA = repo.CommitSHA
	}
	if cfg.CommitSHA == "" {
		return nil, fmt.Errorf("could not determine commit SHA: set GITHUB_SHA or run inside a git repository")
	}

	// Ref resolution.
	if ref := os.Getenv("GITHUB_REF"); ref != "" {
		cfg.Ref = ref
	} else if repo != nil && repo.CurrentBranch != "" && repo.CurrentBranch != "local" {
		cfg.Ref = "refs/heads/" + repo.CurrentBranch
	}
	if cfg.Ref == "" {
		return nil, fmt.Errorf("could not determine git ref: set GITHUB_REF or run inside a git repository")
	}

	// Token resolution.
	cfg.Token = os.Getenv("GITHUB_TOKEN")
	if cfg.Token == "" {
		cfg.Token = os.Getenv("PATCHFLOW_GITHUB_TOKEN")
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("GitHub token not found: set GITHUB_TOKEN or PATCHFLOW_GITHUB_TOKEN")
	}

	return cfg, nil
}

// splitOwnerRepo splits a "owner/repo" string into its components.
func splitOwnerRepo(s string) (string, string, bool) {
	parts := strings.SplitN(strings.TrimSpace(s), "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

var (
	httpsRemoteRe = regexp.MustCompile(`github\.com[/:]([^/]+)/([^/]+?)(?:\.git)?$`)
)

// parseGitHubRemote extracts the owner and repo name from a GitHub remote URL.
// It supports HTTPS (https://github.com/owner/repo.git) and SSH
// (git@github.com:owner/repo.git) formats.
func parseGitHubRemote(remote string) (string, string, bool) {
	remote = strings.TrimSpace(remote)
	if remote == "" {
		return "", "", false
	}
	m := httpsRemoteRe.FindStringSubmatch(remote)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}
