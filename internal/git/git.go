package git

import (
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// Executor abstracts the execution of git commands.
type Executor interface {
	Run(dir string, args ...string) (string, error)
}

// ShellExecutor runs git commands using exec.Command.
type ShellExecutor struct{}

// Run executes a git command in the given directory and returns its combined output.
func (s *ShellExecutor) Run(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// Repository holds metadata about a git repository.
type Repository struct {
	Root          string
	RemoteURL     string
	CurrentBranch string
	CommitSHA     string
	BaseBranch    string
	ChangedFiles  []string
	AddedLines    int
	DeletedLines  int

	executor Executor
}

// NewRepository creates a new Repository using the provided executor.
// If executor is nil, a ShellExecutor is used.
func NewRepository(executor Executor) (*Repository, error) {
	if executor == nil {
		executor = &ShellExecutor{}
	}

	r := &Repository{executor: executor}

	root, err := r.executor.Run("", "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, errors.New("not a git repository")
	}
	r.Root = strings.TrimSpace(root)

	branch, _ := r.executor.Run(r.Root, "rev-parse", "--abbrev-ref", "HEAD")
	r.CurrentBranch = strings.TrimSpace(branch)

	sha, _ := r.executor.Run(r.Root, "rev-parse", "HEAD")
	r.CommitSHA = strings.TrimSpace(sha)

	remote, _ := r.executor.Run(r.Root, "remote", "get-url", "origin")
	r.RemoteURL = strings.TrimSpace(remote)

	r.BaseBranch = r.detectBaseBranch()

	return r, nil
}

// Detect returns a Repository for the current working directory.
func Detect() (*Repository, error) {
	return NewRepository(nil)
}

// detectBaseBranch tries to determine the default base branch.
func (r *Repository) detectBaseBranch() string {
	out, err := r.executor.Run(r.Root, "symbolic-ref", "refs/remotes/origin/HEAD")
	if err == nil {
		ref := strings.TrimSpace(out)
		if strings.HasPrefix(ref, "refs/remotes/origin/") {
			return strings.TrimPrefix(ref, "refs/remotes/origin/")
		}
		return ref
	}

	_, err = r.executor.Run(r.Root, "rev-parse", "--verify", "origin/main")
	if err == nil {
		return "main"
	}

	_, err = r.executor.Run(r.Root, "rev-parse", "--verify", "origin/master")
	if err == nil {
		return "master"
	}

	return ""
}

// DetectChangedFiles populates ChangedFiles by diffing against the base branch.
func (r *Repository) DetectChangedFiles() error {
	var out string
	var err error

	if r.BaseBranch != "" {
		out, err = r.executor.Run(r.Root, "diff", "--name-only", r.BaseBranch+"...HEAD")
	}

	if r.BaseBranch == "" || err != nil {
		out, err = r.executor.Run(r.Root, "diff", "--name-only", "HEAD")
	}

	if err != nil {
		return fmt.Errorf("failed to detect changed files: %w", err)
	}

	files := strings.Split(strings.TrimSpace(out), "\n")
	var result []string
	for _, f := range files {
		if f != "" {
			result = append(result, f)
		}
	}
	r.ChangedFiles = result
	return nil
}

// DetectDiffStats populates AddedLines and DeletedLines by diffing against the base branch.
func (r *Repository) DetectDiffStats() error {
	var out string
	var err error

	if r.BaseBranch != "" {
		out, err = r.executor.Run(r.Root, "diff", "--stat", r.BaseBranch+"...HEAD")
	}

	if r.BaseBranch == "" || err != nil {
		out, err = r.executor.Run(r.Root, "diff", "--stat", "HEAD")
	}

	if err != nil {
		return fmt.Errorf("failed to detect diff stats: %w", err)
	}

	added, deleted := parseDiffStat(out)
	r.AddedLines = added
	r.DeletedLines = deleted
	return nil
}

var insertionRe = regexp.MustCompile(`(\d+)\s+insertion`)
var deletionRe = regexp.MustCompile(`(\d+)\s+deletion`)

func parseDiffStat(stat string) (int, int) {
	totalAdded := 0
	totalDeleted := 0

	for _, line := range strings.Split(stat, "\n") {
		if m := insertionRe.FindStringSubmatch(line); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil {
				totalAdded += n
			}
		}
		if m := deletionRe.FindStringSubmatch(line); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil {
				totalDeleted += n
			}
		}
	}

	return totalAdded, totalDeleted
}

// MockExecutor is a test double for git commands.
type MockExecutor struct {
	Responses map[string]string
	Errors    map[string]error
	Calls     []string
}

// Run returns a pre-configured response or error for the given arguments.
func (m *MockExecutor) Run(dir string, args ...string) (string, error) {
	key := strings.Join(args, " ")
	m.Calls = append(m.Calls, key)
	if err, ok := m.Errors[key]; ok {
		return "", err
	}
	if resp, ok := m.Responses[key]; ok {
		return resp, nil
	}
	return "", fmt.Errorf("unexpected mock command: %s", key)
}
