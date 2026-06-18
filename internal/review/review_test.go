package review

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/patchflow/patchflow-cli/internal/git"
)

func TestCollectContextPopulatesFields(t *testing.T) {
	repo := &git.Repository{
		Root:          "/tmp/repo",
		RemoteURL:     "https://github.com/user/repo.git",
		CurrentBranch: "feature-branch",
		CommitSHA:     "abc123def456",
		BaseBranch:    "main",
		ChangedFiles:  []string{"file1.go", "file2.go"},
		AddedLines:    42,
		DeletedLines:  10,
	}

	ctx, err := CollectContext(repo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.RepoRoot != "/tmp/repo" {
		t.Fatalf("expected RepoRoot %q, got %q", "/tmp/repo", ctx.RepoRoot)
	}
	if ctx.RemoteURL != "https://github.com/user/repo.git" {
		t.Fatalf("expected RemoteURL %q, got %q", "https://github.com/user/repo.git", ctx.RemoteURL)
	}
	if ctx.Branch != "feature-branch" {
		t.Fatalf("expected Branch %q, got %q", "feature-branch", ctx.Branch)
	}
	if ctx.CommitSHA != "abc123def456" {
		t.Fatalf("expected CommitSHA %q, got %q", "abc123def456", ctx.CommitSHA)
	}
	if ctx.BaseBranch != "main" {
		t.Fatalf("expected BaseBranch %q, got %q", "main", ctx.BaseBranch)
	}
	if ctx.FilesChanged != 2 {
		t.Fatalf("expected FilesChanged 2, got %d", ctx.FilesChanged)
	}
	if ctx.AddedLines != 42 {
		t.Fatalf("expected AddedLines 42, got %d", ctx.AddedLines)
	}
	if ctx.DeletedLines != 10 {
		t.Fatalf("expected DeletedLines 10, got %d", ctx.DeletedLines)
	}
	if ctx.DependencyFilesChanged {
		t.Fatal("expected DependencyFilesChanged to be false")
	}
	if ctx.CIWorkflowChanged {
		t.Fatal("expected CIWorkflowChanged to be false")
	}
	if ctx.AuthFilesChanged {
		t.Fatal("expected AuthFilesChanged to be false")
	}
}

func TestCollectContextDependencyFilesChanged(t *testing.T) {
	repo := &git.Repository{
		Root:         "/tmp/repo",
		ChangedFiles: []string{"package.json", "main.go"},
	}

	ctx, err := CollectContext(repo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ctx.DependencyFilesChanged {
		t.Fatal("expected DependencyFilesChanged to be true")
	}
	if ctx.CIWorkflowChanged {
		t.Fatal("expected CIWorkflowChanged to be false")
	}
	if ctx.AuthFilesChanged {
		t.Fatal("expected AuthFilesChanged to be false")
	}
}

func TestCollectContextCIWorkflowChanged(t *testing.T) {
	repo := &git.Repository{
		Root:         "/tmp/repo",
		ChangedFiles: []string{".github/workflows/ci.yml", "main.go"},
	}

	ctx, err := CollectContext(repo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.DependencyFilesChanged {
		t.Fatal("expected DependencyFilesChanged to be false")
	}
	if !ctx.CIWorkflowChanged {
		t.Fatal("expected CIWorkflowChanged to be true")
	}
	if ctx.AuthFilesChanged {
		t.Fatal("expected AuthFilesChanged to be false")
	}
}

func TestCollectContextAuthFilesChanged(t *testing.T) {
	repo := &git.Repository{
		Root:         "/tmp/repo",
		ChangedFiles: []string{"internal/auth/auth.go", "main.go"},
	}

	ctx, err := CollectContext(repo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.DependencyFilesChanged {
		t.Fatal("expected DependencyFilesChanged to be false")
	}
	if ctx.CIWorkflowChanged {
		t.Fatal("expected CIWorkflowChanged to be false")
	}
	if !ctx.AuthFilesChanged {
		t.Fatal("expected AuthFilesChanged to be true")
	}
}

func TestCollectContextMultipleFlags(t *testing.T) {
	repo := &git.Repository{
		Root:         "/tmp/repo",
		ChangedFiles: []string{"package.json", ".github/workflows/ci.yml", "internal/auth/login.go"},
	}

	ctx, err := CollectContext(repo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ctx.DependencyFilesChanged {
		t.Fatal("expected DependencyFilesChanged to be true")
	}
	if !ctx.CIWorkflowChanged {
		t.Fatal("expected CIWorkflowChanged to be true")
	}
	if !ctx.AuthFilesChanged {
		t.Fatal("expected AuthFilesChanged to be true")
	}
}

func TestCollectContextNoFilesChanged(t *testing.T) {
	repo := &git.Repository{
		Root:         "/tmp/repo",
		ChangedFiles: []string{},
	}

	ctx, err := CollectContext(repo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.FilesChanged != 0 {
		t.Fatalf("expected FilesChanged 0, got %d", ctx.FilesChanged)
	}
	if ctx.DependencyFilesChanged {
		t.Fatal("expected DependencyFilesChanged to be false")
	}
}

func TestDetectManifestsFindsManifests(t *testing.T) {
	tmpDir := t.TempDir()

	// Root level manifests
	_ = os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte("{}"), 0644)
	_ = os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte("module test"), 0644)
	_ = os.WriteFile(filepath.Join(tmpDir, "README.md"), []byte("hello"), 0644)

	// Depth 1 manifest
	_ = os.MkdirAll(filepath.Join(tmpDir, "backend"), 0755)
	_ = os.WriteFile(filepath.Join(tmpDir, "backend", "requirements.txt"), []byte("flask"), 0644)

	// Depth 2 manifest (should be skipped)
	_ = os.MkdirAll(filepath.Join(tmpDir, "backend", "nested"), 0755)
	_ = os.WriteFile(filepath.Join(tmpDir, "backend", "nested", "package.json"), []byte("{}"), 0644)

	manifests := DetectManifests(tmpDir)
	if len(manifests) != 3 {
		t.Fatalf("expected 3 manifests, got %d: %+v", len(manifests), manifests)
	}

	// DetectManifests returns unique relative paths
	expected := map[string]bool{
		"package.json":             false,
		"go.mod":                   false,
		"backend/requirements.txt": false,
	}
	for _, m := range manifests {
		expected[m] = true
	}
	for name, found := range expected {
		if !found {
			t.Fatalf("expected manifest %q not found", name)
		}
	}
}

func TestDetectManifestsEmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	manifests := DetectManifests(tmpDir)
	if len(manifests) != 0 {
		t.Fatalf("expected 0 manifests, got %d", len(manifests))
	}
}

func TestDetectManifestsOnlyNonManifests(t *testing.T) {
	tmpDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(tmpDir, "README.md"), []byte("hello"), 0644)
	_ = os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0644)

	manifests := DetectManifests(tmpDir)
	if len(manifests) != 0 {
		t.Fatalf("expected 0 manifests, got %d", len(manifests))
	}
}
