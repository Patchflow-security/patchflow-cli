package templates

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestGetTemplate_AllPlatforms(t *testing.T) {
	for _, platform := range ListTemplates() {
		t.Run(platform, func(t *testing.T) {
			tpl, err := GetTemplate(platform)
			if err != nil {
				t.Fatalf("GetTemplate(%q) returned error: %v", platform, err)
			}
			if tpl.Platform != platform {
				t.Errorf("Platform = %q, want %q", tpl.Platform, platform)
			}
			if tpl.FilePath == "" {
				t.Error("FilePath is empty")
			}
			if tpl.Content == "" {
				t.Error("Content is empty")
			}
			if tpl.Name == "" {
				t.Error("Name is empty")
			}
		})
	}
}

func TestGetTemplate_InvalidPlatform(t *testing.T) {
	_, err := GetTemplate("no-such-platform")
	if err == nil {
		t.Fatal("expected error for invalid platform, got nil")
	}
}

func TestListTemplates(t *testing.T) {
	got := ListTemplates()
	expected := []string{"github-actions", "gitlab-ci", "pre-commit", "jenkins", "azure-devops"}
	sort.Strings(got)
	sort.Strings(expected)
	if len(got) != len(expected) {
		t.Fatalf("ListTemplates returned %d platforms, want %d", len(got), len(expected))
	}
	for i := range expected {
		if got[i] != expected[i] {
			t.Errorf("ListTemplates[%d] = %q, want %q", i, got[i], expected[i])
		}
	}
}

func TestWriteTemplate_GitHubActions(t *testing.T) {
	dir := t.TempDir()
	if err := WriteTemplate("github-actions", dir); err != nil {
		t.Fatalf("WriteTemplate error: %v", err)
	}
	path := filepath.Join(dir, ".github", "workflows", "patchflow-scan.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read written file: %v", err)
	}
	if !strings.Contains(string(data), "patchflow scan run --profile ci --format sarif") {
		t.Error("GitHub Actions template missing expected scan command")
	}
	if !strings.Contains(string(data), "upload-sarif") {
		t.Error("GitHub Actions template missing SARIF upload step")
	}
}

func TestWriteTemplate_GitLabCI_NewFile(t *testing.T) {
	dir := t.TempDir()
	if err := WriteTemplate("gitlab-ci", dir); err != nil {
		t.Fatalf("WriteTemplate error: %v", err)
	}
	path := filepath.Join(dir, ".gitlab-ci.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read written file: %v", err)
	}
	if !strings.Contains(string(data), "patchflow:scan:") {
		t.Error("GitLab CI template missing patchflow:scan job")
	}
}

func TestWriteTemplate_GitLabCI_AppendsExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".gitlab-ci.yml")
	existing := "stages:\n  - build\n  - test\n"
	if err := os.WriteFile(path, []byte(existing), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := WriteTemplate("gitlab-ci", dir); err != nil {
		t.Fatalf("WriteTemplate error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	content := string(data)
	if !strings.HasPrefix(content, "stages:") {
		t.Error("existing content was not preserved")
	}
	if !strings.Contains(content, "patchflow:scan:") {
		t.Error("appended template missing patchflow:scan job")
	}
}

func TestWriteTemplate_PreCommit_NewFile(t *testing.T) {
	dir := t.TempDir()
	if err := WriteTemplate("pre-commit", dir); err != nil {
		t.Fatalf("WriteTemplate error: %v", err)
	}
	path := filepath.Join(dir, ".pre-commit-config.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	if !strings.Contains(string(data), "patchflow scan run --profile dev") {
		t.Error("pre-commit template missing dev profile scan command")
	}
}

func TestWriteTemplate_PreCommit_AppendsExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".pre-commit-config.yaml")
	existing := "repos:\n  - repo: https://example.com/some-hook\n    rev: v1.0.0\n    hooks:\n      - id: some-hook\n"
	if err := os.WriteFile(path, []byte(existing), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := WriteTemplate("pre-commit", dir); err != nil {
		t.Fatalf("WriteTemplate error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "some-hook") {
		t.Error("existing content was not preserved")
	}
	if !strings.Contains(content, "patchflow") {
		t.Error("appended template missing patchflow hook")
	}
}

func TestWriteTemplate_Jenkins(t *testing.T) {
	dir := t.TempDir()
	if err := WriteTemplate("jenkins", dir); err != nil {
		t.Fatalf("WriteTemplate error: %v", err)
	}
	path := filepath.Join(dir, "Jenkinsfile.patchflow")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	if !strings.Contains(string(data), "PatchFlow Security Scan") {
		t.Error("Jenkins template missing stage name")
	}
}

func TestWriteTemplate_AzureDevOps(t *testing.T) {
	dir := t.TempDir()
	if err := WriteTemplate("azure-devops", dir); err != nil {
		t.Fatalf("WriteTemplate error: %v", err)
	}
	path := filepath.Join(dir, "azure-pipelines-patchflow.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	if !strings.Contains(string(data), "PublishBuildArtifacts") {
		t.Error("Azure DevOps template missing publish task")
	}
}

func TestWriteTemplate_InvalidPlatform(t *testing.T) {
	dir := t.TempDir()
	if err := WriteTemplate("no-such-platform", dir); err == nil {
		t.Fatal("expected error for invalid platform, got nil")
	}
}

func TestWriteTemplate_OverwritesGitHubActions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".github", "workflows", "patchflow-scan.yml")
	if err := WriteTemplate("github-actions", dir); err != nil {
		t.Fatalf("first write error: %v", err)
	}
	// Corrupt the file to verify overwrite behavior.
	if err := os.WriteFile(path, []byte("OLD CONTENT"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := WriteTemplate("github-actions", dir); err != nil {
		t.Fatalf("second write error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	if strings.Contains(string(data), "OLD CONTENT") {
		t.Error("github-actions template should overwrite, not append")
	}
}
