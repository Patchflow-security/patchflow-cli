package templates

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Template represents a CI/CD integration template that can be written into a
// user's repository.
type Template struct {
	Name     string // human-readable name
	Platform string // platform identifier
	FilePath string // relative path within the repo
	Content  string // file content
}

// Append indicates whether the template should be appended to an existing file
// (true) or written as a standalone file (false).
type Append bool

const (
	githubActionsTemplate = `name: PatchFlow Security Scan

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]
  schedule:
    # Run weekly on Monday at 09:00 UTC
    - cron: '0 9 * * 1'

permissions:
  contents: read
  security-events: write

jobs:
  patchflow-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.25'

      - name: Install PatchFlow
        run: go install github.com/patchflow/patchflow-cli/cmd/patchflow@latest

      - name: Run PatchFlow scan
        run: patchflow scan run --profile ci --format sarif --output patchflow.sarif
        continue-on-error: true

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always() && hashFiles('patchflow.sarif') != ''
        with:
          sarif_file: patchflow.sarif
          category: patchflow

      - name: Upload scan results artifact
        uses: actions/upload-artifact@v4
        if: always() && hashFiles('patchflow.sarif') != ''
        with:
          name: patchflow-sarif
          path: patchflow.sarif
`

	gitlabCITemplate = `patchflow:scan:
  stage: test
  image: golang:1.24
  before_script:
    - go install github.com/patchflow/patchflow-cli@latest
  script:
    - patchflow scan run --profile ci --format json --output patchflow-report.json
    - patchflow scan run --profile ci --format sarif --output patchflow.sarif
  artifacts:
    reports:
      dotenv: patchflow-report.json
    paths:
      - patchflow.sarif
    expire_in: 1 week
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      changes: [".patchflow/baselines/*"]
      when: never
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
`

	preCommitTemplate = `repos:
  - repo: https://github.com/patchflow/patchflow-cli
    rev: v0.1.0
    hooks:
      - id: patchflow
        name: PatchFlow Security Scan
        entry: patchflow scan run --profile dev --no-reachability
        language: system
        pass_filenames: false
        stages: [commit]
`

	jenkinsTemplate = `stage('PatchFlow Security Scan') {
  agent any
  steps {
    sh 'go install github.com/patchflow/patchflow-cli@latest'
    sh 'patchflow scan run --profile ci --format json --output patchflow-report.json'
    sh 'patchflow scan run --profile ci --format sarif --output patchflow.sarif'
    archiveArtifacts artifacts: 'patchflow-report.json, patchflow.sarif', allowEmptyArchive: true
  }
}
`

	azureDevOpsTemplate = `- task: Bash@3
  displayName: 'PatchFlow Security Scan'
  inputs:
    targetType: 'inline'
    script: |
      go install github.com/patchflow/patchflow-cli@latest
      patchflow scan run --profile ci --format json --output patchflow-report.json
      patchflow scan run --profile ci --format sarif --output patchflow.sarif
- task: PublishBuildArtifacts@1
  inputs:
    pathToPublish: 'patchflow-report.json'
    artifactName: 'PatchFlowReport'
`
)

// templates is the registry of all available CI/CD templates.
var templates = map[string]Template{
	"github-actions": {
		Name:     "GitHub Actions",
		Platform: "github-actions",
		FilePath: ".github/workflows/patchflow-scan.yml",
		Content:  githubActionsTemplate,
	},
	"gitlab-ci": {
		Name:     "GitLab CI",
		Platform: "gitlab-ci",
		FilePath: ".gitlab-ci.yml",
		Content:  gitlabCITemplate,
	},
	"pre-commit": {
		Name:     "pre-commit hook",
		Platform: "pre-commit",
		FilePath: ".pre-commit-config.yaml",
		Content:  preCommitTemplate,
	},
	"jenkins": {
		Name:     "Jenkins",
		Platform: "jenkins",
		FilePath: "Jenkinsfile.patchflow",
		Content:  jenkinsTemplate,
	},
	"azure-devops": {
		Name:     "Azure DevOps",
		Platform: "azure-devops",
		FilePath: "azure-pipelines-patchflow.yml",
		Content:  azureDevOpsTemplate,
	},
}

// appendPlatforms lists platforms whose template should be appended to an
// existing file rather than overwriting it.
var appendPlatforms = map[string]bool{
	"gitlab-ci":  true,
	"pre-commit": true,
}

// GetTemplate returns the template for the given platform.
func GetTemplate(platform string) (*Template, error) {
	t, ok := templates[platform]
	if !ok {
		return nil, fmt.Errorf("unknown platform %q; available: %s", platform, strings.Join(ListTemplates(), ", "))
	}
	return &t, nil
}

// ListTemplates returns the names of all available platforms.
func ListTemplates() []string {
	out := make([]string, 0, len(templates))
	for name := range templates {
		out = append(out, name)
	}
	return out
}

// WriteTemplate writes the template for the given platform into rootDir. If the
// target file already exists and the platform is configured for appending, the
// template content is appended instead of overwriting.
func WriteTemplate(platform, rootDir string) error {
	t, err := GetTemplate(platform)
	if err != nil {
		return err
	}

	fullPath := filepath.Join(rootDir, t.FilePath)

	if appendPlatforms[platform] {
		return writeOrAppend(fullPath, t.Content)
	}
	return writeOverwrite(fullPath, t.Content)
}

// writeOverwrite writes content to path, creating parent directories as needed
// and overwriting any existing file.
func writeOverwrite(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("failed to create directories for %s: %w", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	return nil
}

// writeOrAppend appends content to path if it exists, otherwise creates it.
func writeOrAppend(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("failed to create directories for %s: %w", path, err)
	}
	if _, err := os.Stat(path); err == nil {
		existing, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("failed to read existing %s: %w", path, readErr)
		}
		merged := string(existing)
		if !strings.HasSuffix(merged, "\n") {
			merged += "\n"
		}
		merged += content
		if err := os.WriteFile(path, []byte(merged), 0o644); err != nil {
			return fmt.Errorf("failed to append to %s: %w", path, err)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to stat %s: %w", path, err)
	}
	return writeOverwrite(path, content)
}
