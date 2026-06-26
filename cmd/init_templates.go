package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/patchflow/patchflow-cli/internal/output"
	"github.com/patchflow/patchflow-cli/internal/templates"
	"github.com/spf13/cobra"
)

var initGitHubActionsCmd = &cobra.Command{
	Use:   "github-actions",
	Short: "Generate a GitHub Actions workflow for PatchFlow scans",
	Long: `Create .github/workflows/patchflow-scan.yml in the current repository.
The workflow runs patchflow scan run --profile ci --format sarif and uploads
SARIF results to GitHub Code Scanning.`,
	RunE: runInitTemplate("github-actions"),
}

var initGitLabCICmd = &cobra.Command{
	Use:   "gitlab-ci",
	Short: "Generate a GitLab CI job for PatchFlow scans",
	Long: `Create or append a patchflow:scan job to .gitlab-ci.yml in the current
repository. The job runs patchflow scan run --profile ci and publishes JSON and
SARIF reports as artifacts.`,
	RunE: runInitTemplate("gitlab-ci"),
}

var initPreCommitCmd = &cobra.Command{
	Use:   "pre-commit",
	Short: "Generate a pre-commit hook for PatchFlow scans",
	Long: `Create or append a patchflow hook to .pre-commit-config.yaml in the
current repository. The hook runs patchflow scan run --profile dev on commit.`,
	RunE: runInitTemplate("pre-commit"),
}

var initJenkinsCmd = &cobra.Command{
	Use:   "jenkins",
	Short: "Generate a Jenkins pipeline stage for PatchFlow scans",
	Long: `Create Jenkinsfile.patchflow in the current repository containing a
PatchFlow Security Scan stage. Existing Jenkinsfiles are not modified.`,
	RunE: runInitTemplate("jenkins"),
}

var initAzureDevOpsCmd = &cobra.Command{
	Use:   "azure-devops",
	Short: "Generate an Azure DevOps pipeline snippet for PatchFlow scans",
	Long: `Create azure-pipelines-patchflow.yml in the current repository with a
PatchFlow Security Scan task and artifact publishing.`,
	RunE: runInitTemplate("azure-devops"),
}

func init() {
	initCmd.AddCommand(initGitHubActionsCmd)
	initCmd.AddCommand(initGitLabCICmd)
	initCmd.AddCommand(initPreCommitCmd)
	initCmd.AddCommand(initJenkinsCmd)
	initCmd.AddCommand(initAzureDevOpsCmd)
}

// runInitTemplate returns a RunE function for an `patchflow init <platform>`
// subcommand. It resolves the repo root, writes the template, and prints next
// steps.
func runInitTemplate(platform string) func(cmd *cobra.Command, _ []string) error {
	return func(cmd *cobra.Command, _ []string) error {
		formatter := FormatterFromContext(cmd.Context())

		root, err := getRepoRoot()
		if err != nil {
			return formatter.PrintError(fmt.Errorf("not inside a git repository: %w", err))
		}

		t, err := templates.GetTemplate(platform)
		if err != nil {
			return formatter.PrintError(err)
		}

		fullPath := filepath.Join(root, t.FilePath)
		existed := fileExists(fullPath)

		if err := templates.WriteTemplate(platform, root); err != nil {
			return formatter.PrintError(fmt.Errorf("failed to write template: %w", err))
		}

		if output.IsJSON(formatter) {
			return formatter.Print(map[string]any{
				"platform":  platform,
				"file":      t.FilePath,
				"created":   !existed,
				"appended":  existed,
				"nextSteps": nextSteps(platform),
			})
		}

		action := "Created"
		if existed {
			action = "Updated"
		}
		_ = formatter.PrintSuccess(fmt.Sprintf("%s %s", action, t.FilePath))
		_ = formatter.Print("")
		_ = formatter.Print("Next steps:")
		for _, step := range nextSteps(platform) {
			_ = formatter.Print("  " + step)
		}
		_ = formatter.Print("")
		_ = formatter.Print("Available platforms: " + strings.Join(templates.ListTemplates(), ", "))
		return nil
	}
}

// nextSteps returns platform-specific guidance printed after template creation.
func nextSteps(platform string) []string {
	switch platform {
	case "github-actions":
		return []string{
			"Commit the workflow and push to trigger on the next PR/push.",
			"SARIF results appear under Settings > Code security > Code scanning alerts.",
		}
	case "gitlab-ci":
		return []string{
			"Commit .gitlab-ci.yml and open a merge request to trigger the scan.",
			"Review patchflow-report.json and patchflow.sarif in the pipeline artifacts.",
		}
	case "pre-commit":
		return []string{
			"Run: pre-commit install",
			"Ensure patchflow is on your PATH (go install github.com/patchflow/patchflow-cli/cmd/patchflow@latest).",
		}
	case "jenkins":
		return []string{
			"Reference Jenkinsfile.patchflow from your main Jenkinsfile or use it directly.",
			"Ensure Go is available on the Jenkins agent.",
		}
	case "azure-devops":
		return []string{
			"Add azure-pipelines-patchflow.yml to your pipeline (e.g. as a template include).",
			"Ensure the agent has Go installed.",
		}
	default:
		return []string{"Review the generated file and commit it to your repository."}
	}
}

// fileExists reports whether path exists.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
