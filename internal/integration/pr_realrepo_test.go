// Real-repo integration tests for PR Intelligence (Phase 4).
//
// These tests clone real open-source repositories, make changes on a branch,
// and verify that the PR summary, inline annotations, and reviewer suggestion
// features work end-to-end.
package integration

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// cloneRepoForPR clones a repo and creates a test branch with a change.
func cloneRepoForPR(t *testing.T, url, name string) string {
	t.Helper()
	dir := cloneRepo(t, url, name)

	// Create a test branch
	cmd := exec.Command("git", "checkout", "-b", "test-pr-intelligence")
	cmd.Dir = dir
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		t.Skipf("failed to create branch: %v", err)
	}

	// Add a vulnerable line to a file
	testFile := filepath.Join(dir, "test-vulnerable.js")
	if err := os.WriteFile(testFile, []byte("const evil = eval('user-input');\n"), 0644); err != nil {
		t.Skipf("failed to write test file: %v", err)
	}

	// Git add and commit
	cmd = exec.Command("git", "add", "test-vulnerable.js")
	cmd.Dir = dir
	_ = cmd.Run()

	cmd = exec.Command("git", "commit", "-m", "add vulnerable code for testing")
	cmd.Dir = dir
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		t.Skipf("failed to commit: %v", err)
	}

	return dir
}

// addCodeowners creates a CODEOWNERS file in the repo.
func addCodeowners(t *testing.T, repoDir string) {
	t.Helper()
	githubDir := filepath.Join(repoDir, ".github")
	if err := os.MkdirAll(githubDir, 0755); err != nil {
		t.Fatal(err)
	}
	content := `* @global-owner
*.js @js-team
/test-vulnerable.js @security-team
`
	if err := os.WriteFile(filepath.Join(githubDir, "CODEOWNERS"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("git", "add", ".github/CODEOWNERS")
	cmd.Dir = repoDir
	_ = cmd.Run()

	cmd = exec.Command("git", "commit", "-m", "add codeowners")
	cmd.Dir = repoDir
	_ = cmd.Run()
}

// runPRReview runs patchflow pr-review with given flags and returns output.
func runPRReview(t *testing.T, repoDir string, args ...string) string {
	t.Helper()
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "patchflow")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = "/Users/digitalcenter/patchflow-cli"
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("failed to build patchflow: %v\n%s", err, out)
	}

	allArgs := []string{"pr-review"}
	allArgs = append(allArgs, args...)
	cmd := exec.Command(binPath, allArgs...)
	cmd.Dir = repoDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("pr-review output: %s", string(out))
	}
	return string(out)
}

func TestRealPRSummaryOnNodeGoat(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepoForPR(t, "https://github.com/OWASP/NodeGoat.git", "NodeGoat")

	output := runPRReview(t, repoDir, "--format", "pr-summary")

	// Verify PR summary content
	if !strings.Contains(output, "PatchFlow PR Review") {
		t.Error("expected 'PatchFlow PR Review' header")
	}
	if !strings.Contains(output, "Risk:") {
		t.Error("expected 'Risk:' line")
	}
	if !strings.Contains(output, "Status:") {
		t.Error("expected 'Status:' line")
	}
	if !strings.Contains(output, "Changes") {
		t.Error("expected 'Changes' section")
	}
	if !strings.Contains(output, "Findings by Severity") {
		t.Error("expected 'Findings by Severity' section")
	}
	// Should detect the eval() finding as NEW
	if !strings.Contains(output, "[NEW]") {
		t.Log("warning: expected [NEW] marker for eval() finding")
	}
	// Should mention eval
	if !strings.Contains(output, "eval") {
		t.Log("warning: expected 'eval' in output")
	}
}

func TestRealPRSummaryToFileOnNodeGoat(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepoForPR(t, "https://github.com/OWASP/NodeGoat.git", "NodeGoat")

	outputFile := filepath.Join(repoDir, "pr-summary.md")
	runPRReview(t, repoDir, "--format", "pr-summary", "--output", outputFile)

	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	content := string(data)

	if !strings.Contains(content, "PatchFlow PR Review") {
		t.Error("file should contain PR review header")
	}
	if !strings.Contains(content, "Risk:") {
		t.Error("file should contain risk score")
	}
}

func TestRealAnnotationsOnNodeGoat(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepoForPR(t, "https://github.com/OWASP/NodeGoat.git", "NodeGoat")

	outputFile := filepath.Join(repoDir, "annotations.json")
	output := runPRReview(t, repoDir, "--format", "annotations", "--output", outputFile)

	if !strings.Contains(output, "annotations written") {
		t.Logf("output: %s", output)
	}

	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("failed to read annotations file: %v", err)
	}

	var annotations []map[string]interface{}
	if err := json.Unmarshal(data, &annotations); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if len(annotations) == 0 {
		t.Error("expected at least 1 annotation")
	}

	// Verify annotation structure
	for _, ann := range annotations {
		if _, ok := ann["path"].(string); !ok {
			t.Error("annotation should have 'path'")
		}
		if _, ok := ann["line"].(float64); !ok {
			t.Error("annotation should have 'line'")
		}
		if _, ok := ann["severity"].(string); !ok {
			t.Error("annotation should have 'severity'")
		}
		if _, ok := ann["title"].(string); !ok {
			t.Error("annotation should have 'title'")
		}
	}
}

func TestRealReviewerSuggestionsOnNodeGoat(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepoForPR(t, "https://github.com/OWASP/NodeGoat.git", "NodeGoat")
	addCodeowners(t, repoDir)

	output := runPRReview(t, repoDir, "--suggest-reviewers")

	if !strings.Contains(output, "Suggested Reviewers") {
		t.Error("expected 'Suggested Reviewers' section")
	}

	// Should find CODEOWNERS
	if !strings.Contains(output, "CODEOWNER") {
		t.Error("expected CODEOWNER in output")
	}

	// Should find at least one of the codeowners
	if !strings.Contains(output, "global-owner") && !strings.Contains(output, "js-team") && !strings.Contains(output, "security-team") {
		t.Error("expected at least one CODEOWNER reviewer")
	}
}

func TestRealReviewerSuggestionsWithBlame(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepoForPR(t, "https://github.com/OWASP/NodeGoat.git", "NodeGoat")

	// Don't add CODEOWNERS — should still get reviewers from git blame
	output := runPRReview(t, repoDir, "--suggest-reviewers")

	if !strings.Contains(output, "Suggested Reviewers") {
		t.Error("expected 'Suggested Reviewers' section")
	}

	// Should mention no CODEOWNERS found
	if !strings.Contains(output, "CODEOWNERS") {
		t.Log("warning: expected mention of CODEOWNERS")
	}
}

func TestRealPRReviewTerminalOutput(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepoForPR(t, "https://github.com/OWASP/NodeGoat.git", "NodeGoat")

	output := runPRReview(t, repoDir)

	// Verify terminal output format
	if !strings.Contains(output, "PatchFlow PR Risk Review") {
		t.Error("expected 'PatchFlow PR Risk Review' header")
	}
	if !strings.Contains(output, "Risk Score:") {
		t.Error("expected 'Risk Score:' line")
	}
	if !strings.Contains(output, "Status:") {
		t.Error("expected 'Status:' line")
	}
}

func TestRealPRReviewWithAnnotationsFlag(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepoForPR(t, "https://github.com/OWASP/NodeGoat.git", "NodeGoat")

	output := runPRReview(t, repoDir, "--annotations")

	// Should show inline annotations section
	if !strings.Contains(output, "Inline Annotations") {
		t.Error("expected 'Inline Annotations' section")
	}
}

func TestRealPRSummaryOnDvna(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepoForPR(t, "https://github.com/appsecco/dvna.git", "dvna")

	output := runPRReview(t, repoDir, "--format", "pr-summary")

	if !strings.Contains(output, "PatchFlow PR Review") {
		t.Error("expected 'PatchFlow PR Review' header")
	}
	if !strings.Contains(output, "Risk:") {
		t.Error("expected 'Risk:' line")
	}
}

func TestRealPRSummaryOnDjangoDefectDojo(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepoForPR(t, "https://github.com/DefectDojo/django-DefectDojo.git", "django-DefectDojo")

	output := runPRReview(t, repoDir, "--format", "pr-summary")

	if !strings.Contains(output, "PatchFlow PR Review") {
		t.Error("expected 'PatchFlow PR Review' header")
	}
	if !strings.Contains(output, "Risk:") {
		t.Error("expected 'Risk:' line")
	}
}
