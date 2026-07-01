package fix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
)

// helper: write a temp file and return its path
func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestNewEngine(t *testing.T) {
	engine := NewEngine()
	if engine == nil {
		t.Fatal("NewEngine returned nil")
	}
	if len(engine.templates) == 0 {
		t.Fatal("engine has no templates loaded")
	}
}

func TestBuiltinTemplates(t *testing.T) {
	templates := builtinTemplates()
	if len(templates) < 15 {
		t.Errorf("expected at least 15 templates, got %d", len(templates))
	}

	// Verify all templates have required fields
	ruleIDs := map[string]bool{}
	for i, tmpl := range templates {
		if tmpl.RuleID == "" {
			t.Errorf("template %d has empty RuleID", i)
		}
		if ruleIDs[tmpl.RuleID] {
			t.Errorf("duplicate RuleID: %s", tmpl.RuleID)
		}
		ruleIDs[tmpl.RuleID] = true
		if tmpl.Generate == nil {
			t.Errorf("template %s has nil Generate function", tmpl.RuleID)
		}
		if len(tmpl.Languages) == 0 {
			t.Errorf("template %s has no languages", tmpl.RuleID)
		}
	}

	// Verify expected rule IDs are present
	expectedRules := []string{"JS001", "PY001", "PY003", "PY006", "PY009", "GO022", "GO026"}
	for _, ruleID := range expectedRules {
		if !ruleIDs[ruleID] {
			t.Errorf("missing template for rule %s", ruleID)
		}
	}
}

func TestSuggestSCAFix_WithFixedVersion(t *testing.T) {
	finding := analysis.Finding{
		ID:             "sca-001",
		RuleID:         "SCA-OSV",
		Type:           analysis.TypeSCA,
		PackageName:    "lodash",
		PackageVersion: "4.17.20",
		FixedVersion:   "4.17.21",
		CVEID:          "CVE-2021-23337",
		Severity:       analysis.SeverityHigh,
		FilePath:       "package.json",
		AdvisoryURL:    "https://osv.dev/vulnerability/GHSA-35jh-h3jh-qjm8",
	}

	proposal := suggestSCAFix(finding)
	if proposal == nil {
		t.Fatal("expected proposal, got nil")
	}

	if proposal.PackageName != "lodash" {
		t.Errorf("expected package 'lodash', got '%s'", proposal.PackageName)
	}
	if proposal.PackageVersion != "4.17.20" {
		t.Errorf("expected version '4.17.20', got '%s'", proposal.PackageVersion)
	}
	if proposal.FixedVersion != "4.17.21" {
		t.Errorf("expected fixed version '4.17.21', got '%s'", proposal.FixedVersion)
	}
	if proposal.Strategy != StrategyUpgrade {
		t.Errorf("expected strategy 'upgrade', got '%s'", proposal.Strategy)
	}
	if proposal.Confidence != FixConfidenceHigh {
		t.Errorf("expected confidence 'high', got '%s'", proposal.Confidence)
	}
	if !proposal.AutoApplicable {
		t.Error("expected AutoApplicable=true for fix with known fixed version")
	}
}

func TestSuggestSCAFix_NoFixedVersion(t *testing.T) {
	finding := analysis.Finding{
		ID:             "sca-002",
		RuleID:         "SCA-OSV",
		Type:           analysis.TypeSCA,
		PackageName:    "vulnerable-pkg",
		PackageVersion: "1.0.0",
		FixedVersion:   "",
		CVEID:          "CVE-2024-12345",
		Severity:       analysis.SeverityCritical,
		FilePath:       "package.json",
	}

	proposal := suggestSCAFix(finding)
	if proposal == nil {
		t.Fatal("expected proposal, got nil")
	}

	if proposal.FixedVersion != "" {
		t.Errorf("expected empty fixed version, got '%s'", proposal.FixedVersion)
	}
	if proposal.Confidence != FixConfidenceLow {
		t.Errorf("expected confidence 'low', got '%s'", proposal.Confidence)
	}
	if proposal.AutoApplicable {
		t.Error("expected AutoApplicable=false when no fixed version")
	}
}

func TestSuggest_SCAFindings(t *testing.T) {
	engine := NewEngine()
	findings := []analysis.Finding{
		{
			ID:             "sca-001",
			RuleID:         "SCA-OSV",
			Type:           analysis.TypeSCA,
			PackageName:    "lodash",
			PackageVersion: "4.17.20",
			FixedVersion:   "4.17.21",
			Severity:       analysis.SeverityHigh,
		},
		{
			ID:             "sca-002",
			RuleID:         "SCA-OSV",
			Type:           analysis.TypeSCA,
			PackageName:    "express",
			PackageVersion: "4.17.0",
			FixedVersion:   "4.18.0",
			Severity:       analysis.SeverityMedium,
		},
	}

	proposals := engine.Suggest(findings)
	if len(proposals) != 2 {
		t.Fatalf("expected 2 proposals, got %d", len(proposals))
	}

	// Higher severity should come first
	if proposals[0].Severity != "high" {
		t.Errorf("expected first proposal to be high severity, got %s", proposals[0].Severity)
	}
}

func TestFixEval_Python(t *testing.T) {
	source := "import os\ndata = eval(user_input)\nprint(data)\n"
	path := writeTempFile(t, "test.py", source)

	finding := analysis.Finding{
		ID:        "sast-001",
		RuleID:    "PY001",
		Type:      analysis.TypeSAST,
		Title:     "Use of eval()",
		Severity:  analysis.SeverityHigh,
		FilePath:  path,
		LineStart: 2,
	}

	proposal, err := fixEval(finding, source)
	if err != nil {
		t.Fatalf("fixEval failed: %v", err)
	}
	if proposal == nil {
		t.Fatal("expected proposal, got nil")
	}

	if !strings.Contains(proposal.FixedCode, "ast.literal_eval") {
		t.Errorf("expected fixed code to contain 'ast.literal_eval', got: %s", proposal.FixedCode)
	}
	if proposal.Patch == "" {
		t.Error("expected non-empty patch")
	}
	if proposal.AutoApplicable {
		t.Error("eval fix should not be auto-applicable")
	}
}

func TestFixEval_JavaScript(t *testing.T) {
	source := "const data = eval(input);\nconsole.log(data);\n"
	path := writeTempFile(t, "test.js", source)

	finding := analysis.Finding{
		ID:        "sast-001",
		RuleID:    "JS001",
		Type:      analysis.TypeSAST,
		Title:     "Use of eval()",
		Severity:  analysis.SeverityHigh,
		FilePath:  path,
		LineStart: 1,
	}

	proposal, err := fixEval(finding, source)
	if err != nil {
		t.Fatalf("fixEval failed: %v", err)
	}
	if proposal == nil {
		t.Fatal("expected proposal, got nil")
	}

	if !strings.Contains(proposal.FixedCode, "JSON.parse") {
		t.Errorf("expected fixed code to contain 'JSON.parse', got: %s", proposal.FixedCode)
	}
}

func TestFixYamlLoad(t *testing.T) {
	source := "import yaml\ndata = yaml.load(content)\nprint(data)\n"
	path := writeTempFile(t, "test.py", source)

	finding := analysis.Finding{
		ID:        "sast-001",
		RuleID:    "PY006",
		Type:      analysis.TypeSAST,
		Title:     "yaml.load() without SafeLoader",
		Severity:  analysis.SeverityHigh,
		FilePath:  path,
		LineStart: 2,
	}

	proposal, err := fixYamlLoad(finding, source)
	if err != nil {
		t.Fatalf("fixYamlLoad failed: %v", err)
	}
	if proposal == nil {
		t.Fatal("expected proposal, got nil")
	}

	if !strings.Contains(proposal.FixedCode, "yaml.safe_load") {
		t.Errorf("expected 'yaml.safe_load', got: %s", proposal.FixedCode)
	}
	if !proposal.AutoApplicable {
		t.Error("yaml.safe_load fix should be auto-applicable")
	}
}

func TestFixMD5_Python(t *testing.T) {
	source := "import hashlib\nh = hashlib.md5(data)\nprint(h.hexdigest())\n"
	path := writeTempFile(t, "test.py", source)

	finding := analysis.Finding{
		ID:        "sast-001",
		RuleID:    "PY009",
		Type:      analysis.TypeSAST,
		Title:     "MD5 hash usage",
		Severity:  analysis.SeverityMedium,
		FilePath:  path,
		LineStart: 2,
	}

	proposal, err := fixMD5(finding, source)
	if err != nil {
		t.Fatalf("fixMD5 failed: %v", err)
	}
	if proposal == nil {
		t.Fatal("expected proposal, got nil")
	}

	if !strings.Contains(proposal.FixedCode, "hashlib.sha256") {
		t.Errorf("expected 'hashlib.sha256', got: %s", proposal.FixedCode)
	}
	if !proposal.AutoApplicable {
		t.Error("MD5→SHA256 fix should be auto-applicable")
	}
}

func TestFixMD5_Go(t *testing.T) {
	source := `package main
import (
	"crypto/md5"
	"fmt"
)
func main() {
	h := md5.Sum([]byte("test"))
	fmt.Printf("%x\n", h)
}
`
	path := writeTempFile(t, "main.go", source)

	finding := analysis.Finding{
		ID:        "sast-001",
		RuleID:    "GO026",
		Type:      analysis.TypeSAST,
		Title:     "MD5 hash usage",
		Severity:  analysis.SeverityMedium,
		FilePath:  path,
		LineStart: 3,
	}

	proposal, err := fixGoMD5(finding, source)
	if err != nil {
		t.Fatalf("fixGoMD5 failed: %v", err)
	}
	if proposal == nil {
		t.Fatal("expected proposal, got nil")
	}

	if !strings.Contains(proposal.FixedCode, "crypto/sha256") {
		t.Errorf("expected 'crypto/sha256', got: %s", proposal.FixedCode)
	}
}

func TestFixSHA1_Go(t *testing.T) {
	source := `package main
import (
	"crypto/sha1"
	"fmt"
)
func main() {
	h := sha1.Sum([]byte("test"))
	fmt.Printf("%x\n", h)
}
`
	path := writeTempFile(t, "main.go", source)

	finding := analysis.Finding{
		ID:        "sast-001",
		RuleID:    "GO027",
		Type:      analysis.TypeSAST,
		Title:     "SHA1 hash usage",
		Severity:  analysis.SeverityMedium,
		FilePath:  path,
		LineStart: 3,
	}

	proposal, err := fixGoSHA1(finding, source)
	if err != nil {
		t.Fatalf("fixGoSHA1 failed: %v", err)
	}
	if proposal == nil {
		t.Fatal("expected proposal, got nil")
	}

	if !strings.Contains(proposal.FixedCode, "crypto/sha256") {
		t.Errorf("expected 'crypto/sha256', got: %s", proposal.FixedCode)
	}
}

func TestFixInsecureSkipVerify(t *testing.T) {
	source := `package main
import (
	"crypto/tls"
	"net/http"
)
func main() {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	_ = client
}
`
	path := writeTempFile(t, "main.go", source)

	finding := analysis.Finding{
		ID:        "sast-001",
		RuleID:    "GO022",
		Type:      analysis.TypeSAST,
		Title:     "InsecureSkipVerify enabled",
		Severity:  analysis.SeverityHigh,
		FilePath:  path,
		LineStart: 9,
	}

	proposal, err := fixInsecureSkipVerify(finding, source)
	if err != nil {
		t.Fatalf("fixInsecureSkipVerify failed: %v", err)
	}
	if proposal == nil {
		t.Fatal("expected proposal, got nil")
	}

	if !strings.Contains(proposal.FixedCode, "InsecureSkipVerify: false") {
		t.Errorf("expected 'InsecureSkipVerify: false', got: %s", proposal.FixedCode)
	}
	if !proposal.AutoApplicable {
		t.Error("InsecureSkipVerify fix should be auto-applicable")
	}
}

func TestFixSubprocessShellTrue(t *testing.T) {
	source := "import subprocess\nsubprocess.run(cmd, shell=True)\n"
	path := writeTempFile(t, "test.py", source)

	finding := analysis.Finding{
		ID:        "sast-001",
		RuleID:    "PY004",
		Type:      analysis.TypeSAST,
		Title:     "subprocess with shell=True",
		Severity:  analysis.SeverityHigh,
		FilePath:  path,
		LineStart: 2,
	}

	proposal, err := fixSubprocessShellTrue(finding, source)
	if err != nil {
		t.Fatalf("fixSubprocessShellTrue failed: %v", err)
	}
	if proposal == nil {
		t.Fatal("expected proposal, got nil")
	}

	if !strings.Contains(proposal.FixedCode, "shell=False") {
		t.Errorf("expected 'shell=False', got: %s", proposal.FixedCode)
	}
}

func TestFixOsSystem(t *testing.T) {
	source := "import os\nos.system('ls -la')\n"
	path := writeTempFile(t, "test.py", source)

	finding := analysis.Finding{
		ID:        "sast-001",
		RuleID:    "PY003",
		Type:      analysis.TypeSAST,
		Title:     "os.system() usage",
		Severity:  analysis.SeverityHigh,
		FilePath:  path,
		LineStart: 2,
	}

	proposal, err := fixOsSystem(finding, source)
	if err != nil {
		t.Fatalf("fixOsSystem failed: %v", err)
	}
	if proposal == nil {
		t.Fatal("expected proposal, got nil")
	}

	if !strings.Contains(proposal.FixedCode, "subprocess.run") {
		t.Errorf("expected 'subprocess.run', got: %s", proposal.FixedCode)
	}
	if !strings.Contains(proposal.FixedCode, "shell=False") {
		t.Errorf("expected 'shell=False', got: %s", proposal.FixedCode)
	}
}

func TestFixRequestsVerifyFalse(t *testing.T) {
	source := "import requests\nr = requests.get(url, verify=False)\n"
	path := writeTempFile(t, "test.py", source)

	finding := analysis.Finding{
		ID:        "sast-001",
		RuleID:    "PY014",
		Type:      analysis.TypeSAST,
		Title:     "requests with verify=False",
		Severity:  analysis.SeverityHigh,
		FilePath:  path,
		LineStart: 2,
	}

	proposal, err := fixRequestsVerifyFalse(finding, source)
	if err != nil {
		t.Fatalf("fixRequestsVerifyFalse failed: %v", err)
	}
	if proposal == nil {
		t.Fatal("expected proposal, got nil")
	}

	if !strings.Contains(proposal.FixedCode, "verify=True") {
		t.Errorf("expected 'verify=True', got: %s", proposal.FixedCode)
	}
	if !proposal.AutoApplicable {
		t.Error("verify=False fix should be auto-applicable")
	}
}

func TestFixDebugTrue(t *testing.T) {
	source := "app.config.DEBUG = True\n"
	path := writeTempFile(t, "test.py", source)

	finding := analysis.Finding{
		ID:        "sast-001",
		RuleID:    "PY015",
		Type:      analysis.TypeSAST,
		Title:     "Debug mode enabled",
		Severity:  analysis.SeverityMedium,
		FilePath:  path,
		LineStart: 1,
	}

	proposal, err := fixDebugTrue(finding, source)
	if err != nil {
		t.Fatalf("fixDebugTrue failed: %v", err)
	}
	if proposal == nil {
		t.Fatal("expected proposal, got nil")
	}

	if !strings.Contains(proposal.FixedCode, "debug=False") {
		t.Errorf("expected 'debug=False', got: %s", proposal.FixedCode)
	}
}

func TestFixChildProcessExec(t *testing.T) {
	source := `const child_process = require('child_process');
child_process.exec('ls -la', (err, stdout, stderr) => {
  console.log(stdout);
});
`
	path := writeTempFile(t, "test.js", source)

	finding := analysis.Finding{
		ID:        "sast-001",
		RuleID:    "JS003",
		Type:      analysis.TypeSAST,
		Title:     "child_process.exec() usage",
		Severity:  analysis.SeverityHigh,
		FilePath:  path,
		LineStart: 2,
	}

	proposal, err := fixChildProcessExec(finding, source)
	if err != nil {
		t.Fatalf("fixChildProcessExec failed: %v", err)
	}
	if proposal == nil {
		t.Fatal("expected proposal, got nil")
	}

	if !strings.Contains(proposal.FixedCode, "execFile") {
		t.Errorf("expected 'execFile', got: %s", proposal.FixedCode)
	}
}

func TestFixInnerHTML(t *testing.T) {
	source := "element.innerHTML = userInput;\n"
	path := writeTempFile(t, "test.js", source)

	finding := analysis.Finding{
		ID:        "sast-001",
		RuleID:    "JS006",
		Type:      analysis.TypeSAST,
		Title:     "innerHTML assignment",
		Severity:  analysis.SeverityMedium,
		FilePath:  path,
		LineStart: 1,
	}

	proposal, err := fixInnerHTML(finding, source)
	if err != nil {
		t.Fatalf("fixInnerHTML failed: %v", err)
	}
	if proposal == nil {
		t.Fatal("expected proposal, got nil")
	}

	if !strings.Contains(proposal.FixedCode, "textContent") {
		t.Errorf("expected 'textContent', got: %s", proposal.FixedCode)
	}
}

func TestSuggestForFinding_SAST(t *testing.T) {
	source := "import yaml\ndata = yaml.load(content)\n"
	path := writeTempFile(t, "test.py", source)

	finding := analysis.Finding{
		ID:        "sast-001",
		RuleID:    "PY006",
		Type:      analysis.TypeSAST,
		Title:     "yaml.load() without SafeLoader",
		Severity:  analysis.SeverityHigh,
		FilePath:  path,
		LineStart: 2,
	}

	engine := NewEngine()
	proposal, err := engine.SuggestForFinding(finding)
	if err != nil {
		t.Fatalf("SuggestForFinding failed: %v", err)
	}
	if proposal == nil {
		t.Fatal("expected proposal, got nil")
	}

	if !strings.Contains(proposal.FixedCode, "yaml.safe_load") {
		t.Errorf("expected 'yaml.safe_load', got: %s", proposal.FixedCode)
	}
}

func TestSuggestForFinding_SCA(t *testing.T) {
	finding := analysis.Finding{
		ID:             "sca-001",
		RuleID:         "SCA-OSV",
		Type:           analysis.TypeSCA,
		PackageName:    "lodash",
		PackageVersion: "4.17.20",
		FixedVersion:   "4.17.21",
		Severity:       analysis.SeverityHigh,
	}

	engine := NewEngine()
	proposal, err := engine.SuggestForFinding(finding)
	if err != nil {
		t.Fatalf("SuggestForFinding failed: %v", err)
	}
	if proposal == nil {
		t.Fatal("expected proposal, got nil")
	}

	if proposal.PackageName != "lodash" {
		t.Errorf("expected package 'lodash', got '%s'", proposal.PackageName)
	}
}

func TestSuggestForFinding_NoMatchingTemplate(t *testing.T) {
	source := "x = 1\n"
	path := writeTempFile(t, "test.py", source)

	finding := analysis.Finding{
		ID:        "sast-001",
		RuleID:    "UNKNOWN_RULE_999",
		Type:      analysis.TypeSAST,
		Title:     "Unknown issue",
		Severity:  analysis.SeverityLow,
		FilePath:  path,
		LineStart: 1,
	}

	engine := NewEngine()
	_, err := engine.SuggestForFinding(finding)
	if err == nil {
		t.Error("expected error for unknown rule, got nil")
	}
}

func TestApply_DryRun(t *testing.T) {
	source := "import yaml\ndata = yaml.load(content)\n"
	path := writeTempFile(t, "test.py", source)

	finding := analysis.Finding{
		ID:        "sast-001",
		RuleID:    "PY006",
		Type:      analysis.TypeSAST,
		Title:     "yaml.load()",
		Severity:  analysis.SeverityHigh,
		FilePath:  path,
		LineStart: 2,
	}

	engine := NewEngine()
	proposal, err := engine.SuggestForFinding(finding)
	if err != nil {
		t.Fatalf("SuggestForFinding failed: %v", err)
	}

	// Dry run — should not modify the file
	result, err := Apply(*proposal, ApplyOptions{DryRun: true})
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Applied {
		t.Error("dry run should not apply")
	}

	// Verify file was not modified
	content, _ := os.ReadFile(path)
	if !strings.Contains(string(content), "yaml.load") {
		t.Error("file was modified during dry run")
	}
}

func TestApply_RealApply(t *testing.T) {
	source := "import yaml\ndata = yaml.load(content)\n"
	path := writeTempFile(t, "test.py", source)

	finding := analysis.Finding{
		ID:        "sast-001",
		RuleID:    "PY006",
		Type:      analysis.TypeSAST,
		Title:     "yaml.load()",
		Severity:  analysis.SeverityHigh,
		FilePath:  path,
		LineStart: 2,
	}

	engine := NewEngine()
	proposal, err := engine.SuggestForFinding(finding)
	if err != nil {
		t.Fatalf("SuggestForFinding failed: %v", err)
	}

	// Real apply
	result, err := Apply(*proposal, ApplyOptions{DryRun: false, NoConfirm: true})
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if !result.Applied {
		t.Error("expected Applied=true")
	}

	// Verify file was modified
	content, _ := os.ReadFile(path)
	if !strings.Contains(string(content), "yaml.safe_load") {
		t.Error("file was not modified after apply")
	}
	if strings.Contains(string(content), "yaml.load(") {
		t.Error("original yaml.load still present after apply")
	}
}

func TestApply_WithBackup(t *testing.T) {
	source := "import yaml\ndata = yaml.load(content)\n"
	path := writeTempFile(t, "test.py", source)

	finding := analysis.Finding{
		ID:        "sast-001",
		RuleID:    "PY006",
		Type:      analysis.TypeSAST,
		Title:     "yaml.load()",
		Severity:  analysis.SeverityHigh,
		FilePath:  path,
		LineStart: 2,
	}

	engine := NewEngine()
	proposal, err := engine.SuggestForFinding(finding)
	if err != nil {
		t.Fatalf("SuggestForFinding failed: %v", err)
	}

	result, err := Apply(*proposal, ApplyOptions{Backup: true, NoConfirm: true})
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if result.BackupPath == "" {
		t.Error("expected backup path to be set")
	}

	// Verify backup contains original content
	backupContent, err := os.ReadFile(result.BackupPath)
	if err != nil {
		t.Fatalf("failed to read backup: %v", err)
	}
	if !strings.Contains(string(backupContent), "yaml.load") {
		t.Error("backup should contain original content")
	}
}

func TestApply_SCAUpgrade_SkipsCodeModification(t *testing.T) {
	proposal := FixProposal{
		ID:           "fix-sca-001",
		FindingID:    "sca-001",
		RuleID:       "SCA-OSV",
		Title:        "Upgrade lodash",
		Strategy:     StrategyUpgrade,
		PackageName:  "lodash",
		FilePath:     "package.json",
		FixedCode:    "",
	}

	result, err := Apply(proposal, ApplyOptions{NoConfirm: true})
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Applied {
		t.Error("SCA upgrade should not be applied as code fix")
	}
}

func TestApplyAll(t *testing.T) {
	source1 := "import yaml\ndata = yaml.load(content)\n"
	path1 := writeTempFile(t, "test1.py", source1)

	source2 := "import hashlib\nh = hashlib.md5(data)\n"
	path2 := writeTempFile(t, "test2.py", source2)

	engine := NewEngine()
	findings := []analysis.Finding{
		{
			ID:        "sast-001",
			RuleID:    "PY006",
			Type:      analysis.TypeSAST,
			Title:     "yaml.load()",
			Severity:  analysis.SeverityHigh,
			FilePath:  path1,
			LineStart: 2,
		},
		{
			ID:        "sast-002",
			RuleID:    "PY009",
			Type:      analysis.TypeSAST,
			Title:     "MD5 usage",
			Severity:  analysis.SeverityMedium,
			FilePath:  path2,
			LineStart: 2,
		},
	}

	proposals := engine.Suggest(findings)
	if len(proposals) != 2 {
		t.Fatalf("expected 2 proposals, got %d", len(proposals))
	}

	result := ApplyAll(proposals, ApplyOptions{NoConfirm: true})
	if result.TotalProposals != 2 {
		t.Errorf("expected 2 total, got %d", result.TotalProposals)
	}
	if result.Applied != 2 {
		t.Errorf("expected 2 applied, got %d", result.Applied)
	}
}

func TestRenderProposalMarkdown(t *testing.T) {
	proposal := FixProposal{
		ID:           "fix-001",
		FindingID:    "sast-001",
		RuleID:       "PY006",
		Title:        "Replace yaml.load() with yaml.safe_load()",
		Description:  "yaml.load() can execute arbitrary code",
		Severity:     "high",
		FilePath:     "test.py",
		LineStart:    2,
		OriginalCode: "data = yaml.load(content)",
		FixedCode:    "data = yaml.safe_load(content)",
		Confidence:   FixConfidenceHigh,
		Strategy:     StrategyReplace,
		Rationale:    "safe_load doesn't allow custom objects",
		References:   []string{"https://pyyaml.org"},
	}

	md := RenderProposalMarkdown(proposal)
	if !strings.Contains(md, "yaml.safe_load") {
		t.Error("markdown should contain fixed code")
	}
	if !strings.Contains(md, "test.py") {
		t.Error("markdown should contain file path")
	}
	if !strings.Contains(md, "high") {
		t.Error("markdown should contain severity")
	}
}

func TestRenderSummary(t *testing.T) {
	proposals := []FixProposal{
		{ID: "fix-1", Title: "Fix 1", Severity: "high", Confidence: FixConfidenceHigh, AutoApplicable: true, Strategy: StrategyReplace},
		{ID: "fix-2", Title: "Fix 2", Severity: "medium", Confidence: FixConfidenceMedium, AutoApplicable: false, Strategy: StrategyReplace},
	}

	summary := RenderSummary(proposals)
	if !strings.Contains(summary, "2") {
		t.Error("summary should contain count")
	}
	if !strings.Contains(summary, "Fix 1") {
		t.Error("summary should contain proposal title")
	}
}

func TestRenderSummary_Empty(t *testing.T) {
	summary := RenderSummary(nil)
	if !strings.Contains(summary, "No fix proposals") {
		t.Error("empty summary should indicate no proposals")
	}
}

func TestRenderApplyResult(t *testing.T) {
	result := &ApplyResult{
		TotalProposals: 3,
		Applied:        2,
		Skipped:        1,
		Failed:         0,
		DryRun:         false,
		Results: []FixResult{
			{ProposalID: "fix-1", Applied: true, FilePath: "test1.py"},
			{ProposalID: "fix-2", Applied: true, FilePath: "test2.py"},
			{ProposalID: "fix-3", Applied: false, FilePath: "test3.py"},
		},
	}

	md := RenderApplyResult(result)
	if !strings.Contains(md, "3") {
		t.Error("should contain total count")
	}
	if !strings.Contains(md, "2") {
		t.Error("should contain applied count")
	}
}

func TestExtractLine(t *testing.T) {
	source := "line1\nline2\nline3\n"
	if got := extractLine(source, 2); got != "line2" {
		t.Errorf("expected 'line2', got '%s'", got)
	}
}

func TestExtractLine_OutOfRange(t *testing.T) {
	source := "line1\n"
	if got := extractLine(source, 10); got != "" {
		t.Errorf("expected empty string, got '%s'", got)
	}
}

func TestReplaceLine(t *testing.T) {
	source := "line1\nline2\nline3\n"
	result := replaceLine(source, 2, "replaced")
	if !strings.Contains(result, "replaced") {
		t.Error("expected replaced line")
	}
	if strings.Contains(result, "line2") {
		t.Error("original line2 should be gone")
	}
}

func TestDetectLanguage(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"test.py", "python"},
		{"test.js", "javascript"},
		{"test.ts", "typescript"},
		{"test.go", "go"},
		{"test.unknown", ""},
	}

	for _, tt := range tests {
		got := detectLanguage(tt.path)
		if got != tt.expected {
			t.Errorf("detectLanguage(%s) = %s, want %s", tt.path, got, tt.expected)
		}
	}
}

func TestGenerateUnifiedDiff(t *testing.T) {
	original := "line1\nline2\nline3\n"
	fixed := "line1\nreplaced\nline3\n"
	diff := generateUnifiedDiff("test.py", original, fixed)

	if !strings.Contains(diff, "test.py") {
		t.Error("diff should contain file path")
	}
	if !strings.Contains(diff, "-line2") {
		t.Error("diff should show removed line")
	}
	if !strings.Contains(diff, "+replaced") {
		t.Error("diff should show added line")
	}
}

func TestSuggestGenericFix_Eval(t *testing.T) {
	source := "data = eval(user_input)\n"
	path := writeTempFile(t, "test.py", source)

	finding := analysis.Finding{
		ID:        "sast-001",
		RuleID:    "CUSTOM_EVAL_RULE",
		Type:      analysis.TypeSAST,
		Title:     "Use of eval()",
		Severity:  analysis.SeverityHigh,
		FilePath:  path,
		LineStart: 1,
	}

	engine := NewEngine()
	proposal, err := engine.suggestGenericFix(finding, source)
	if err != nil {
		t.Fatalf("suggestGenericFix failed: %v", err)
	}
	if proposal == nil {
		t.Fatal("expected proposal, got nil")
	}
}

func TestSuggestGenericFix_NoMatch(t *testing.T) {
	source := "x = 1\n"
	path := writeTempFile(t, "test.py", source)

	finding := analysis.Finding{
		ID:        "sast-001",
		RuleID:    "UNKNOWN_RULE",
		Type:      analysis.TypeSAST,
		Title:     "Some unknown issue",
		Severity:  analysis.SeverityLow,
		FilePath:  path,
		LineStart: 1,
	}

	engine := NewEngine()
	_, err := engine.suggestGenericFix(finding, source)
	if err == nil {
		t.Error("expected error for unmatched rule")
	}
}

func TestFixNewFunction(t *testing.T) {
	source := "const fn = new Function('return 1+1');\n"
	path := writeTempFile(t, "test.js", source)

	finding := analysis.Finding{
		ID:        "sast-001",
		RuleID:    "JS002",
		Type:      analysis.TypeSAST,
		Title:     "new Function() usage",
		Severity:  analysis.SeverityHigh,
		FilePath:  path,
		LineStart: 1,
	}

	proposal, err := fixNewFunction(finding, source)
	if err != nil {
		t.Fatalf("fixNewFunction failed: %v", err)
	}
	if !strings.Contains(proposal.FixedCode, "JSON.parse") {
		t.Errorf("expected 'JSON.parse', got: %s", proposal.FixedCode)
	}
}

func TestFixChildProcessExecSync(t *testing.T) {
	source := `const child_process = require('child_process');
const result = child_process.execSync('ls -la');
`
	path := writeTempFile(t, "test.js", source)

	finding := analysis.Finding{
		ID:        "sast-001",
		RuleID:    "JS004",
		Type:      analysis.TypeSAST,
		Title:     "execSync usage",
		Severity:  analysis.SeverityHigh,
		FilePath:  path,
		LineStart: 2,
	}

	proposal, err := fixChildProcessExecSync(finding, source)
	if err != nil {
		t.Fatalf("fixChildProcessExecSync failed: %v", err)
	}
	if !strings.Contains(proposal.FixedCode, "execFileSync") {
		t.Errorf("expected 'execFileSync', got: %s", proposal.FixedCode)
	}
}

func TestFixPythonExec(t *testing.T) {
	source := "exec('x = 1')\n"
	path := writeTempFile(t, "test.py", source)

	finding := analysis.Finding{
		ID:        "sast-001",
		RuleID:    "PY002",
		Type:      analysis.TypeSAST,
		Title:     "exec() usage",
		Severity:  analysis.SeverityHigh,
		FilePath:  path,
		LineStart: 1,
	}

	proposal, err := fixPythonExec(finding, source)
	if err != nil {
		t.Fatalf("fixPythonExec failed: %v", err)
	}
	if proposal == nil {
		t.Fatal("expected proposal, got nil")
	}
	if proposal.Strategy != StrategyRemove {
		t.Errorf("expected strategy 'remove', got '%s'", proposal.Strategy)
	}
}

func TestFixSHA1_Python(t *testing.T) {
	source := "import hashlib\nh = hashlib.sha1(data)\n"
	path := writeTempFile(t, "test.py", source)

	finding := analysis.Finding{
		ID:        "sast-001",
		RuleID:    "PY010",
		Type:      analysis.TypeSAST,
		Title:     "SHA1 usage",
		Severity:  analysis.SeverityMedium,
		FilePath:  path,
		LineStart: 2,
	}

	proposal, err := fixSHA1(finding, source)
	if err != nil {
		t.Fatalf("fixSHA1 failed: %v", err)
	}
	if !strings.Contains(proposal.FixedCode, "hashlib.sha256") {
		t.Errorf("expected 'hashlib.sha256', got: %s", proposal.FixedCode)
	}
}

func TestFixFlaskDebug(t *testing.T) {
	source := "from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)\n"
	path := writeTempFile(t, "app.py", source)

	finding := analysis.Finding{
		ID:        "sast-001",
		RuleID:    "PY016",
		Type:      analysis.TypeSAST,
		Title:     "Flask debug=True",
		Severity:  analysis.SeverityHigh,
		FilePath:  path,
		LineStart: 3,
	}

	proposal, err := fixFlaskDebug(finding, source)
	if err != nil {
		t.Fatalf("fixFlaskDebug failed: %v", err)
	}
	if !strings.Contains(proposal.FixedCode, "debug=False") {
		t.Errorf("expected 'debug=False', got: %s", proposal.FixedCode)
	}
}

func TestFixGoExecShell(t *testing.T) {
	source := `package main
import (
	"os/exec"
)
func main() {
	cmd := exec.Command("sh", "-c", "ls -la")
	cmd.Run()
}
`
	path := writeTempFile(t, "main.go", source)

	finding := analysis.Finding{
		ID:        "sast-001",
		RuleID:    "GO025",
		Type:      analysis.TypeSAST,
		Title:     "exec.Command with sh -c",
		Severity:  analysis.SeverityHigh,
		FilePath:  path,
		LineStart: 6,
	}

	proposal, err := fixGoExecShell(finding, source)
	if err != nil {
		t.Fatalf("fixGoExecShell failed: %v", err)
	}
	if !strings.Contains(proposal.FixedCode, "arg0") {
		t.Errorf("expected placeholder for arg0, got: %s", proposal.FixedCode)
	}
}

func TestFixSSLVerifyFalse(t *testing.T) {
	source := "import ssl\nctx = ssl.create_default_context()\nctx.verify = False\n"
	path := writeTempFile(t, "test.py", source)

	finding := analysis.Finding{
		ID:        "sast-001",
		RuleID:    "PY013",
		Type:      analysis.TypeSAST,
		Title:     "SSL verification disabled",
		Severity:  analysis.SeverityHigh,
		FilePath:  path,
		LineStart: 3,
	}

	proposal, err := fixSSLVerifyFalse(finding, source)
	if err != nil {
		t.Fatalf("fixSSLVerifyFalse failed: %v", err)
	}
	if !strings.Contains(proposal.FixedCode, "verify=True") {
		t.Errorf("expected 'verify=True', got: %s", proposal.FixedCode)
	}
}

func TestFixJSSQLInjection(t *testing.T) {
	source := "const query = `SELECT * FROM users WHERE id = ${userId}`;\n"
	path := writeTempFile(t, "test.js", source)

	finding := analysis.Finding{
		ID:        "sast-001",
		RuleID:    "JS005",
		Type:      analysis.TypeSAST,
		Title:     "SQL injection via template literal",
		Severity:  analysis.SeverityHigh,
		FilePath:  path,
		LineStart: 1,
	}

	proposal, err := fixJSSQLInjection(finding, source)
	if err != nil {
		t.Fatalf("fixJSSQLInjection failed: %v", err)
	}
	if proposal == nil {
		t.Fatal("expected proposal, got nil")
	}
	if !strings.Contains(proposal.FixedCode, "?") {
		t.Errorf("expected ? placeholder, got: %s", proposal.FixedCode)
	}
}

func TestFixHardcodedSecret(t *testing.T) {
	source := "api_key = 'sk-1234567890abcdef'\n"
	path := writeTempFile(t, "test.py", source)

	finding := analysis.Finding{
		ID:        "sast-001",
		RuleID:    "PY-SECRET-001",
		Type:      analysis.TypeSecret,
		Title:     "Hardcoded API key",
		Severity:  analysis.SeverityHigh,
		FilePath:  path,
		LineStart: 1,
	}

	proposal, err := fixHardcodedSecret(finding, source)
	if err != nil {
		t.Fatalf("fixHardcodedSecret failed: %v", err)
	}
	if !strings.Contains(proposal.FixedCode, "os.environ") {
		t.Errorf("expected env var lookup, got: %s", proposal.FixedCode)
	}
}

func TestSuggest_EmptyFindings(t *testing.T) {
	engine := NewEngine()
	proposals := engine.Suggest(nil)
	if len(proposals) != 0 {
		t.Errorf("expected 0 proposals for empty findings, got %d", len(proposals))
	}
}

func TestSuggest_MixedFindings(t *testing.T) {
	source := "import yaml\ndata = yaml.load(content)\n"
	path := writeTempFile(t, "test.py", source)

	engine := NewEngine()
	findings := []analysis.Finding{
		{
			ID:             "sca-001",
			RuleID:         "SCA-OSV",
			Type:           analysis.TypeSCA,
			PackageName:    "lodash",
			PackageVersion: "4.17.20",
			FixedVersion:   "4.17.21",
			Severity:       analysis.SeverityHigh,
		},
		{
			ID:        "sast-001",
			RuleID:    "PY006",
			Type:      analysis.TypeSAST,
			Title:     "yaml.load()",
			Severity:  analysis.SeverityHigh,
			FilePath:  path,
			LineStart: 2,
		},
	}

	proposals := engine.Suggest(findings)
	if len(proposals) != 2 {
		t.Fatalf("expected 2 proposals, got %d", len(proposals))
	}
}

func TestApply_NonExistentFile(t *testing.T) {
	proposal := FixProposal{
		ID:         "fix-001",
		FindingID:  "sast-001",
		RuleID:     "PY006",
		Strategy:   StrategyReplace,
		FilePath:   "/nonexistent/path/test.py",
		FixedCode:  "data = yaml.safe_load(content)",
	}

	result, err := Apply(proposal, ApplyOptions{NoConfirm: true})
	if err != nil {
		t.Fatalf("Apply should not return error for file read failure: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Applied {
		t.Error("should not apply to non-existent file")
	}
	if result.Error == "" {
		t.Error("should have error message")
	}
}

func TestApply_EmptyFilePath(t *testing.T) {
	proposal := FixProposal{
		ID:        "fix-001",
		Strategy:  StrategyReplace,
		FilePath:  "",
		FixedCode: "test",
	}

	_, err := Apply(proposal, ApplyOptions{NoConfirm: true})
	if err == nil {
		t.Error("expected error for empty file path")
	}
}

func TestApply_EmptyFixedCode(t *testing.T) {
	proposal := FixProposal{
		ID:        "fix-001",
		Strategy:  StrategyReplace,
		FilePath:  "test.py",
		FixedCode: "",
	}

	_, err := Apply(proposal, ApplyOptions{NoConfirm: true})
	if err == nil {
		t.Error("expected error for empty fixed code")
	}
}
