// Real-repo integration tests for the SBOM/VEX/license pipeline.
//
// These tests clone real open-source repositories (shallow clones), run the
// full PatchFlow SBOM/VEX/license/dep-graph pipeline against them, and
// verify that the output is valid and contains expected data.
//
// Tests are skipped in -short mode to avoid network access in CI.
package integration

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestRealReposEnabled controls whether real-repo tests run.
// These tests require network access to clone repos from GitHub.
func skipIfShort(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping real-repo test in -short mode")
	}
	// Check if git is available
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
}

// cloneRepo clones a repo (shallow) into a temp directory and returns the path.
func cloneRepo(t *testing.T, url, name string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("git", "clone", "--depth", "1", url, dir)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		t.Skipf("failed to clone %s: %v (network issue?)", name, err)
	}
	return dir
}

// runPatchflowExport runs patchflow scan export with the given format on a repo.
// It builds the patchflow binary first, then runs it.
func runPatchflowExport(t *testing.T, repoDir, format string, extraArgs ...string) []byte {
	t.Helper()
	// Build patchflow binary
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "patchflow")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = "/Users/digitalcenter/patchflow-cli"
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("failed to build patchflow: %v\n%s", err, out)
	}

	// Run scan export
	outputFile := filepath.Join(binDir, "output")
	args := []string{"scan", "export", "--format", format, "--output", outputFile}
	args = append(args, extraArgs...)
	cmd := exec.Command(binPath, args...)
	cmd.Dir = repoDir
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		t.Fatalf("patchflow scan export --format %s failed: %v", format, err)
	}

	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("failed to read output: %v", err)
	}
	return data
}

// runPatchflowDepsLicenses runs patchflow deps licenses on a repo.
func runPatchflowDepsLicenses(t *testing.T, repoDir string) string {
	t.Helper()
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "patchflow")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = "/Users/digitalcenter/patchflow-cli"
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("failed to build patchflow: %v\n%s", err, out)
	}

	cmd := exec.Command(binPath, "deps", "licenses")
	cmd.Dir = repoDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("patchflow deps licenses failed: %v\n%s", err, out)
	}
	return string(out)
}

// --- NodeGoat (OWASP Node.js vulnerable app) ---

func TestRealNodeGoatCycloneDX(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepo(t, "https://github.com/OWASP/NodeGoat.git", "NodeGoat")

	data := runPatchflowExport(t, repoDir, "cyclonedx-json", "--include-vex")

	var bom map[string]interface{}
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Verify BOM format
	if bom["bomFormat"] != "CycloneDX" {
		t.Errorf("expected bomFormat=CycloneDX, got %v", bom["bomFormat"])
	}
	if bom["specVersion"] != "1.5" {
		t.Errorf("expected specVersion=1.5, got %v", bom["specVersion"])
	}

	// Verify root component
	meta, ok := bom["metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("expected metadata object")
	}
	component, ok := meta["component"].(map[string]interface{})
	if !ok {
		t.Fatal("expected metadata.component")
	}
	rootName, _ := component["name"].(string)
	if !strings.Contains(strings.ToLower(rootName), "goat") {
		t.Errorf("expected root name to contain 'goat', got %s", rootName)
	}

	// Verify root has a license (NodeGoat uses Apache 2.0)
	licenses, ok := component["licenses"].([]interface{})
	if ok && len(licenses) > 0 {
		firstLic, ok := licenses[0].(map[string]interface{})
		if ok {
			licObj, ok := firstLic["license"].(map[string]interface{})
			if ok {
				licName := ""
				if id, ok := licObj["id"].(string); ok {
					licName = id
				}
				if licName == "" {
					if name, ok := licObj["name"].(string); ok {
						licName = name
					}
				}
				if licName != "" && !strings.Contains(strings.ToLower(licName), "apache") {
					t.Logf("root license: %s (expected Apache)", licName)
				}
			}
		}
	}

	// Verify components exist (NodeGoat has ~30+ npm deps)
	components, ok := bom["components"].([]interface{})
	if !ok {
		t.Fatal("expected components array")
	}
	if len(components) < 20 {
		t.Errorf("expected at least 20 components, got %d", len(components))
	}

	// Verify vulnerabilities with VEX (NodeGoat has known vulns)
	vulns, ok := bom["vulnerabilities"].([]interface{})
	if !ok {
		t.Fatal("expected vulnerabilities array")
	}
	if len(vulns) < 5 {
		t.Errorf("expected at least 5 vulnerabilities, got %d", len(vulns))
	}

	// Verify VEX states are populated
	for _, v := range vulns {
		vuln, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		analysis, ok := vuln["analysis"].(map[string]interface{})
		if !ok {
			t.Error("expected analysis in vulnerability")
			continue
		}
		state, ok := analysis["state"].(string)
		if !ok || state == "" {
			t.Error("expected non-empty VEX state")
			continue
		}
		// State should be one of the valid VEX states
		validStates := map[string]bool{
			"exploitable": true, "in_triage": true,
			"not_affected": true, "resolved": true,
		}
		if !validStates[state] {
			t.Errorf("invalid VEX state: %s", state)
		}
	}
}

func TestRealNodeGoatSPDX(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepo(t, "https://github.com/OWASP/NodeGoat.git", "NodeGoat")

	data := runPatchflowExport(t, repoDir, "spdx-json")

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if doc["spdxVersion"] != "SPDX-2.3" {
		t.Errorf("expected spdxVersion=SPDX-2.3, got %v", doc["spdxVersion"])
	}

	packages := doc["packages"].([]interface{})
	if len(packages) < 20 {
		t.Errorf("expected at least 20 packages, got %d", len(packages))
	}

	// Verify relationships exist
	rels := doc["relationships"].([]interface{})
	if len(rels) < 20 {
		t.Errorf("expected at least 20 relationships, got %d", len(rels))
	}

	// Verify at least one DEPENDS_ON relationship
	foundDependsOn := false
	for _, r := range rels {
		rel := r.(map[string]interface{})
		if rel["relationshipType"] == "DEPENDS_ON" {
			foundDependsOn = true
			break
		}
	}
	if !foundDependsOn {
		t.Error("expected at least one DEPENDS_ON relationship")
	}
}

func TestRealNodeGoatVEX(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepo(t, "https://github.com/OWASP/NodeGoat.git", "NodeGoat")

	data := runPatchflowExport(t, repoDir, "vex-json")

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if doc["bomFormat"] != "CycloneDX" {
		t.Errorf("expected bomFormat=CycloneDX, got %v", doc["bomFormat"])
	}

	vulns := doc["vulnerabilities"].([]interface{})
	if len(vulns) < 5 {
		t.Errorf("expected at least 5 vulnerabilities, got %d", len(vulns))
	}

	// Verify all vulnerabilities have analysis with valid states
	validStates := map[string]bool{
		"exploitable": true, "in_triage": true,
		"not_affected": true, "resolved": true,
	}
	for _, v := range vulns {
		vuln, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		analysis, ok := vuln["analysis"].(map[string]interface{})
		if !ok {
			t.Error("expected analysis in vulnerability")
			continue
		}
		state, ok := analysis["state"].(string)
		if !ok {
			t.Error("expected state in analysis")
			continue
		}
		if !validStates[state] {
			t.Errorf("invalid VEX state: %s", state)
		}
	}

	// Verify at least some vulnerabilities are exploitable (NodeGoat imports vulnerable packages)
	foundExploitable := false
	for _, v := range vulns {
		vuln, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		analysis, ok := vuln["analysis"].(map[string]interface{})
		if !ok {
			continue
		}
		if analysis["state"] == "exploitable" {
			foundExploitable = true
			// Verify detail is populated
			if detail, ok := analysis["detail"].(string); ok && detail == "" {
				t.Error("exploitable vulnerability should have detail")
			}
			break
		}
	}
	if !foundExploitable {
		t.Log("warning: no exploitable vulnerabilities found (expected some for NodeGoat)")
	}
}

func TestRealNodeGoatDepTree(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepo(t, "https://github.com/OWASP/NodeGoat.git", "NodeGoat")

	data := runPatchflowExport(t, repoDir, "dep-tree")
	tree := string(data)

	if !strings.Contains(tree, "npm") {
		t.Error("tree should contain npm ecosystem")
	}

	// NodeGoat uses express — should be in the tree
	if !strings.Contains(tree, "express") {
		t.Error("tree should contain express dependency")
	}

	// Verify tree structure (should have box-drawing characters)
	if !strings.Contains(tree, "└──") && !strings.Contains(tree, "├──") {
		t.Error("tree should use box-drawing characters")
	}
}

func TestRealNodeGoatDepDot(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepo(t, "https://github.com/OWASP/NodeGoat.git", "NodeGoat")

	data := runPatchflowExport(t, repoDir, "dep-dot")
	dot := string(data)

	if !strings.Contains(dot, "digraph") {
		t.Error("DOT should contain 'digraph'")
	}
	if !strings.Contains(dot, "express") {
		t.Error("DOT should contain express")
	}
}

func TestRealNodeGoatLicenses(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepo(t, "https://github.com/OWASP/NodeGoat.git", "NodeGoat")

	output := runPatchflowDepsLicenses(t, repoDir)

	if !strings.Contains(output, "License Report") {
		t.Error("expected 'License Report' header")
	}
	if !strings.Contains(output, "By Category") {
		t.Error("expected 'By Category' section")
	}
	if !strings.Contains(output, "By Risk") {
		t.Error("expected 'By Risk' section")
	}

	// NodeGoat's package.json has a license field
	if !strings.Contains(output, "Apache") {
		t.Log("warning: expected Apache license in output")
	}
}

// --- dvna (Damn Vulnerable Node Application) ---

func TestRealDvnaCycloneDX(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepo(t, "https://github.com/appsecco/dvna.git", "dvna")

	data := runPatchflowExport(t, repoDir, "cyclonedx-json", "--include-vex")

	var bom map[string]interface{}
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if bom["bomFormat"] != "CycloneDX" {
		t.Errorf("expected bomFormat=CycloneDX, got %v", bom["bomFormat"])
	}

	components := bom["components"].([]interface{})
	if len(components) < 10 {
		t.Errorf("expected at least 10 components, got %d", len(components))
	}

	// dvna has known vulnerabilities
	vulns := bom["vulnerabilities"].([]interface{})
	if len(vulns) < 5 {
		t.Errorf("expected at least 5 vulnerabilities, got %d", len(vulns))
	}
}

func TestRealDvnaVEX(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepo(t, "https://github.com/appsecco/dvna.git", "dvna")

	data := runPatchflowExport(t, repoDir, "vex-json")

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	vulns := doc["vulnerabilities"].([]interface{})
	if len(vulns) < 5 {
		t.Errorf("expected at least 5 vulnerabilities, got %d", len(vulns))
	}

	// Verify VEX states
	validStates := map[string]bool{
		"exploitable": true, "in_triage": true,
		"not_affected": true, "resolved": true,
	}
	for _, v := range vulns {
		vuln, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		analysis, ok := vuln["analysis"].(map[string]interface{})
		if !ok {
			t.Error("expected analysis in vulnerability")
			continue
		}
		state, ok := analysis["state"].(string)
		if !ok {
			t.Error("expected state in analysis")
			continue
		}
		if !validStates[state] {
			t.Errorf("invalid VEX state: %s", state)
		}
	}
}

// --- django-DefectDojo (Python) ---

func TestRealDjangoDefectDojoCycloneDX(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepo(t, "https://github.com/DefectDojo/django-DefectDojo.git", "django-DefectDojo")

	data := runPatchflowExport(t, repoDir, "cyclonedx-json", "--include-vex")

	var bom map[string]interface{}
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if bom["bomFormat"] != "CycloneDX" {
		t.Errorf("expected bomFormat=CycloneDX, got %v", bom["bomFormat"])
	}

	// DefectDojo is a large project with many deps
	components := bom["components"].([]interface{})
	if len(components) < 50 {
		t.Errorf("expected at least 50 components, got %d", len(components))
	}

	// Verify root component name
	meta := bom["metadata"].(map[string]interface{})
	component := meta["component"].(map[string]interface{})
	rootName, _ := component["name"].(string)
	if !strings.Contains(strings.ToLower(rootName), "defect") {
		t.Errorf("expected root name to contain 'defect', got %s", rootName)
	}
}

func TestRealDjangoDefectDojoLicenses(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepo(t, "https://github.com/DefectDojo/django-DefectDojo.git", "django-DefectDojo")

	output := runPatchflowDepsLicenses(t, repoDir)

	if !strings.Contains(output, "License Report") {
		t.Error("expected 'License Report' header")
	}

	// DefectDojo has BSD-3-Clause license
	if !strings.Contains(output, "BSD-3-Clause") {
		t.Log("warning: expected BSD-3-Clause license in output")
	}

	// Should classify some as permissive
	if !strings.Contains(output, "permissive") {
		t.Error("expected permissive category in output")
	}
}

// --- WebGoat (Java/Maven) ---

func TestRealWebGoatCycloneDX(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepo(t, "https://github.com/WebGoat/WebGoat.git", "WebGoat")

	data := runPatchflowExport(t, repoDir, "cyclonedx-json", "--include-vex")

	var bom map[string]interface{}
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if bom["bomFormat"] != "CycloneDX" {
		t.Errorf("expected bomFormat=CycloneDX, got %v", bom["bomFormat"])
	}

	// WebGoat is a Java/Maven project with many deps
	components := bom["components"].([]interface{})
	if len(components) < 20 {
		t.Errorf("expected at least 20 components, got %d", len(components))
	}

	// Verify root component name
	meta := bom["metadata"].(map[string]interface{})
	component := meta["component"].(map[string]interface{})
	rootName, _ := component["name"].(string)
	if !strings.Contains(strings.ToLower(rootName), "goat") {
		t.Errorf("expected root name to contain 'goat', got %s", rootName)
	}

	// Verify Maven purl format
	foundMavenPurl := false
	for _, c := range components {
		comp := c.(map[string]interface{})
		if purl, ok := comp["purl"].(string); ok {
			if strings.Contains(purl, "pkg:maven/") {
				foundMavenPurl = true
				break
			}
		}
	}
	if !foundMavenPurl {
		t.Error("expected at least one Maven purl in components")
	}
}

func TestRealWebGoatSPDX(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepo(t, "https://github.com/WebGoat/WebGoat.git", "WebGoat")

	data := runPatchflowExport(t, repoDir, "spdx-json")

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if doc["spdxVersion"] != "SPDX-2.3" {
		t.Errorf("expected spdxVersion=SPDX-2.3, got %v", doc["spdxVersion"])
	}

	packages := doc["packages"].([]interface{})
	if len(packages) < 20 {
		t.Errorf("expected at least 20 packages, got %d", len(packages))
	}

	// Verify root package name
	name, _ := doc["name"].(string)
	if !strings.Contains(strings.ToLower(name), "goat") {
		t.Errorf("expected name to contain 'goat', got %s", name)
	}

	// Verify Maven purl external refs
	foundPurlRef := false
	for _, p := range packages {
		pkg := p.(map[string]interface{})
		if refs, ok := pkg["externalRefs"].([]interface{}); ok {
			for _, r := range refs {
				ref := r.(map[string]interface{})
				if ref["referenceType"] == "purl" {
					if strings.Contains(ref["referenceLocator"].(string), "pkg:maven/") {
						foundPurlRef = true
					}
				}
			}
		}
	}
	if !foundPurlRef {
		t.Error("expected at least one Maven purl external reference")
	}
}

func TestRealWebGoatVEX(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepo(t, "https://github.com/WebGoat/WebGoat.git", "WebGoat")

	data := runPatchflowExport(t, repoDir, "vex-json")

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	vulns := doc["vulnerabilities"].([]interface{})
	if len(vulns) < 5 {
		t.Errorf("expected at least 5 vulnerabilities, got %d", len(vulns))
	}

	// Verify all have valid VEX states
	validStates := map[string]bool{
		"exploitable": true, "in_triage": true,
		"not_affected": true, "resolved": true,
	}
	for _, v := range vulns {
		vuln, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		analysis, ok := vuln["analysis"].(map[string]interface{})
		if !ok {
			t.Error("expected analysis in vulnerability")
			continue
		}
		state, ok := analysis["state"].(string)
		if !ok {
			t.Error("expected state in analysis")
			continue
		}
		if !validStates[state] {
			t.Errorf("invalid VEX state: %s", state)
		}
	}
}

// --- Cross-repo consistency test ---

func TestRealReposCycloneDXConsistency(t *testing.T) {
	skipIfShort(t)
	repos := []struct {
		url  string
		name string
	}{
		{"https://github.com/OWASP/NodeGoat.git", "NodeGoat"},
		{"https://github.com/appsecco/dvna.git", "dvna"},
	}

	for _, repo := range repos {
		t.Run(repo.name, func(t *testing.T) {
			repoDir := cloneRepo(t, repo.url, repo.name)

			// Generate CycloneDX
			cdxData := runPatchflowExport(t, repoDir, "cyclonedx-json", "--include-vex")
			var bom map[string]interface{}
			if err := json.Unmarshal(cdxData, &bom); err != nil {
				t.Fatalf("invalid CycloneDX JSON: %v", err)
			}

			// Generate SPDX
			spdxData := runPatchflowExport(t, repoDir, "spdx-json")
			var doc map[string]interface{}
			if err := json.Unmarshal(spdxData, &doc); err != nil {
				t.Fatalf("invalid SPDX JSON: %v", err)
			}

			// Verify component counts are consistent
			cdxComponents := len(bom["components"].([]interface{}))
			spdxPackages := len(doc["packages"].([]interface{}))

			// SPDX has 1 extra (root package), CycloneDX root is in metadata
			if spdxPackages < cdxComponents {
				t.Errorf("SPDX packages (%d) should be >= CycloneDX components (%d)",
					spdxPackages, cdxComponents)
			}

			// Verify root name is consistent
			cdxMeta, ok := bom["metadata"].(map[string]interface{})
			if !ok {
				t.Fatal("expected metadata in CycloneDX")
			}
			cdxComp, ok := cdxMeta["component"].(map[string]interface{})
			if !ok {
				t.Fatal("expected component in CycloneDX metadata")
			}
			cdxRoot, _ := cdxComp["name"].(string)
			spdxName, _ := doc["name"].(string)
			if cdxRoot != spdxName {
				t.Errorf("root name mismatch: CycloneDX=%s, SPDX=%s", cdxRoot, spdxName)
			}
		})
	}
}
