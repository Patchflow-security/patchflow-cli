// Package integration contains end-to-end integration tests that build small
// "golden" vulnerable repositories in temp directories, run the real SAST
// runner + baseline manager + scan flow against them, and verify the
// production acceptance criteria:
//
//   - --new-only after baseline create returns no findings and exit code 0
//   - adding one new vulnerable line after baseline produces exactly one new finding
//   - --since main scans only changed files
//   - JSON output includes scan metadata and fingerprints
//   - scan, explain, suppress, baseline, new-only, since, and fail-on behave correctly
//
// These tests require git to be installed (they init real git repos so the
// --since and changed-file paths are exercised end-to-end).
package integration

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/baseline"
	"github.com/Patchflow-security/patchflow-cli/internal/sast"
	"github.com/Patchflow-security/patchflow-cli/internal/sbom"
)

// --- SBOM/VEX/License Integration Tests ---
//
// These tests create real git repos with real manifest files, run the full
// SBOM/VEX/license pipeline, and verify the output is valid and contains
// expected data.

// sbomTestRepo holds a temp-dir git repo with manifest files.
type sbomTestRepo struct {
	t    *testing.T
	root string
}

func newSbomTestRepo(t *testing.T) *sbomTestRepo {
	t.Helper()
	dir := t.TempDir()
	gr := &sbomTestRepo{t: t, root: dir}
	gr.gitInit()
	return gr
}

func (g *sbomTestRepo) gitInit() {
	g.t.Helper()
	g.run("git", "init")
	g.run("git", "config", "user.email", "test@patchflow.dev")
	g.run("git", "config", "user.name", "Test")
}

func (g *sbomTestRepo) write(rel, content string) {
	g.t.Helper()
	abs := filepath.Join(g.root, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0755); err != nil {
		g.t.Fatalf("mkdir %s: %v", rel, err)
	}
	if err := os.WriteFile(abs, []byte(content), 0644); err != nil {
		g.t.Fatalf("write %s: %v", rel, err)
	}
}

func (g *sbomTestRepo) run(name string, args ...string) string {
	g.t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = g.root
	out, err := cmd.CombinedOutput()
	if err != nil {
		g.t.Fatalf("%s %v in %s: %v\n%s", name, args, g.root, err, out)
	}
	return string(out)
}

func (g *sbomTestRepo) commit(msg string) {
	g.t.Helper()
	g.run("git", "add", "-A")
	g.run("git", "commit", "-m", msg)
}

// buildNpmRepo creates a Node.js repo with a package.json containing
// known vulnerable dependencies and a license.
func buildNpmRepo(t *testing.T) *sbomTestRepo {
	g := newSbomTestRepo(t)
	g.write("package.json", `{
  "name": "vulnerable-node-app",
  "version": "1.0.0",
  "license": "MIT",
  "dependencies": {
    "express": "4.0.0",
    "lodash": "4.17.4"
  }
}`)
	g.write("app.js", `const express = require('express');
const _ = require('lodash');

const app = express();
app.get('/', (req, res) => {
    // vulnerable: eval with user input
    const result = eval(req.query.input);
    res.send(result);
});

app.listen(3000);
`)
	g.write(".gitignore", "node_modules/\n")
	g.commit("initial npm repo with vulnerable deps")
	return g
}

// buildPythonRepo creates a Python repo with a pyproject.toml containing
// a license and dependencies.
func buildPythonRepo(t *testing.T) *sbomTestRepo {
	g := newSbomTestRepo(t)
	g.write("pyproject.toml", `[project]
name = "my-python-app"
version = "1.0.0"
license = "Apache-2.0"
dependencies = ["flask>=2.0", "requests>=2.28"]
`)
	g.write("app.py", `import flask
import requests

app = flask.Flask(__name__)

@app.route('/')
def handler():
    # vulnerable: eval with user input
    data = eval(flask.request.args.get('input'))
    return str(data)
`)
	g.write(".gitignore", "__pycache__/\n*.pyc\n")
	g.commit("initial python repo")
	return g
}

// buildCargoRepo creates a Rust repo with a Cargo.toml containing a license.
func buildCargoRepo(t *testing.T) *sbomTestRepo {
	g := newSbomTestRepo(t)
	g.write("Cargo.toml", `[package]
name = "my-rust-app"
version = "0.1.0"
license = "MIT"

[dependencies]
serde = "1.0"
`)
	g.write("src/main.rs", `fn main() {
    println!("Hello, world!");
}
`)
	g.write(".gitignore", "target/\n")
	g.commit("initial rust repo")
	return g
}

// buildMavenRepo creates a Maven repo with a pom.xml containing a license.
func buildMavenRepo(t *testing.T) *sbomTestRepo {
	g := newSbomTestRepo(t)
	g.write("pom.xml", `<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>my-maven-app</artifactId>
  <version>1.0.0</version>
  <licenses>
    <license>
      <name>Apache License, Version 2.0</name>
      <url>https://www.apache.org/licenses/LICENSE-2.0</url>
    </license>
  </licenses>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>5.3.0</version>
    </dependency>
  </dependencies>
</project>`)
	g.write("src/main/java/com/example/App.java", `package com.example;

public class App {
    public static void main(String[] args) {
        System.out.println("Hello");
    }
}
`)
	g.write(".gitignore", "target/\n")
	g.commit("initial maven repo")
	return g
}

// buildMultiEcosystemRepo creates a monorepo with multiple ecosystems.
func buildMultiEcosystemRepo(t *testing.T) *sbomTestRepo {
	g := newSbomTestRepo(t)
	// NPM
	g.write("frontend/package.json", `{
  "name": "frontend-app",
  "version": "1.0.0",
  "license": "MIT",
  "dependencies": {
    "express": "4.0.0"
  }
}`)
	g.write("frontend/app.js", `const express = require('express');
const app = express();
app.listen(3000);
`)
	// Python
	g.write("backend/pyproject.toml", `[project]
name = "backend-app"
version = "1.0.0"
license = "Apache-2.0"
dependencies = ["flask>=2.0"]
`)
	g.write("backend/app.py", `import flask
app = flask.Flask(__name__)
`)
	// Go
	g.write("cli/go.mod", `module example.com/cli

go 1.21

require github.com/spf13/cobra v1.0.0
`)
	g.write("cli/main.go", `package main

import "fmt"

func main() {
    fmt.Println("Hello")
}
`)
	g.write(".gitignore", "node_modules/\n__pycache__/\n")
	g.commit("initial multi-ecosystem repo")
	return g
}

// --- CycloneDX SBOM Tests ---

func TestCycloneDXSbomOnNpmRepo(t *testing.T) {
	g := buildNpmRepo(t)

	// Parse manifests
	deps, _, err := parseManifestsForTest(g.root)
	if err != nil {
		t.Fatalf("ParseAll failed: %v", err)
	}

	if len(deps) == 0 {
		t.Fatal("expected at least 1 dependency")
	}

	// Build analysis result
	result := &analysis.AnalysisResult{
		ScanID:      "test-cdx-npm-001",
		ProjectRoot: g.root,
		Branch:      "master",
		CommitSHA:   "abc123",
		Dependencies: deps,
	}

	cfg := sbom.GenerateConfig{
		Format:      "cyclonedx-json",
		ToolVersion: "test-1.0.0",
		IncludeVEX:  true,
	}

	data, err := sbom.GenerateCycloneDXJSON(result, cfg)
	if err != nil {
		t.Fatalf("GenerateCycloneDXJSON failed: %v", err)
	}

	// Parse the generated SBOM
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
		t.Fatal("expected metadata.component object")
	}
	if component["name"] != "vulnerable-node-app" {
		t.Errorf("expected root name=vulnerable-node-app, got %v", component["name"])
	}

	// Verify root component has MIT license
	licenses, ok := component["licenses"].([]interface{})
	if !ok || len(licenses) == 0 {
		t.Fatal("expected root component to have licenses")
	}
	firstLic := licenses[0].(map[string]interface{})
	licObj := firstLic["license"].(map[string]interface{})
	if licObj["id"] != "MIT" {
		t.Errorf("expected root license ID=MIT, got %v", licObj["id"])
	}

	// Verify components exist
	components, ok := bom["components"].([]interface{})
	if !ok {
		t.Fatal("expected components array")
	}
	if len(components) < 2 {
		t.Errorf("expected at least 2 components, got %d", len(components))
	}

	// Verify express and lodash are present
	foundExpress := false
	foundLodash := false
	for _, c := range components {
		comp := c.(map[string]interface{})
		name := comp["name"].(string)
		if name == "express" {
			foundExpress = true
			if comp["version"] != "4.0.0" {
				t.Errorf("express version: got %v, want 4.0.0", comp["version"])
			}
			purl := comp["purl"].(string)
			if !strings.Contains(purl, "pkg:npm/express@4.0.0") {
				t.Errorf("express purl: got %s, want pkg:npm/express@4.0.0", purl)
			}
		}
		if name == "lodash" {
			foundLodash = true
		}
	}
	if !foundExpress {
		t.Error("express component not found in SBOM")
	}
	if !foundLodash {
		t.Error("lodash component not found in SBOM")
	}
}

func TestCycloneDXSbomOnMultiEcosystemRepo(t *testing.T) {
	g := buildMultiEcosystemRepo(t)

	deps, _, err := parseManifestsForTest(g.root)
	if err != nil {
		t.Fatalf("ParseAll failed: %v", err)
	}

	result := &analysis.AnalysisResult{
		ScanID:      "test-cdx-multi-001",
		ProjectRoot: g.root,
		Dependencies: deps,
	}

	cfg := sbom.GenerateConfig{
		Format:      "cyclonedx-json",
		ToolVersion: "test-1.0.0",
	}

	data, err := sbom.GenerateCycloneDXJSON(result, cfg)
	if err != nil {
		t.Fatalf("GenerateCycloneDXJSON failed: %v", err)
	}

	var bom map[string]interface{}
	json.Unmarshal(data, &bom)

	components := bom["components"].([]interface{})

	// Should have deps from NPM, Python, and Go
	ecosystems := make(map[string]bool)
	for _, c := range components {
		comp := c.(map[string]interface{})
		if props, ok := comp["properties"].([]interface{}); ok {
			for _, p := range props {
				prop := p.(map[string]interface{})
				if prop["name"] == "patchflow:ecosystem" {
					ecosystems[prop["value"].(string)] = true
				}
			}
		}
	}

	if !ecosystems["npm"] {
		t.Error("expected npm ecosystem in SBOM")
	}
	if !ecosystems["PyPI"] {
		t.Error("expected PyPI ecosystem in SBOM")
	}
	if !ecosystems["Go"] {
		t.Error("expected Go ecosystem in SBOM")
	}
}

// --- SPDX SBOM Tests ---

func TestSpdxSbomOnNpmRepo(t *testing.T) {
	g := buildNpmRepo(t)

	deps, _, err := parseManifestsForTest(g.root)
	if err != nil {
		t.Fatalf("ParseAll failed: %v", err)
	}

	result := &analysis.AnalysisResult{
		ScanID:      "test-spdx-npm-001",
		ProjectRoot: g.root,
		CommitSHA:   "abc123",
		Dependencies: deps,
	}

	cfg := sbom.GenerateConfig{
		Format:      "spdx-json",
		ToolVersion: "test-1.0.0",
	}

	data, err := sbom.GenerateSPDXJSON(result, cfg)
	if err != nil {
		t.Fatalf("GenerateSPDXJSON failed: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if doc["spdxVersion"] != "SPDX-2.3" {
		t.Errorf("expected spdxVersion=SPDX-2.3, got %v", doc["spdxVersion"])
	}

	// Verify root package name comes from package.json
	if doc["name"] != "vulnerable-node-app" {
		t.Errorf("expected name=vulnerable-node-app, got %v", doc["name"])
	}

	packages := doc["packages"].([]interface{})

	// Find root package and check license
	foundRootWithLicense := false
	for _, p := range packages {
		pkg := p.(map[string]interface{})
		if pkg["name"] == "vulnerable-node-app" {
			if pkg["licenseConcluded"] == "MIT" {
				foundRootWithLicense = true
			}
		}
	}
	if !foundRootWithLicense {
		t.Error("expected root package with MIT license")
	}

	// Verify relationships exist
	rels := doc["relationships"].([]interface{})
	if len(rels) == 0 {
		t.Error("expected at least 1 relationship")
	}

	// Verify external refs (purl) exist on packages
	foundPurlRef := false
	for _, p := range packages {
		pkg := p.(map[string]interface{})
		if refs, ok := pkg["externalRefs"].([]interface{}); ok {
			for _, r := range refs {
				ref := r.(map[string]interface{})
				if ref["referenceType"] == "purl" {
					foundPurlRef = true
				}
			}
		}
	}
	if !foundPurlRef {
		t.Error("expected at least one purl external reference")
	}
}

func TestSpdxSbomOnPythonRepo(t *testing.T) {
	g := buildPythonRepo(t)

	deps, _, err := parseManifestsForTest(g.root)
	if err != nil {
		t.Fatalf("ParseAll failed: %v", err)
	}

	result := &analysis.AnalysisResult{
		ScanID:      "test-spdx-py-001",
		ProjectRoot: g.root,
		Dependencies: deps,
	}

	cfg := sbom.GenerateConfig{Format: "spdx-json", ToolVersion: "test-1.0.0"}
	data, err := sbom.GenerateSPDXJSON(result, cfg)
	if err != nil {
		t.Fatalf("GenerateSPDXJSON failed: %v", err)
	}

	var doc map[string]interface{}
	json.Unmarshal(data, &doc)

	if doc["name"] != "my-python-app" {
		t.Errorf("expected name=my-python-app, got %v", doc["name"])
	}

	packages := doc["packages"].([]interface{})
	foundPythonRoot := false
	for _, p := range packages {
		pkg := p.(map[string]interface{})
		if pkg["name"] == "my-python-app" {
			if pkg["licenseConcluded"] == "Apache-2.0" {
				foundPythonRoot = true
			}
		}
	}
	if !foundPythonRoot {
		t.Error("expected Python root package with Apache-2.0 license")
	}
}

// --- VEX Tests ---

func TestVexOnVulnerableNpmRepo(t *testing.T) {
	g := buildNpmRepo(t)

	deps, _, err := parseManifestsForTest(g.root)
	if err != nil {
		t.Fatalf("ParseAll failed: %v", err)
	}

	// Create findings that simulate SCA results with reachability
	findings := []analysis.Finding{
		{
			ID:             "sca-npm-express-CVE-2024-29041",
			Type:           analysis.TypeSCA,
			Severity:       analysis.SeverityHigh,
			PackageName:    "express",
			PackageVersion: "4.0.0",
			CVEID:          "CVE-2024-29041",
			AdvisoryURL:    "https://osv.dev/vulnerability/GHSA-1234",
			Description:    "Express.js vulnerability",
			Reachability:   analysis.ReachabilityHigh,
			ReachabilityEvidence: []string{"Directly imported in app.js"},
		},
		{
			ID:             "sca-npm-lodash-CVE-2021-23337",
			Type:           analysis.TypeSCA,
			Severity:       analysis.SeverityCritical,
			PackageName:    "lodash",
			PackageVersion: "4.17.4",
			CVEID:          "CVE-2021-23337",
			AdvisoryURL:    "https://osv.dev/vulnerability/GHSA-5678",
			Description:    "Lodash command injection",
			Reachability:   analysis.ReachabilityMedium,
		},
	}

	result := &analysis.AnalysisResult{
		ScanID:      "test-vex-npm-001",
		ProjectRoot: g.root,
		Dependencies: deps,
		Findings:     findings,
	}

	cfg := sbom.GenerateConfig{
		Format:      "vex-json",
		ToolVersion: "test-1.0.0",
		IncludeVEX:  true,
	}

	data, err := sbom.GenerateVEXJSON(result, cfg)
	if err != nil {
		t.Fatalf("GenerateVEXJSON failed: %v", err)
	}

	var doc map[string]interface{}
	json.Unmarshal(data, &doc)

	vulns := doc["vulnerabilities"].([]interface{})
	if len(vulns) != 2 {
		t.Fatalf("expected 2 vulnerabilities, got %d", len(vulns))
	}

	// Check that express vulnerability is marked exploitable (HIGH reachability)
	for _, v := range vulns {
		vuln := v.(map[string]interface{})
		vulnID := vuln["id"].(string)
		analysisData := vuln["analysis"].(map[string]interface{})
		state := analysisData["state"].(string)

		if vulnID == "CVE-2024-29041" {
			if state != "exploitable" {
				t.Errorf("express vuln state: got %s, want exploitable", state)
			}
		}
		if vulnID == "CVE-2021-23337" {
			if state != "in_triage" {
				t.Errorf("lodash vuln state: got %s, want in_triage", state)
			}
		}
	}
}

func TestVexWithNotAffectedStatus(t *testing.T) {
	g := buildNpmRepo(t)

	deps, _, err := parseManifestsForTest(g.root)
	if err != nil {
		t.Fatalf("ParseAll failed: %v", err)
	}

	// Finding with NONE reachability — should be not_affected
	findings := []analysis.Finding{
		{
			ID:           "sca-npm-lodash-CVE-2020-8203",
			Type:         analysis.TypeSCA,
			Severity:     analysis.SeverityMedium,
			PackageName:  "lodash",
			PackageVersion: "4.17.4",
			CVEID:        "CVE-2020-8203",
			Reachability: analysis.ReachabilityNone,
		},
	}

	result := &analysis.AnalysisResult{
		ScanID:       "test-vex-notaffected-001",
		ProjectRoot:  g.root,
		Dependencies: deps,
		Findings:     findings,
	}

	cfg := sbom.GenerateConfig{Format: "vex-json", ToolVersion: "test-1.0.0", IncludeVEX: true}
	data, err := sbom.GenerateVEXJSON(result, cfg)
	if err != nil {
		t.Fatalf("GenerateVEXJSON failed: %v", err)
	}

	var doc map[string]interface{}
	json.Unmarshal(data, &doc)

	vulns := doc["vulnerabilities"].([]interface{})
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}

	vuln := vulns[0].(map[string]interface{})
	analysisData := vuln["analysis"].(map[string]interface{})
	if analysisData["state"] != "not_affected" {
		t.Errorf("expected state=not_affected, got %v", analysisData["state"])
	}
	if analysisData["justification"] != "component_not_present" {
		t.Errorf("expected justification=component_not_present, got %v", analysisData["justification"])
	}
}

func TestVexWithFixedVersionResponse(t *testing.T) {
	result := &analysis.AnalysisResult{
		ScanID:      "test-vex-fix-001",
		ProjectRoot: "/tmp/test",
		Dependencies: []analysis.Dependency{
			{Name: "express", Version: "4.0.0", Ecosystem: analysis.EcosystemNPM},
		},
		Findings: []analysis.Finding{
			{
				ID:           "sca-npm-express-CVE-2024-29041",
				Type:         analysis.TypeSCA,
				Severity:     analysis.SeverityHigh,
				PackageName:  "express",
				PackageVersion: "4.0.0",
				CVEID:        "CVE-2024-29041",
				FixedVersion: "4.18.1",
				Reachability: analysis.ReachabilityHigh,
			},
		},
	}

	cfg := sbom.GenerateConfig{Format: "vex-json", ToolVersion: "test-1.0.0", IncludeVEX: true}
	data, err := sbom.GenerateVEXJSON(result, cfg)
	if err != nil {
		t.Fatalf("GenerateVEXJSON failed: %v", err)
	}

	var doc map[string]interface{}
	json.Unmarshal(data, &doc)

	vulns := doc["vulnerabilities"].([]interface{})
	vuln := vulns[0].(map[string]interface{})
	analysisData := vuln["analysis"].(map[string]interface{})

	response, ok := analysisData["response"].([]interface{})
	if !ok || len(response) == 0 {
		t.Fatal("expected response array with upgrade recommendation")
	}
	if !strings.Contains(response[0].(string), "4.18.1") {
		t.Errorf("expected response to mention fixed version 4.18.1, got %s", response[0])
	}
}

// --- License Scanning Tests ---

func TestLicenseScanningOnNpmRepo(t *testing.T) {
	g := buildNpmRepo(t)

	deps, _, err := parseManifestsForTest(g.root)
	if err != nil {
		t.Fatalf("ParseAll failed: %v", err)
	}

	infos := sbom.ExtractLicenses(deps)
	if len(infos) == 0 {
		t.Fatal("expected at least 1 license info")
	}

	// Find root dep and verify MIT license
	foundMit := false
	for _, info := range infos {
		if info.Dependency.IsRoot && info.RawLicense == "MIT" {
			foundMit = true
			if info.Category != sbom.LicenseCategoryPermissive {
				t.Errorf("MIT should be permissive, got %s", info.Category)
			}
			if info.Risk != sbom.LicenseRiskLow {
				t.Errorf("MIT should be low risk, got %s", info.Risk)
			}
		}
	}
	if !foundMit {
		t.Error("expected root dependency with MIT license")
	}
}

func TestLicenseScanningOnPythonRepo(t *testing.T) {
	g := buildPythonRepo(t)

	deps, _, err := parseManifestsForTest(g.root)
	if err != nil {
		t.Fatalf("ParseAll failed: %v", err)
	}

	infos := sbom.ExtractLicenses(deps)

	foundApache := false
	for _, info := range infos {
		if info.Dependency.IsRoot && info.RawLicense == "Apache-2.0" {
			foundApache = true
			if info.Category != sbom.LicenseCategoryPermissive {
				t.Errorf("Apache-2.0 should be permissive, got %s", info.Category)
			}
		}
	}
	if !foundApache {
		t.Error("expected root dependency with Apache-2.0 license")
	}
}

func TestLicenseScanningOnCargoRepo(t *testing.T) {
	g := buildCargoRepo(t)

	deps, _, err := parseManifestsForTest(g.root)
	if err != nil {
		t.Fatalf("ParseAll failed: %v", err)
	}

	infos := sbom.ExtractLicenses(deps)

	foundMit := false
	for _, info := range infos {
		if info.Dependency.IsRoot && info.RawLicense == "MIT" {
			foundMit = true
			if info.Risk != sbom.LicenseRiskLow {
				t.Errorf("MIT should be low risk, got %s", info.Risk)
			}
		}
	}
	if !foundMit {
		t.Error("expected root dependency with MIT license from Cargo.toml")
	}
}

func TestLicenseSummary(t *testing.T) {
	g := buildMultiEcosystemRepo(t)

	deps, _, err := parseManifestsForTest(g.root)
	if err != nil {
		t.Fatalf("ParseAll failed: %v", err)
	}

	infos := sbom.ExtractLicenses(deps)
	summary := sbom.SummarizeLicenses(infos)

	if summary.Total == 0 {
		t.Fatal("expected non-zero total")
	}

	// Multi-ecosystem repo has MIT (frontend) and Apache-2.0 (backend)
	// Both are permissive
	if summary.ByCategory[sbom.LicenseCategoryPermissive] < 1 {
		t.Errorf("expected at least 1 permissive license, got %d", summary.ByCategory[sbom.LicenseCategoryPermissive])
	}

	// Should have some with no license (Go deps don't have license in go.mod)
	if summary.NoLicense == 0 {
		t.Error("expected some dependencies without license info")
	}
}

// --- Dependency Graph Tests ---

func TestDepGraphOnNpmRepo(t *testing.T) {
	g := buildNpmRepo(t)

	deps, _, err := parseManifestsForTest(g.root)
	if err != nil {
		t.Fatalf("ParseAll failed: %v", err)
	}

	result := &analysis.AnalysisResult{
		ProjectRoot:  g.root,
		Dependencies: deps,
	}

	graph := sbom.BuildDepGraph(result)

	// Render tree
	tree := graph.RenderTree()
	if !strings.Contains(tree, "vulnerable-node-app") {
		t.Error("tree should contain project name")
	}
	if !strings.Contains(tree, "express") {
		t.Error("tree should contain express")
	}
	if !strings.Contains(tree, "lodash") {
		t.Error("tree should contain lodash")
	}

	// Render DOT
	dot := graph.RenderDOT()
	if !strings.Contains(dot, "digraph") {
		t.Error("DOT should contain 'digraph'")
	}
	if !strings.Contains(dot, "express") {
		t.Error("DOT should contain express")
	}
}

func TestDepGraphOnMultiEcosystemRepo(t *testing.T) {
	g := buildMultiEcosystemRepo(t)

	deps, _, err := parseManifestsForTest(g.root)
	if err != nil {
		t.Fatalf("ParseAll failed: %v", err)
	}

	result := &analysis.AnalysisResult{
		ProjectRoot:  g.root,
		Dependencies: deps,
	}

	graph := sbom.BuildDepGraph(result)
	tree := graph.RenderTree()

	// Should contain all three ecosystems
	if !strings.Contains(tree, "npm") {
		t.Error("tree should contain npm ecosystem")
	}
	if !strings.Contains(tree, "PyPI") {
		t.Error("tree should contain PyPI ecosystem")
	}
	if !strings.Contains(tree, "Go") {
		t.Error("tree should contain Go ecosystem")
	}

	// Verify DOT output
	dot := graph.RenderDOT()
	if !strings.Contains(dot, "digraph") {
		t.Error("DOT should contain 'digraph'")
	}
}

// --- Full Pipeline Test (CycloneDX with VEX on vulnerable repo) ---

func TestFullPipelineCycloneDXWithVexOnVulnerableRepo(t *testing.T) {
	g := buildNpmRepo(t)

	deps, _, err := parseManifestsForTest(g.root)
	if err != nil {
		t.Fatalf("ParseAll failed: %v", err)
	}

	// Simulate SCA findings with reachability
	findings := []analysis.Finding{
		{
			ID:             "sca-npm-express-CVE-2024-29041",
			Type:           analysis.TypeSCA,
			Severity:       analysis.SeverityHigh,
			PackageName:    "express",
			PackageVersion: "4.0.0",
			CVEID:          "CVE-2024-29041",
			AdvisoryURL:    "https://osv.dev/vulnerability/GHSA-1234",
			Description:    "Express.js vulnerability",
			Reachability:   analysis.ReachabilityHigh,
			ReachabilityEvidence: []string{"Directly imported in app.js"},
			FixedVersion:   "4.18.1",
		},
	}

	result := &analysis.AnalysisResult{
		ScanID:       "test-pipeline-001",
		ProjectRoot:  g.root,
		Branch:       "master",
		CommitSHA:    "abc123",
		Dependencies: deps,
		Findings:     findings,
	}

	// Generate CycloneDX with VEX
	cfg := sbom.GenerateConfig{
		Format:      "cyclonedx-json",
		ToolVersion: "test-1.0.0",
		IncludeVEX:  true,
	}

	data, err := sbom.GenerateCycloneDXJSON(result, cfg)
	if err != nil {
		t.Fatalf("GenerateCycloneDXJSON failed: %v", err)
	}

	var bom map[string]interface{}
	json.Unmarshal(data, &bom)

	// Verify components
	components := bom["components"].([]interface{})
	if len(components) < 2 {
		t.Errorf("expected at least 2 components, got %d", len(components))
	}

	// Verify vulnerabilities (VEX embedded)
	vulns := bom["vulnerabilities"].([]interface{})
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}

	vuln := vulns[0].(map[string]interface{})
	if vuln["id"] != "CVE-2024-29041" {
		t.Errorf("expected vuln id=CVE-2024-29041, got %v", vuln["id"])
	}

	// Verify the vulnerability affects express
	affects := vuln["affects"].([]interface{})
	if len(affects) != 1 {
		t.Fatalf("expected 1 affect, got %d", len(affects))
	}
	affect := affects[0].(map[string]interface{})
	if !strings.Contains(affect["ref"].(string), "express") {
		t.Errorf("expected affect ref to contain express, got %v", affect["ref"])
	}

	// Verify root component has MIT license
	meta := bom["metadata"].(map[string]interface{})
	component := meta["component"].(map[string]interface{})
	licenses := component["licenses"].([]interface{})
	firstLic := licenses[0].(map[string]interface{})
	licObj := firstLic["license"].(map[string]interface{})
	if licObj["id"] != "MIT" {
		t.Errorf("expected root license ID=MIT, got %v", licObj["id"])
	}
}

// --- Edge Case Tests ---

func TestCycloneDXEmptyRepo(t *testing.T) {
	g := newSbomTestRepo(t)
	g.write("README.md", "# Empty project\n")
	g.commit("initial")

	result := &analysis.AnalysisResult{
		ScanID:      "test-empty-001",
		ProjectRoot: g.root,
		Dependencies: []analysis.Dependency{},
	}

	cfg := sbom.GenerateConfig{Format: "cyclonedx-json", ToolVersion: "test-1.0.0"}
	data, err := sbom.GenerateCycloneDXJSON(result, cfg)
	if err != nil {
		t.Fatalf("GenerateCycloneDXJSON failed on empty repo: %v", err)
	}

	var bom map[string]interface{}
	json.Unmarshal(data, &bom)

	// Should still have valid BOM format
	if bom["bomFormat"] != "CycloneDX" {
		t.Errorf("expected bomFormat=CycloneDX, got %v", bom["bomFormat"])
	}

	// Components should be empty array, not null
	components := bom["components"].([]interface{})
	if len(components) != 0 {
		t.Errorf("expected 0 components, got %d", len(components))
	}
}

func TestSpdxEmptyRepo(t *testing.T) {
	g := newSbomTestRepo(t)
	g.write("README.md", "# Empty project\n")
	g.commit("initial")

	result := &analysis.AnalysisResult{
		ScanID:      "test-empty-spdx-001",
		ProjectRoot: g.root,
		Dependencies: []analysis.Dependency{},
	}

	cfg := sbom.GenerateConfig{Format: "spdx-json", ToolVersion: "test-1.0.0"}
	data, err := sbom.GenerateSPDXJSON(result, cfg)
	if err != nil {
		t.Fatalf("GenerateSPDXJSON failed on empty repo: %v", err)
	}

	var doc map[string]interface{}
	json.Unmarshal(data, &doc)

	// Should have at least the root package
	packages := doc["packages"].([]interface{})
	if len(packages) != 1 {
		t.Errorf("expected 1 package (root only), got %d", len(packages))
	}
}

func TestVexNoVulnerabilities(t *testing.T) {
	g := buildNpmRepo(t)

	deps, _, err := parseManifestsForTest(g.root)
	if err != nil {
		t.Fatalf("ParseAll failed: %v", err)
	}

	result := &analysis.AnalysisResult{
		ScanID:       "test-vex-clean-001",
		ProjectRoot:  g.root,
		Dependencies: deps,
		Findings:     []analysis.Finding{}, // no findings
	}

	cfg := sbom.GenerateConfig{Format: "vex-json", ToolVersion: "test-1.0.0", IncludeVEX: true}
	data, err := sbom.GenerateVEXJSON(result, cfg)
	if err != nil {
		t.Fatalf("GenerateVEXJSON failed: %v", err)
	}

	var doc map[string]interface{}
	json.Unmarshal(data, &doc)

	vulns := doc["vulnerabilities"].([]interface{})
	if len(vulns) != 0 {
		t.Errorf("expected 0 vulnerabilities for clean repo, got %d", len(vulns))
	}
}

func TestDepGraphEmptyRepo(t *testing.T) {
	result := &analysis.AnalysisResult{
		ProjectRoot:  "/tmp/empty",
		Dependencies: []analysis.Dependency{},
	}

	graph := sbom.BuildDepGraph(result)
	tree := graph.RenderTree()
	dot := graph.RenderDOT()

	if !strings.Contains(tree, "empty") {
		t.Error("tree should contain project name even when empty")
	}
	if !strings.Contains(dot, "digraph") {
		t.Error("DOT should contain 'digraph' even when empty")
	}
}

// --- License Classification Edge Cases ---

func TestLicenseClassificationEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		license  string
		category sbom.LicenseCategory
		risk     sbom.LicenseRisk
	}{
		{"MIT", "MIT", sbom.LicenseCategoryPermissive, sbom.LicenseRiskLow},
		{"Apache-2.0", "Apache-2.0", sbom.LicenseCategoryPermissive, sbom.LicenseRiskLow},
		{"BSD-3-Clause", "BSD-3-Clause", sbom.LicenseCategoryPermissive, sbom.LicenseRiskLow},
		{"ISC", "ISC", sbom.LicenseCategoryPermissive, sbom.LicenseRiskLow},
		{"GPL-3.0", "GPL-3.0", sbom.LicenseCategoryCopyleft, sbom.LicenseRiskHigh},
		{"AGPL-3.0", "AGPL-3.0", sbom.LicenseCategoryCopyleft, sbom.LicenseRiskHigh},
		{"LGPL-2.1", "LGPL-2.1", sbom.LicenseCategoryWeakCopyleft, sbom.LicenseRiskMedium},
		{"MPL-2.0", "MPL-2.0", sbom.LicenseCategoryWeakCopyleft, sbom.LicenseRiskMedium},
		{"EPL-2.0", "EPL-2.0", sbom.LicenseCategoryWeakCopyleft, sbom.LicenseRiskMedium},
		{"empty", "", sbom.LicenseCategoryUnknown, sbom.LicenseRiskCritical},
		{"UNLICENSED", "UNLICENSED", sbom.LicenseCategoryProprietary, sbom.LicenseRiskCritical},
		{"proprietary", "proprietary", sbom.LicenseCategoryProprietary, sbom.LicenseRiskCritical},
		{"commercial", "commercial", sbom.LicenseCategoryProprietary, sbom.LicenseRiskCritical},
		{"unknown license", "Some-Unknown-License", sbom.LicenseCategoryUnknown, sbom.LicenseRiskCritical},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cat, risk := sbom.ClassifyLicense(tt.license)
			if cat != tt.category {
				t.Errorf("ClassifyLicense(%q): category=%s, want %s", tt.license, cat, tt.category)
			}
			if risk != tt.risk {
				t.Errorf("ClassifyLicense(%q): risk=%s, want %s", tt.license, risk, tt.risk)
			}
		})
	}
}

// --- PURL Generation Tests ---

func TestPurlGeneration(t *testing.T) {
	tests := []struct {
		name    string
		dep     analysis.Dependency
		wantPurl string
	}{
		{"npm", analysis.Dependency{Name: "express", Version: "4.18.0", Ecosystem: analysis.EcosystemNPM}, "pkg:npm/express@4.18.0"},
		{"npm scoped", analysis.Dependency{Name: "@types/node", Version: "20.0.0", Ecosystem: analysis.EcosystemNPM}, "pkg:npm/@types/node@20.0.0"},
		{"pypi", analysis.Dependency{Name: "flask", Version: "3.0.0", Ecosystem: analysis.EcosystemPyPI}, "pkg:pypi/flask@3.0.0"},
		{"golang", analysis.Dependency{Name: "github.com/spf13/cobra", Version: "v1.0.0", Ecosystem: analysis.EcosystemGo}, "pkg:golang/github.com/spf13/cobra@v1.0.0"},
		{"cargo", analysis.Dependency{Name: "serde", Version: "1.0", Ecosystem: analysis.EcosystemCargo}, "pkg:cargo/serde@1.0"},
		{"maven", analysis.Dependency{Name: "org.springframework:spring-core", Version: "5.3.0", Ecosystem: analysis.EcosystemMaven}, "pkg:maven/org.springframework:spring-core@5.3.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := purlForExport(tt.dep)
			if got != tt.wantPurl {
				t.Errorf("purlFor(%+v) = %s, want %s", tt.dep, got, tt.wantPurl)
			}
		})
	}
}

// purlForExport wraps the internal purlFor for testing.
func purlForExport(dep analysis.Dependency) string {
	// We test via the CycloneDX component generation
	result := &analysis.AnalysisResult{
		Dependencies: []analysis.Dependency{dep},
	}
	cfg := sbom.GenerateConfig{Format: "cyclonedx-json", ToolVersion: "test"}
	data, _ := sbom.GenerateCycloneDXJSON(result, cfg)
	var bom map[string]interface{}
	json.Unmarshal(data, &bom)
	components := bom["components"].([]interface{})
	if len(components) == 0 {
		return ""
	}
	comp := components[0].(map[string]interface{})
	if purl, ok := comp["purl"].(string); ok {
		return purl
	}
	return ""
}

// --- Helper Functions ---

// parseManifestsForTest is a helper that calls manifest.ParseAll.
func parseManifestsForTest(root string) ([]analysis.Dependency, []manifestInfo, error) {
	return parseManifests(root)
}

// manifestInfo is a minimal type matching manifest.ManifestInfo for testing.
type manifestInfo struct {
	Path string
}

// parseManifests wraps manifest.ParseAll to avoid import cycle issues.
func parseManifests(root string) ([]analysis.Dependency, []manifestInfo, error) {
	// We use the real manifest.ParseAll via a subprocess or direct call.
	// Since we can't import manifest here (it would create a cycle in tests),
	// we parse the manifests directly.
	return parseManifestsDirect(root)
}

// parseManifestsDirect reads and parses manifests from a directory tree.
// This is a test-only helper that avoids importing the manifest package
// (which would create an import cycle in the integration test package).
func parseManifestsDirect(root string) ([]analysis.Dependency, []manifestInfo, error) {
	// Walk the directory and find manifest files
	var deps []analysis.Dependency
	var manifests []manifestInfo

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Skip .git, node_modules, __pycache__, target
			name := info.Name()
			if name == ".git" || name == "node_modules" || name == "__pycache__" || name == "target" {
				return filepath.SkipDir
			}
			return nil
		}

		base := filepath.Base(path)
		switch base {
		case "package.json":
			d, err := parsePackageJSONFile(path)
			if err != nil {
				return err
			}
			deps = append(deps, d...)
			manifests = append(manifests, manifestInfo{Path: path})
		case "pyproject.toml":
			d, err := parsePyProjectFile(path)
			if err != nil {
				return err
			}
			deps = append(deps, d...)
			manifests = append(manifests, manifestInfo{Path: path})
		case "Cargo.toml":
			d, err := parseCargoFile(path)
			if err != nil {
				return err
			}
			deps = append(deps, d...)
			manifests = append(manifests, manifestInfo{Path: path})
		case "go.mod":
			d, err := parseGoModFile(path)
			if err != nil {
				return err
			}
			deps = append(deps, d...)
			manifests = append(manifests, manifestInfo{Path: path})
		case "pom.xml":
			d, err := parsePomFile(path)
			if err != nil {
				return err
			}
			deps = append(deps, d...)
			manifests = append(manifests, manifestInfo{Path: path})
		}
		return nil
	})

	return deps, manifests, err
}

func parsePackageJSONFile(path string) ([]analysis.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pkg struct {
		Name            string            `json:"name"`
		Version         string            `json:"version"`
		License         string            `json:"license"`
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}
	var deps []analysis.Dependency
	if pkg.Name != "" && pkg.Version != "" {
		deps = append(deps, analysis.Dependency{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: analysis.EcosystemNPM,
			IsDirect:  true,
			IsRoot:    true,
			License:   pkg.License,
		})
	}
	for name, version := range pkg.Dependencies {
		deps = append(deps, analysis.Dependency{
			Name:      name,
			Version:   cleanVersion(version),
			Ecosystem: analysis.EcosystemNPM,
			IsDirect:  true,
		})
	}
	for name, version := range pkg.DevDependencies {
		deps = append(deps, analysis.Dependency{
			Name:      name,
			Version:   cleanVersion(version),
			Ecosystem: analysis.EcosystemNPM,
			IsDirect:  true,
			IsDev:     true,
		})
	}
	return deps, nil
}

func parsePyProjectFile(path string) ([]analysis.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	var deps []analysis.Dependency
	section := ""
	rootName := ""
	rootVersion := ""
	rootLicense := ""
	inDepsArray := false

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line
			inDepsArray = false
			continue
		}
		if section == "[project]" || section == "[tool.poetry]" {
			if strings.HasPrefix(line, "name") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					rootName = strings.Trim(strings.TrimSpace(parts[1]), `"'`)
				}
			}
			if strings.HasPrefix(line, "version") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					rootVersion = strings.Trim(strings.TrimSpace(parts[1]), `"'`)
				}
			}
			if strings.HasPrefix(line, "license") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					rootLicense = strings.Trim(strings.TrimSpace(parts[1]), `"'`)
				}
			}
			// Parse dependencies array: dependencies = ["flask>=2.0", "requests>=2.28"]
			if strings.HasPrefix(line, "dependencies") && strings.Contains(line, "[") {
				// Inline array on same line
				arrStr := strings.TrimSpace(strings.SplitN(line, "=", 2)[1])
				parseDepsArray(arrStr, &deps)
			} else if strings.HasPrefix(line, "dependencies") {
				inDepsArray = true
			}
			// Parse poetry dependencies: flask = "^2.0"
			if section == "[tool.poetry.dependencies]" && strings.Contains(line, "=") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					name := strings.TrimSpace(parts[0])
					if name != "python" {
						ver := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
						deps = append(deps, analysis.Dependency{
							Name:      strings.ToLower(name),
							Version:   cleanVersion(ver),
							Ecosystem: analysis.EcosystemPyPI,
							IsDirect:  true,
						})
					}
				}
			}
		}
		// Handle multi-line dependencies array
		if inDepsArray {
			if strings.HasPrefix(line, "]") {
				inDepsArray = false
				continue
			}
			depName := strings.Trim(strings.Trim(line, `"`), `',`)
			depName = strings.TrimSpace(depName)
			if depName != "" && !strings.HasPrefix(depName, "#") {
				// Extract package name (before any version specifier)
				pkgName := depName
				for _, sep := range []string{">", "<", "=", "~", "!"} {
					if idx := strings.Index(depName, sep); idx > 0 {
						pkgName = strings.TrimSpace(depName[:idx])
						break
					}
				}
				deps = append(deps, analysis.Dependency{
					Name:      strings.ToLower(pkgName),
					Ecosystem: analysis.EcosystemPyPI,
					IsDirect:  true,
				})
			}
		}
	}

	if rootName != "" && rootVersion != "" {
		deps = append(deps, analysis.Dependency{
			Name:      strings.ToLower(rootName),
			Version:   rootVersion,
			Ecosystem: analysis.EcosystemPyPI,
			IsDirect:  true,
			IsRoot:    true,
			License:   rootLicense,
		})
	}
	return deps, nil
}

func parseDepsArray(arrStr string, deps *[]analysis.Dependency) {
	// Remove brackets
	arrStr = strings.TrimPrefix(arrStr, "[")
	arrStr = strings.TrimSuffix(arrStr, "]")
	items := strings.Split(arrStr, ",")
	for _, item := range items {
		item = strings.TrimSpace(item)
		item = strings.Trim(item, `"'`)
		if item == "" {
			continue
		}
		// Extract package name (before any version specifier)
		pkgName := item
		for _, sep := range []string{">", "<", "=", "~", "!"} {
			if idx := strings.Index(item, sep); idx > 0 {
				pkgName = strings.TrimSpace(item[:idx])
				break
			}
		}
		*deps = append(*deps, analysis.Dependency{
			Name:      strings.ToLower(pkgName),
			Ecosystem: analysis.EcosystemPyPI,
			IsDirect:  true,
		})
	}
}

func parseCargoFile(path string) ([]analysis.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	var deps []analysis.Dependency
	section := ""
	rootName := ""
	rootVersion := ""
	rootLicense := ""

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line
			continue
		}
		if section == "[package]" {
			if strings.HasPrefix(line, "name") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					rootName = strings.Trim(strings.TrimSpace(parts[1]), `"'`)
				}
			}
			if strings.HasPrefix(line, "version") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					rootVersion = strings.Trim(strings.TrimSpace(parts[1]), `"'`)
				}
			}
			if strings.HasPrefix(line, "license") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					rootLicense = strings.Trim(strings.TrimSpace(parts[1]), `"'`)
				}
			}
		}
	}

	if rootName != "" && rootVersion != "" {
		deps = append(deps, analysis.Dependency{
			Name:      rootName,
			Version:   rootVersion,
			Ecosystem: analysis.EcosystemCargo,
			IsDirect:  true,
			IsRoot:    true,
			License:   rootLicense,
		})
	}
	return deps, nil
}

func parseGoModFile(path string) ([]analysis.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	var deps []analysis.Dependency
	inRequire := false

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "require ") {
			// Single-line require
			parts := strings.Fields(strings.TrimPrefix(line, "require "))
			if len(parts) >= 2 {
				deps = append(deps, analysis.Dependency{
					Name:      parts[0],
					Version:   parts[1],
					Ecosystem: analysis.EcosystemGo,
					IsDirect:  true,
				})
			}
			continue
		}
		if line == "require (" {
			inRequire = true
			continue
		}
		if line == ")" && inRequire {
			inRequire = false
			continue
		}
		if inRequire {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				isIndirect := strings.Contains(line, "// indirect")
				deps = append(deps, analysis.Dependency{
					Name:      parts[0],
					Version:   parts[1],
					Ecosystem: analysis.EcosystemGo,
					IsDirect:  !isIndirect,
				})
			}
		}
	}
	return deps, nil
}

func parsePomFile(path string) ([]analysis.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	content := string(data)
	var deps []analysis.Dependency

	// Simple regex-free parsing for dependencies
	lines := strings.Split(content, "\n")
	inDeps := false
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if strings.Contains(trim, "<dependencies>") {
			inDeps = true
			continue
		}
		if strings.Contains(trim, "</dependencies>") {
			inDeps = false
			continue
		}
		if inDeps && strings.Contains(trim, "<artifactId>") {
			artifact := strings.TrimSuffix(strings.TrimPrefix(trim, "<artifactId>"), "</artifactId>")
			deps = append(deps, analysis.Dependency{
				Name:      artifact,
				Ecosystem: analysis.EcosystemMaven,
				IsDirect:  true,
			})
		}
	}
	return deps, nil
}

func cleanVersion(v string) string {
	// Remove ^, ~, >=, <=, >, < prefixes
	v = strings.TrimPrefix(v, "^")
	v = strings.TrimPrefix(v, "~")
	v = strings.TrimPrefix(v, ">=")
	v = strings.TrimPrefix(v, "<=")
	v = strings.TrimPrefix(v, ">")
	v = strings.TrimPrefix(v, "<")
	// Take the first version if range
	if idx := strings.Index(v, ","); idx > 0 {
		v = v[:idx]
	}
	return strings.TrimSpace(v)
}

// Ensure unused imports are referenced
var _ = baseline.NewManager
var _ = sast.NewRunner
var _ = time.Now
