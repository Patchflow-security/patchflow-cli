package sbom

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
)

func sampleResult() *analysis.AnalysisResult {
	return &analysis.AnalysisResult{
		ScanID:      "test-scan-001",
		ProjectRoot: "/tmp/test-project",
		Branch:      "main",
		CommitSHA:   "abc123",
		Dependencies: []analysis.Dependency{
			{Name: "express", Version: "4.18.0", Ecosystem: analysis.EcosystemNPM, IsDirect: true, License: "MIT"},
			{Name: "lodash", Version: "4.17.21", Ecosystem: analysis.EcosystemNPM, IsDirect: false},
			{Name: "github.com/spf13/cobra", Version: "v1.0.0", Ecosystem: analysis.EcosystemGo, IsDirect: true, License: "Apache-2.0"},
			{Name: "flask", Version: "3.0.0", Ecosystem: analysis.EcosystemPyPI, IsDirect: true, License: "BSD-3-Clause"},
		},
		Findings: []analysis.Finding{
			{
				ID:                   "sca-npm-express-GHSA-1234",
				Type:                 analysis.TypeSCA,
				Severity:             analysis.SeverityHigh,
				PackageName:          "express",
				PackageVersion:       "4.18.0",
				CVEID:                "CVE-2024-1234",
				AdvisoryURL:          "https://osv.dev/vulnerability/GHSA-1234",
				Description:          "Express.js vulnerability",
				Reachability:         analysis.ReachabilityHigh,
				ReachabilityEvidence: []string{"Directly imported in app.js"},
			},
		},
	}
}

func TestGenerateCycloneDXJSON(t *testing.T) {
	result := sampleResult()
	cfg := GenerateConfig{Format: "cyclonedx-json", ToolVersion: "1.0.0", IncludeVEX: true}

	data, err := GenerateCycloneDXJSON(result, cfg)
	if err != nil {
		t.Fatalf("GenerateCycloneDXJSON failed: %v", err)
	}

	// Verify it's valid JSON
	var bom map[string]interface{}
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Check required fields
	if bom["bomFormat"] != "CycloneDX" {
		t.Errorf("expected bomFormat=CycloneDX, got %v", bom["bomFormat"])
	}
	if bom["specVersion"] != "1.5" {
		t.Errorf("expected specVersion=1.5, got %v", bom["specVersion"])
	}

	// Check components
	components, ok := bom["components"].([]interface{})
	if !ok {
		t.Fatal("expected components array")
	}
	if len(components) != 4 {
		t.Errorf("expected 4 components, got %d", len(components))
	}

	// Check vulnerabilities (VEX)
	vulns, ok := bom["vulnerabilities"].([]interface{})
	if !ok {
		t.Fatal("expected vulnerabilities array")
	}
	if len(vulns) != 1 {
		t.Errorf("expected 1 vulnerability, got %d", len(vulns))
	}
}

func TestGenerateSPDXJSON(t *testing.T) {
	result := sampleResult()
	cfg := GenerateConfig{Format: "spdx-json", ToolVersion: "1.0.0"}

	data, err := GenerateSPDXJSON(result, cfg)
	if err != nil {
		t.Fatalf("GenerateSPDXJSON failed: %v", err)
	}

	// Verify it's valid JSON
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if doc["spdxVersion"] != "SPDX-2.3" {
		t.Errorf("expected spdxVersion=SPDX-2.3, got %v", doc["spdxVersion"])
	}

	packages, ok := doc["packages"].([]interface{})
	if !ok {
		t.Fatal("expected packages array")
	}
	// 1 root + 4 deps = 5
	if len(packages) != 5 {
		t.Errorf("expected 5 packages, got %d", len(packages))
	}

	// Check relationships exist
	rels, ok := doc["relationships"].([]interface{})
	if !ok {
		t.Fatal("expected relationships array")
	}
	if len(rels) < 4 {
		t.Errorf("expected at least 4 relationships, got %d", len(rels))
	}
}

func TestGenerateVEXJSON(t *testing.T) {
	result := sampleResult()
	cfg := GenerateConfig{Format: "vex-json", ToolVersion: "1.0.0", IncludeVEX: true}

	data, err := GenerateVEXJSON(result, cfg)
	if err != nil {
		t.Fatalf("GenerateVEXJSON failed: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if doc["bomFormat"] != "CycloneDX" {
		t.Errorf("expected bomFormat=CycloneDX, got %v", doc["bomFormat"])
	}

	vulns, ok := doc["vulnerabilities"].([]interface{})
	if !ok {
		t.Fatal("expected vulnerabilities array")
	}
	if len(vulns) != 1 {
		t.Errorf("expected 1 vulnerability, got %d", len(vulns))
	}

	// Check the vulnerability has analysis (VEX statement)
	vuln := vulns[0].(map[string]interface{})
	analysisData, ok := vuln["analysis"].(map[string]interface{})
	if !ok {
		t.Fatal("expected analysis in vulnerability")
	}
	if analysisData["state"] != "exploitable" {
		t.Errorf("expected state=exploitable, got %v", analysisData["state"])
	}
}

func TestGenerateVEXNotAffected(t *testing.T) {
	result := sampleResult()
	result.Findings[0].Reachability = analysis.ReachabilityNone

	cfg := GenerateConfig{Format: "vex-json", ToolVersion: "1.0.0", IncludeVEX: true}
	data, err := GenerateVEXJSON(result, cfg)
	if err != nil {
		t.Fatalf("GenerateVEXJSON failed: %v", err)
	}

	var doc map[string]interface{}
	json.Unmarshal(data, &doc)
	vulns := doc["vulnerabilities"].([]interface{})
	vuln := vulns[0].(map[string]interface{})
	analysisData := vuln["analysis"].(map[string]interface{})
	if analysisData["state"] != "not_affected" {
		t.Errorf("expected state=not_affected, got %v", analysisData["state"])
	}
}

func TestClassifyLicense(t *testing.T) {
	tests := []struct {
		license  string
		category LicenseCategory
		risk     LicenseRisk
	}{
		{"MIT", LicenseCategoryPermissive, LicenseRiskLow},
		{"Apache-2.0", LicenseCategoryPermissive, LicenseRiskLow},
		{"BSD-3-Clause", LicenseCategoryPermissive, LicenseRiskLow},
		{"ISC", LicenseCategoryPermissive, LicenseRiskLow},
		{"0BSD", LicenseCategoryPermissive, LicenseRiskLow},
		{"BlueOak-1.0.0", LicenseCategoryPermissive, LicenseRiskLow},
		{"Ruby license", LicenseCategoryPermissive, LicenseRiskLow},
		{"Python-2.0", LicenseCategoryPermissive, LicenseRiskLow},
		{"GPL-3.0", LicenseCategoryCopyleft, LicenseRiskHigh},
		{"AGPL-3.0", LicenseCategoryCopyleft, LicenseRiskHigh},
		{"LGPL-2.1", LicenseCategoryWeakCopyleft, LicenseRiskMedium},
		{"MPL-2.0", LicenseCategoryWeakCopyleft, LicenseRiskMedium},
		{"", LicenseCategoryUnknown, LicenseRiskCritical},
		{"UNLICENSED", LicenseCategoryProprietary, LicenseRiskCritical},
		{"proprietary", LicenseCategoryProprietary, LicenseRiskCritical},
	}

	for _, tt := range tests {
		cat, risk := ClassifyLicense(tt.license)
		if cat != tt.category {
			t.Errorf("ClassifyLicense(%q): category=%s, want %s", tt.license, cat, tt.category)
		}
		if risk != tt.risk {
			t.Errorf("ClassifyLicense(%q): risk=%s, want %s", tt.license, risk, tt.risk)
		}
	}
}

func TestExtractLicenses(t *testing.T) {
	deps := []analysis.Dependency{
		{Name: "pkg1", License: "MIT"},
		{Name: "pkg2", License: "GPL-3.0"},
		{Name: "pkg3", License: ""},
	}
	infos := ExtractLicenses(deps)
	if len(infos) != 3 {
		t.Fatalf("expected 3 license infos, got %d", len(infos))
	}
	if infos[0].Category != LicenseCategoryPermissive {
		t.Errorf("pkg1 should be permissive, got %s", infos[0].Category)
	}
	if infos[1].Risk != LicenseRiskHigh {
		t.Errorf("pkg2 should be high risk, got %s", infos[1].Risk)
	}
	if infos[2].Category != LicenseCategoryUnknown {
		t.Errorf("pkg3 should be unknown, got %s", infos[2].Category)
	}
}

func TestSummarizeLicenses(t *testing.T) {
	infos := []LicenseInfo{
		{RawLicense: "MIT", Category: LicenseCategoryPermissive, Risk: LicenseRiskLow},
		{RawLicense: "GPL-3.0", Category: LicenseCategoryCopyleft, Risk: LicenseRiskHigh},
		{RawLicense: "", Category: LicenseCategoryUnknown, Risk: LicenseRiskCritical},
	}
	summary := SummarizeLicenses(infos)
	if summary.Total != 3 {
		t.Errorf("expected total=3, got %d", summary.Total)
	}
	if summary.WithLicense != 2 {
		t.Errorf("expected withLicense=2, got %d", summary.WithLicense)
	}
	if summary.NoLicense != 1 {
		t.Errorf("expected noLicense=1, got %d", summary.NoLicense)
	}
	if summary.ByCategory[LicenseCategoryPermissive] != 1 {
		t.Errorf("expected 1 permissive, got %d", summary.ByCategory[LicenseCategoryPermissive])
	}
	if len(summary.HighRisk) != 2 {
		t.Errorf("expected 2 high risk, got %d", len(summary.HighRisk))
	}
}

func TestBuildDepGraph(t *testing.T) {
	result := sampleResult()
	graph := BuildDepGraph(result)

	if graph.Root == nil {
		t.Fatal("expected root node")
	}
	if len(graph.Root.Children) == 0 {
		t.Fatal("expected ecosystem children")
	}

	// Should have 3 ecosystem nodes (npm, Go, PyPI)
	if len(graph.Root.Children) != 3 {
		t.Errorf("expected 3 ecosystem children, got %d", len(graph.Root.Children))
	}
}

func TestRenderTree(t *testing.T) {
	result := sampleResult()
	graph := BuildDepGraph(result)
	tree := graph.RenderTree()

	if !strings.Contains(tree, "test-project") {
		t.Error("tree should contain project name")
	}
	if !strings.Contains(tree, "express") {
		t.Error("tree should contain express")
	}
	if !strings.Contains(tree, "cobra") {
		t.Error("tree should contain cobra")
	}
}

func TestRenderDOT(t *testing.T) {
	result := sampleResult()
	graph := BuildDepGraph(result)
	dot := graph.RenderDOT()

	if !strings.Contains(dot, "digraph") {
		t.Error("DOT should contain 'digraph'")
	}
	if !strings.Contains(dot, "express") {
		t.Error("DOT should contain express")
	}
}

func TestPurlFor(t *testing.T) {
	tests := []struct {
		dep  analysis.Dependency
		purl string
	}{
		{analysis.Dependency{Name: "express", Version: "4.18.0", Ecosystem: analysis.EcosystemNPM}, "pkg:npm/express@4.18.0"},
		{analysis.Dependency{Name: "flask", Version: "3.0.0", Ecosystem: analysis.EcosystemPyPI}, "pkg:pypi/flask@3.0.0"},
		{analysis.Dependency{Name: "github.com/spf13/cobra", Version: "v1.0.0", Ecosystem: analysis.EcosystemGo}, "pkg:golang/github.com/spf13/cobra@v1.0.0"},
		{analysis.Dependency{Name: "serde", Version: "1.0", Ecosystem: analysis.EcosystemCargo}, "pkg:cargo/serde@1.0"},
	}
	for _, tt := range tests {
		got := purlFor(tt.dep)
		if got != tt.purl {
			t.Errorf("purlFor(%+v) = %s, want %s", tt.dep, got, tt.purl)
		}
	}
}
