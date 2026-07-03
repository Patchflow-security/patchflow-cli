package osv

import (
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
)

func TestEcosystemToOSV(t *testing.T) {
	tests := []struct {
		eco    analysis.Ecosystem
		osvEco string
	}{
		{analysis.EcosystemGo, "Go"},
		{analysis.EcosystemNPM, "npm"},
		{analysis.EcosystemPyPI, "PyPI"},
		{analysis.EcosystemCargo, "crates.io"},
		{analysis.EcosystemRubyGems, "RubyGems"},
		{analysis.EcosystemMaven, "Maven"},
		{analysis.EcosystemPackagist, "Packagist"},
		{analysis.Ecosystem("unknown"), ""},
	}
	for _, tt := range tests {
		if got := ecosystemToOSV(tt.eco); got != tt.osvEco {
			t.Errorf("ecosystemToOSV(%s) = %s, want %s", tt.eco, got, tt.osvEco)
		}
	}
}

func TestExtractSeverity(t *testing.T) {
	// Test with CVSS score
	vuln := Vulnerability{
		Severity: []Severity{
			{Type: "CVSS_V3", Score: "CVSS_V3/9.5"},
		},
	}
	if got := ExtractSeverity(vuln); got != analysis.SeverityCritical {
		t.Errorf("expected critical for CVSS 9.5, got %s", got)
	}

	// Test with medium CVSS
	vuln = Vulnerability{
		Severity: []Severity{
			{Type: "CVSS_V3", Score: "CVSS_V3/5.5"},
		},
	}
	if got := ExtractSeverity(vuln); got != analysis.SeverityMedium {
		t.Errorf("expected medium for CVSS 5.5, got %s", got)
	}

	// Test with database_specific severity
	vuln = Vulnerability{
		DatabaseSpecific: map[string]interface{}{
			"severity": "HIGH",
		},
	}
	if got := ExtractSeverity(vuln); got != analysis.SeverityHigh {
		t.Errorf("expected high from database_specific, got %s", got)
	}

	// Test with no severity info — should default to medium
	vuln = Vulnerability{}
	if got := ExtractSeverity(vuln); got != analysis.SeverityMedium {
		t.Errorf("expected medium default, got %s", got)
	}
}

func TestExtractCVEID(t *testing.T) {
	vuln := Vulnerability{
		ID:      "GHSA-1234-5678-9abc",
		Aliases: []string{"CVE-2024-1234", "GHSA-1234-5678-9abc"},
	}
	if got := ExtractCVEID(vuln); got != "CVE-2024-1234" {
		t.Errorf("expected CVE-2024-1234, got %s", got)
	}

	// No CVE alias
	vuln = Vulnerability{
		ID:      "GHSA-only",
		Aliases: []string{"GHSA-only"},
	}
	if got := ExtractCVEID(vuln); got != "" {
		t.Errorf("expected empty CVE, got %s", got)
	}
}

func TestExtractFixedVersion(t *testing.T) {
	vuln := Vulnerability{
		Affected: []Affected{
			{
				Package: &Package{Name: "test-pkg", Ecosystem: "PyPI"},
				Ranges: []Range{
					{
						Type: "ECOSYSTEM",
						Events: []Event{
							{Introduced: "1.0.0"},
							{Fixed: "2.0.0"},
						},
					},
				},
			},
		},
	}

	fixed := ExtractFixedVersion(vuln, "test-pkg", "1.5.0")
	if fixed != "2.0.0" {
		t.Errorf("expected fixed version 2.0.0, got %s", fixed)
	}
}

func TestParseCVSSScore(t *testing.T) {
	tests := []struct {
		input  string
		score  float64
	}{
		{"CVSS_V3/9.5", 9.5},
		{"7.5", 7.5},
		{"CVSS_V3/4.0", 4.0},
		{"invalid", 0},
		{"", 0},
	}
	for _, tt := range tests {
		if got := parseCVSSScore(tt.input); got != tt.score {
			t.Errorf("parseCVSSScore(%s) = %f, want %f", tt.input, got, tt.score)
		}
	}
}

func TestCVSSToSeverity(t *testing.T) {
	tests := []struct {
		score    float64
		severity analysis.Severity
	}{
		{9.0, analysis.SeverityCritical},
		{7.0, analysis.SeverityHigh},
		{4.0, analysis.SeverityMedium},
		{1.0, analysis.SeverityLow},
		{0, analysis.SeverityInfo},
	}
	for _, tt := range tests {
		if got := cvssToSeverity(tt.score); got != tt.severity {
			t.Errorf("cvssToSeverity(%f) = %s, want %s", tt.score, got, tt.severity)
		}
	}
}
