package scan

import (
	"encoding/json"

	"github.com/Patchflow-security/patchflow-cli/pkg/version"
)

// Report represents a minimal SARIF 2.1.0 report.
type Report struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

// Run represents a single run in a SARIF report.
type Run struct {
	Tool    Tool          `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// Tool represents the tool that produced the SARIF report.
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver represents the driver component of a tool.
type Driver struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// SARIFResult represents a single result in a SARIF run.
type SARIFResult struct {
	RuleID    string     `json:"ruleId"`
	Message   Message    `json:"message"`
	Locations []Location `json:"locations"`
}

// Message represents a message in a SARIF result.
type Message struct {
	Text string `json:"text"`
}

// Location represents a location in a SARIF result.
type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

// PhysicalLocation represents a physical location in a SARIF result.
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
}

// ArtifactLocation represents an artifact location in a SARIF result.
type ArtifactLocation struct {
	URI string `json:"uri"`
}

// ExportSARIF converts a scan.Result to a SARIF Report.
//
// Deprecated: ExportSARIF is the legacy SARIF exporter and does not emit
// tool.driver.rules, result fingerprints, or scan metadata. Prefer
// report.Generator.SARIF() (internal/report), which produces a SARIF 2.1.0
// report with rule descriptors, stable fingerprints, and invocation metadata
// for downstream deduplication. This function is retained for backward
// compatibility and will be removed in a future release.
func ExportSARIF(scanResult *Result) (*Report, error) {
	var sarifResults []SARIFResult
	for _, m := range scanResult.Manifests {
		sarifResults = append(sarifResults, SARIFResult{
			RuleID: "manifest-detection",
			Message: Message{
				Text: "Detected dependency manifest: " + m.Path,
			},
			Locations: []Location{
				{
					PhysicalLocation: PhysicalLocation{
						ArtifactLocation: ArtifactLocation{
							URI: m.Path,
						},
					},
				},
			},
		})
	}

	report := &Report{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []Run{
			{
				Tool: Tool{
					Driver: Driver{
						Name:    "PatchFlow CLI",
						Version: version.Version,
					},
				},
				Results: sarifResults,
			},
		},
	}

	return report, nil
}

// ExportJSON marshals a scan.Result to indented JSON bytes.
func ExportJSON(scanResult *Result) ([]byte, error) {
	return json.MarshalIndent(scanResult, "", "  ")
}
