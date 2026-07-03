// VEX (Vulnerability Exploitability eXchange) document generation.
// VEX is a companion to SBOM that communicates the exploitability status
// of vulnerabilities. See: https://www.cisa.gov/sites/default/files/docs/VEX_Use_Cases_Document_508c.pdf
//
// PatchFlow generates VEX in CycloneDX VEX format (a CycloneDX BOM with
// vulnerability analysis statements). The exploitability assessment is
// derived from PatchFlow's reachability analysis.
package sbom

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
)

// vexDocument is a CycloneDX VEX document (BOM with vulnerability analysis).
type vexDocument struct {
	BomFormat       string           `json:"bomFormat"`
	SpecVersion     string           `json:"specVersion"`
	SerialNumber    string           `json:"serialNumber"`
	Version         int              `json:"version"`
	Metadata        vexMetadata      `json:"metadata"`
	Vulnerabilities []vexVulnerability `json:"vulnerabilities"`
}

type vexMetadata struct {
	Timestamp string       `json:"timestamp"`
	Tools     []vexTool    `json:"tools"`
	Component *vexComponent `json:"component,omitempty"`
}

type vexTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type vexComponent struct {
	Type   string `json:"type"`
	BomRef string `json:"bom-ref"`
	Name   string `json:"name"`
}

type vexVulnerability struct {
	ID          string             `json:"id"`
	Source      vexSource          `json:"source"`
	Ratings     []vexRating        `json:"ratings,omitempty"`
	Affects     []vexAffect        `json:"affects"`
	Analysis    *vexAnalysis       `json:"analysis,omitempty"`
	Description string             `json:"description,omitempty"`
}

type vexSource struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

type vexRating struct {
	Severity string  `json:"severity"`
	Score    float64 `json:"score,omitempty"`
	Method   string  `json:"method,omitempty"`
}

type vexAffect struct {
	Ref string `json:"ref"`
}

// vexAnalysis is the core VEX statement — it communicates the
// exploitability status and justification.
type vexAnalysis struct {
	State         string    `json:"state"`
	Justification string    `json:"justification,omitempty"`
	Response      []string  `json:"response,omitempty"`
	Detail        string    `json:"detail,omitempty"`
	FirstIssued   string    `json:"firstIssued,omitempty"`
}

// VEX states (CycloneDX VEX spec)
const (
	VEXStateResolved       = "resolved"        // vulnerability was fixed
	VEXStateResolvedWithPID = "resolved_with_pid" // fixed with patch
	VEXStateExploitable    = "exploitable"     // vulnerability is exploitable
	VEXStateInTriage       = "in_triage"       // under investigation
	VEXStateNotAffected    = "not_affected"    // not exploitable
)

// VEX justifications (CycloneDX VEX spec)
const (
	VEXJustComponentNotPresent       = "component_not_present"
	VEXJustVulnerableCodeNotPresent  = "vulnerable_code_not_present"
	VEXJustVulnerableCodeNotInExecutePath = "vulnerable_code_not_in_execute_path"
	VEXJustVulnerableCodeCannotBeControlledByAdversary = "vulnerable_code_cannot_be_controlled_by_adversary"
	VEXJustInlineMitigationsAlreadyExist = "inline_mitigations_already_exist"
)

// GenerateVEXJSON generates a CycloneDX VEX document in JSON format.
// The VEX document contains exploitability assessments for all SCA findings,
// derived from PatchFlow's reachability analysis.
func GenerateVEXJSON(result *analysis.AnalysisResult, cfg GenerateConfig) ([]byte, error) {
	doc := buildVEXDocument(result, cfg)
	return json.MarshalIndent(doc, "", "  ")
}

// buildVEXDocument constructs the VEX document from analysis results.
func buildVEXDocument(result *analysis.AnalysisResult, cfg GenerateConfig) *vexDocument {
	rootName := projectNameFromResult(result)

	doc := &vexDocument{
		BomFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: "urn:uuid:" + result.ScanID + "-vex",
		Version:      1,
		Metadata: vexMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []vexTool{
				{
					Vendor:  "PatchFlow",
					Name:    "patchflow-cli",
					Version: cfg.ToolVersion,
				},
			},
			Component: &vexComponent{
				Type:   "application",
				BomRef: "pkg:patchflow/" + rootName,
				Name:   rootName,
			},
		},
		Vulnerabilities: []vexVulnerability{},
	}

	for _, f := range result.Findings {
		if f.Type != analysis.TypeSCA {
			continue
		}

		vuln := vexVulnerability{
			ID: vulnID(f),
			Source: vexSource{
				Name: "OSV.dev",
				URL:  f.AdvisoryURL,
			},
			Affects: []vexAffect{
				{Ref: componentRefByNameVer(f.PackageName, f.PackageVersion)},
			},
			Description: f.Description,
			Analysis:    reachabilityToVEXAnalysis(f),
		}

		vuln.Ratings = append(vuln.Ratings, vexRating{
			Severity: string(f.Severity),
			Method:   "other",
		})

		// Add response if there's a fixed version
		if f.FixedVersion != "" {
			vuln.Analysis.Response = []string{
				fmt.Sprintf("Upgrade to %s or later", f.FixedVersion),
			}
		}

		doc.Vulnerabilities = append(doc.Vulnerabilities, vuln)
	}

	return doc
}

// reachabilityToVEXAnalysis converts a finding's reachability status to a
// VEX analysis statement with appropriate state and justification.
func reachabilityToVEXAnalysis(f analysis.Finding) *vexAnalysis {
	stmt := &vexAnalysis{
		FirstIssued: time.Now().UTC().Format(time.RFC3339),
	}

	switch f.Reachability {
	case analysis.ReachabilityHigh:
		// Package is directly imported and used — exploitable
		stmt.State = VEXStateExploitable
		stmt.Detail = "Vulnerable package is directly imported in source code."
		if len(f.ReachabilityEvidence) > 0 {
			stmt.Detail += " Evidence: " + strings.Join(f.ReachabilityEvidence, "; ")
		}

	case analysis.ReachabilityMedium:
		// Direct dependency but not directly imported — likely exploitable
		stmt.State = VEXStateInTriage
		stmt.Detail = "Package is a direct dependency but no direct imports found."
		if len(f.ReachabilityEvidence) > 0 {
			stmt.Detail += " Evidence: " + strings.Join(f.ReachabilityEvidence, "; ")
		}

	case analysis.ReachabilityLow:
		// Transitive dependency — may not be exploitable
		stmt.State = VEXStateInTriage
		stmt.Justification = VEXJustVulnerableCodeNotInExecutePath
		stmt.Detail = "Package is a transitive dependency with no direct imports."

	case analysis.ReachabilityNone:
		// Not in the dependency graph at all — not affected
		stmt.State = VEXStateNotAffected
		stmt.Justification = VEXJustComponentNotPresent
		stmt.Detail = "Package not found in the dependency graph."

	default:
		// Unknown — under investigation
		stmt.State = VEXStateInTriage
		stmt.Detail = "Reachability analysis incomplete."
	}

	return stmt
}
