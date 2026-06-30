// SPDX SBOM generation (JSON format, SPDX spec v2.3).
// See: https://spdx.github.io/spdx-spec/v2.3/
package sbom

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
)

// spdxDocument is the SPDX JSON document structure (v2.3).
type spdxDocument struct {
	SPDXVersion       string            `json:"spdxVersion"`
	DataLicense       string            `json:"dataLicense"`
	SPDXID            string            `json:"SPDXID"`
	Name              string            `json:"name"`
	DocumentNamespace string            `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo  `json:"creationInfo"`
	Packages          []spdxPackage     `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships,omitempty"`
}

type spdxCreationInfo struct {
	Created         string   `json:"created"`
	Creators        []string `json:"creators"`
	LicenseListVer  string   `json:"licenseListVersion,omitempty"`
}

type spdxPackage struct {
	SPDXID         string         `json:"SPDXID"`
	Name           string         `json:"name"`
	VersionInfo    string         `json:"versionInfo,omitempty"`
	DownloadLocation string       `json:"downloadLocation,omitempty"`
	FilesAnalyzed  bool           `json:"filesAnalyzed"`
	LicenseConcluded string       `json:"licenseConcluded,omitempty"`
	LicenseDeclared string        `json:"licenseDeclared,omitempty"`
	CopyrightText  string         `json:"copyrightText,omitempty"`
	Supplier       string         `json:"supplier,omitempty"`
	ExternalRefs   []spdxExternalRef `json:"externalRefs,omitempty"`
	Description    string         `json:"description,omitempty"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

// GenerateSPDXJSON generates an SPDX v2.3 SBOM in JSON format.
func GenerateSPDXJSON(result *analysis.AnalysisResult, cfg GenerateConfig) ([]byte, error) {
	doc := buildSPDXDocument(result, cfg)
	return json.MarshalIndent(doc, "", "  ")
}

// buildSPDXDocument constructs the SPDX document from analysis results.
func buildSPDXDocument(result *analysis.AnalysisResult, cfg GenerateConfig) *spdxDocument {
	rootName := projectNameFromResult(result)
	rootLicense := rootLicenseFromResult(result)
	ns := fmt.Sprintf("https://patchflow.dev/spdx/%s-%d", rootName, time.Now().Unix())

	doc := &spdxDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              rootName,
		DocumentNamespace: ns,
		CreationInfo: spdxCreationInfo{
			Created: time.Now().UTC().Format(time.RFC3339),
			Creators: []string{
				"Tool: patchflow-cli-" + cfg.ToolVersion,
				"Organization: PatchFlow",
			},
			LicenseListVer: "3.21",
		},
	}

	// Root package (the project itself)
	rootPkg := spdxPackage{
		SPDXID:           "SPDXRef-Package-Root",
		Name:             rootName,
		VersionInfo:      result.CommitSHA,
		DownloadLocation: "NOASSERTION",
		FilesAnalyzed:    false,
		LicenseConcluded: spdxLicenseField(rootLicense),
		LicenseDeclared:  spdxLicenseField(rootLicense),
		CopyrightText:    "NOASSERTION",
		Description:      "Root project package",
	}
	doc.Packages = append(doc.Packages, rootPkg)

	seen := make(map[string]bool)
	for _, dep := range result.Dependencies {
		pkgID := spdxPackageID(dep.Name, dep.Version)
		if seen[pkgID] {
			continue
		}
		seen[pkgID] = true

		pkg := spdxPackage{
			SPDXID:         pkgID,
			Name:           dep.Name,
			VersionInfo:    dep.Version,
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:  false,
			LicenseConcluded: spdxLicenseField(dep.License),
			LicenseDeclared:  spdxLicenseField(dep.License),
			CopyrightText:  "NOASSERTION",
		}

		// External reference (purl)
		purl := purlFor(dep)
		if purl != "" {
			pkg.ExternalRefs = append(pkg.ExternalRefs, spdxExternalRef{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  purl,
			})
		}

		doc.Packages = append(doc.Packages, pkg)

		// Relationship: root DESCRIBES / DEPENDS_ON package
		relType := "DEPENDS_ON"
		if dep.IsRoot {
			relType = "DESCRIBES"
		}
		doc.Relationships = append(doc.Relationships, spdxRelationship{
			SPDXElementID:      "SPDXRef-Package-Root",
			RelationshipType:   relType,
			RelatedSPDXElement: pkgID,
		})
	}

	return doc
}

// spdxPackageID generates a valid SPDX package ID from name and version.
// SPDX IDs must match [A-Za-z0-9.-]+ and cannot contain spaces or special chars.
func spdxPackageID(name, version string) string {
	id := "SPDXRef-Package-" + sanitizeSPDXID(name)
	if version != "" {
		id += "-" + sanitizeSPDXID(version)
	}
	return id
}

// sanitizeSPDXID replaces characters not allowed in SPDX IDs.
func sanitizeSPDXID(s string) string {
	var b strings.Builder
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' {
			b.WriteRune(c)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// spdxLicenseField returns the SPDX license field value.
// If no license is known, returns "NOASSERTION" (SPDX convention).
func spdxLicenseField(license string) string {
	if license == "" {
		return "NOASSERTION"
	}
	return license
}
