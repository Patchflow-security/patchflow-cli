// License scanning and classification.
// Extracts license information from dependency manifests and classifies
// licenses into risk categories for policy enforcement.
package sbom

import (
	"strings"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
)

// LicenseCategory represents the risk category of a license.
type LicenseCategory string

const (
	LicenseCategoryPermissive   LicenseCategory = "permissive"    // MIT, Apache-2.0, BSD-*, ISC
	LicenseCategoryCopyleft     LicenseCategory = "copyleft"      // GPL-*, AGPL-*, LGPL-*
	LicenseCategoryWeakCopyleft LicenseCategory = "weak_copyleft" // MPL-*, EPL-*, LGPL-*
	LicenseCategoryProprietary  LicenseCategory = "proprietary"   // commercial, proprietary
	LicenseCategoryUnknown      LicenseCategory = "unknown"       // no license info
)

// LicenseRisk represents the risk level of a license.
type LicenseRisk string

const (
	LicenseRiskLow      LicenseRisk = "low"      // permissive licenses
	LicenseRiskMedium   LicenseRisk = "medium"   // weak copyleft
	LicenseRiskHigh     LicenseRisk = "high"     // strong copyleft
	LicenseRiskCritical LicenseRisk = "critical" // proprietary or unknown
)

// LicenseInfo holds classified license information for a dependency.
type LicenseInfo struct {
	Dependency analysis.Dependency
	RawLicense string
	Category   LicenseCategory
	Risk       LicenseRisk
	SPDXIDs    []string // normalized SPDX license identifiers
}

// ClassifyLicense determines the category and risk of a license string.
func ClassifyLicense(license string) (LicenseCategory, LicenseRisk) {
	normalized := strings.ToUpper(strings.TrimSpace(license))
	if normalized == "" {
		return LicenseCategoryUnknown, LicenseRiskCritical
	}

	// Proprietary / commercial / unlicensed — check first to avoid
	// "UNLICENSED" matching the "UNLICENSE" permissive entry.
	if strings.Contains(normalized, "PROPRIETARY") ||
		strings.Contains(normalized, "COMMERCIAL") ||
		normalized == "UNLICENSED" {
		return LicenseCategoryProprietary, LicenseRiskCritical
	}

	// Permissive licenses
	permissive := []string{
		"MIT", "ISC", "BSD-2-CLAUSE", "BSD-3-CLAUSE", "BSD-4-CLAUSE",
		"0BSD", "BLUEOAK-1.0.0", "RUBY", "RUBY LICENSE", "PYTHON-2.0",
		"APACHE-2.0", "APACHE 2.0", "APACHE-1.0", "APACHE 1.0",
		"ZLIB", "BOOST", "BSL-1.0", "UNLICENSE", "CC0-1.0",
		"CC-BY-4.0", "CC-BY-3.0", "WTFPL", "FTL",
	}
	for _, p := range permissive {
		if normalized == p || strings.Contains(normalized, p) {
			return LicenseCategoryPermissive, LicenseRiskLow
		}
	}

	// Strong copyleft
	copyleft := []string{
		"GPL-2.0", "GPL-3.0", "GPL 2.0", "GPL 3.0",
		"AGPL-3.0", "AGPL 3.0", "AGPL-1.0",
		"EUPL-1.1", "EUPL-1.2",
	}
	for _, c := range copyleft {
		if normalized == c || strings.Contains(normalized, c) {
			return LicenseCategoryCopyleft, LicenseRiskHigh
		}
	}

	// Weak copyleft
	weakCopyleft := []string{
		"LGPL-2.0", "LGPL-2.1", "LGPL-3.0", "LGPL 2.1", "LGPL 3.0",
		"MPL-1.0", "MPL-1.1", "MPL-2.0", "MPL 2.0",
		"EPL-1.0", "EPL-2.0", "EPL 1.0", "EPL 2.0",
		"CDDL-1.0", "CDDL 1.0", "CDDL-GPL-2.0",
	}
	for _, w := range weakCopyleft {
		if normalized == w || strings.Contains(normalized, w) {
			return LicenseCategoryWeakCopyleft, LicenseRiskMedium
		}
	}

	// Default: unknown
	return LicenseCategoryUnknown, LicenseRiskCritical
}

// ExtractLicenses extracts and classifies license information from a list
// of dependencies. Returns LicenseInfo for each dependency that has a
// license (or where license info is missing).
func ExtractLicenses(deps []analysis.Dependency) []LicenseInfo {
	var result []LicenseInfo
	for _, dep := range deps {
		info := LicenseInfo{
			Dependency: dep,
			RawLicense: dep.License,
		}
		info.Category, info.Risk = ClassifyLicense(dep.License)
		if dep.License != "" {
			info.SPDXIDs = normalizeSPDXIDs(dep.License)
		}
		result = append(result, info)
	}
	return result
}

// normalizeSPDXIDs extracts SPDX license identifiers from a license string.
// Handles comma-separated, "OR", "AND", and "WITH" expressions.
func normalizeSPDXIDs(license string) []string {
	// Split on OR, AND, WITH, commas
	replaced := strings.NewReplacer(
		" OR ", "|", " or ", "|",
		" AND ", "|", " and ", "|",
		" WITH ", "|", " with ", "|",
		",", "|",
	)
	parts := strings.Split(replaced.Replace(license), "|")
	var ids []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		ids = append(ids, p)
	}
	return ids
}

// LicenseSummary provides aggregate license statistics.
type LicenseSummary struct {
	Total       int
	WithLicense int
	NoLicense   int
	ByCategory  map[LicenseCategory]int
	ByRisk      map[LicenseRisk]int
	HighRisk    []LicenseInfo
}

// SummarizeLicenses produces aggregate statistics from license info.
func SummarizeLicenses(infos []LicenseInfo) LicenseSummary {
	summary := LicenseSummary{
		Total:      len(infos),
		ByCategory: make(map[LicenseCategory]int),
		ByRisk:     make(map[LicenseRisk]int),
	}
	for _, info := range infos {
		if info.RawLicense != "" {
			summary.WithLicense++
		} else {
			summary.NoLicense++
		}
		summary.ByCategory[info.Category]++
		summary.ByRisk[info.Risk]++
		if info.Risk == LicenseRiskHigh || info.Risk == LicenseRiskCritical {
			summary.HighRisk = append(summary.HighRisk, info)
		}
	}
	return summary
}
