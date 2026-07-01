// Package registry provides package registry metadata lookup and license
// analysis. This file contains the LicenseAnalyzer that converts dependency
// license info into analysis.Findings for the scan pipeline.
package registry

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/sbom"
)

// LicenseResult holds the output of a license analysis run.
type LicenseResult struct {
	Findings []analysis.Finding
	Summary  sbom.LicenseSummary
	Infos    []sbom.LicenseInfo
	Enriched int // number of dependencies enriched with registry metadata
}

// AnalysisSummary converts the SBOM license summary into the stable analysis
// report shape used by JSON and markdown renderers.
func (r *LicenseResult) AnalysisSummary() *analysis.LicenseSummary {
	if r == nil {
		return nil
	}
	summary := &analysis.LicenseSummary{
		Total:       r.Summary.Total,
		WithLicense: r.Summary.WithLicense,
		NoLicense:   r.Summary.NoLicense,
		ByCategory:  make(map[string]int, len(r.Summary.ByCategory)),
		ByRisk:      make(map[string]int, len(r.Summary.ByRisk)),
	}
	for category, count := range r.Summary.ByCategory {
		summary.ByCategory[string(category)] = count
	}
	for risk, count := range r.Summary.ByRisk {
		summary.ByRisk[string(risk)] = count
	}
	return summary
}

// LicenseAnalyzer combines manifest-extracted licenses with registry metadata
// lookup and produces license findings for the scan pipeline.
type LicenseAnalyzer struct {
	Client *MetadataClient
	// Policy defines which license categories should be treated as violations.
	// When set, license findings in these categories are elevated to CRITICAL
	// severity and the scan will fail (when used with --fail-on critical).
	// Categories: "gpl", "agpl", "copyleft", "weak_copyleft", "proprietary",
	// "unknown", "permissive" (rarely used).
	Policy []string
}

// NewLicenseAnalyzer creates a license analyzer with a registry metadata client.
func NewLicenseAnalyzer() *LicenseAnalyzer {
	return &LicenseAnalyzer{
		Client: NewMetadataClient(),
	}
}

// SetCache attaches a disk cache to the registry metadata client.
func (a *LicenseAnalyzer) SetCache(cache *Cache) {
	a.Client.SetCache(cache)
}

// SetPolicy sets the license policy. The policy is a list of license categories
// or specific license IDs that should be treated as violations.
// Supported categories: gpl, agpl, copyleft, weak_copyleft, proprietary, unknown.
// Supported specific licenses: GPL-2.0, GPL-3.0, AGPL-3.0, LGPL-3.0, etc.
func (a *LicenseAnalyzer) SetPolicy(policy []string) {
	a.Policy = policy
}

// policyMatches returns true if a license info matches the configured policy.
func (a *LicenseAnalyzer) policyMatches(info sbom.LicenseInfo) bool {
	if len(a.Policy) == 0 {
		return false
	}
	for _, p := range a.Policy {
		p = strings.ToLower(strings.TrimSpace(p))
		switch p {
		case "gpl":
			if info.Category == sbom.LicenseCategoryCopyleft &&
				(strings.Contains(strings.ToLower(info.RawLicense), "gpl") ||
					strings.Contains(strings.ToLower(info.RawLicense), "general public license")) {
				return true
			}
		case "agpl":
			if info.Category == sbom.LicenseCategoryCopyleft &&
				strings.Contains(strings.ToLower(info.RawLicense), "agpl") {
				return true
			}
		case "copyleft":
			if info.Category == sbom.LicenseCategoryCopyleft {
				return true
			}
		case "weak_copyleft", "lgpl":
			if info.Category == sbom.LicenseCategoryWeakCopyleft {
				return true
			}
		case "proprietary":
			if info.Category == sbom.LicenseCategoryProprietary {
				return true
			}
		case "unknown":
			if info.Category == sbom.LicenseCategoryUnknown {
				return true
			}
		case "permissive":
			if info.Category == sbom.LicenseCategoryPermissive {
				return true
			}
		default:
			// Check if the policy entry is a specific license ID (e.g., "GPL-3.0")
			if strings.EqualFold(info.RawLicense, p) {
				return true
			}
		}
	}
	return false
}

// Analyze runs license analysis on a list of dependencies.
// It:
//  1. Fetches missing license info from package registries (npm, PyPI, Maven, etc.)
//  2. Enriches the dependency list with license strings
//  3. Classifies each license using sbom.ClassifyLicense
//  4. Generates analysis.Finding objects for high/critical risk licenses
//  5. Returns a summary and the enriched dependencies
func (a *LicenseAnalyzer) Analyze(ctx context.Context, deps []analysis.Dependency) (*LicenseResult, error) {
	// Step 1: Fetch missing license info from registries
	licenseMap := a.Client.FetchLicenses(ctx, deps)
	enriched := 0

	// Step 2: Enrich dependencies with fetched license info
	enrichedDeps := make([]analysis.Dependency, len(deps))
	copy(enrichedDeps, deps)
	for i := range enrichedDeps {
		if enrichedDeps[i].License == "" {
			if lic, ok := licenseMap[depKey(enrichedDeps[i])]; ok && lic != "" {
				enrichedDeps[i].License = lic
				enriched++
			}
		}
	}

	// Step 3: Extract and classify licenses
	licenseInfos := sbom.ExtractLicenses(enrichedDeps)
	summary := sbom.SummarizeLicenses(licenseInfos)

	// Step 4: Generate findings for high/critical risk licenses and policy violations
	var findings []analysis.Finding
	for _, info := range licenseInfos {
		// Check if this license matches the configured policy
		policyViolation := a.policyMatches(info)
		if info.Dependency.IsRoot && info.RawLicense == "" && !policyViolation {
			continue
		}

		// Generate finding if: (a) high/critical risk, or (b) policy violation
		if info.Risk == sbom.LicenseRiskHigh || info.Risk == sbom.LicenseRiskCritical || policyViolation {
			severity := licenseRiskToSeverity(info.Risk)
			if policyViolation {
				severity = analysis.SeverityCritical // Policy violations are always critical
			}
			finding := analysis.Finding{
				ID:             fmt.Sprintf("license-%s-%s-%s", info.Dependency.Ecosystem, info.Dependency.Name, info.Dependency.Version),
				Type:           analysis.TypeLicense,
				Analyzer:       "registry-license",
				Severity:       severity,
				Confidence:     analysis.ConfidenceHigh,
				Title:          licenseTitle(info),
				Description:    licenseDescription(info),
				PackageName:    info.Dependency.Name,
				PackageVersion: info.Dependency.Version,
				FilePath:       info.Dependency.ManifestPath,
				Evidence:       info.RawLicense,
				Recommendation: licenseRecommendation(info),
				DetectedAt:     now(),
			}
			if policyViolation {
				finding.Description = fmt.Sprintf("LICENSE POLICY VIOLATION: %s. %s",
					finding.Description, "This license is restricted by the --license-policy flag.")
			}
			findings = append(findings, finding)
		}
	}

	return &LicenseResult{
		Findings: findings,
		Summary:  summary,
		Infos:    licenseInfos,
		Enriched: enriched,
	}, nil
}

// licenseRiskToSeverity maps license risk to finding severity.
func licenseRiskToSeverity(risk sbom.LicenseRisk) analysis.Severity {
	switch risk {
	case sbom.LicenseRiskCritical:
		return analysis.SeverityCritical
	case sbom.LicenseRiskHigh:
		return analysis.SeverityHigh
	case sbom.LicenseRiskMedium:
		return analysis.SeverityMedium
	case sbom.LicenseRiskLow:
		return analysis.SeverityLow
	default:
		return analysis.SeverityInfo
	}
}

// licenseDisplay returns a human-readable license string.
func licenseDisplay(info sbom.LicenseInfo) string {
	if info.RawLicense != "" {
		return info.RawLicense
	}
	return "no license"
}

func licenseTitle(info sbom.LicenseInfo) string {
	if info.RawLicense == "" {
		return fmt.Sprintf("%s@%s has no license information (%s)", info.Dependency.Name, info.Dependency.Version, info.Category)
	}
	return fmt.Sprintf("%s@%s uses %s license (%s)", info.Dependency.Name, info.Dependency.Version, info.RawLicense, info.Category)
}

// licenseDescription generates a description for a license finding.
func licenseDescription(info sbom.LicenseInfo) string {
	dep := info.Dependency
	switch info.Category {
	case sbom.LicenseCategoryCopyleft:
		return fmt.Sprintf("Package %s@%s is licensed under %s (strong copyleft). "+
			"Strong copyleft licenses (GPL, AGPL) require derivative works to be released under the same license. "+
			"Verify this is compatible with your project's distribution model.",
			dep.Name, dep.Version, info.RawLicense)
	case sbom.LicenseCategoryProprietary:
		return fmt.Sprintf("Package %s@%s has a proprietary or unlicensed status (%s). "+
			"Proprietary or unlicensed code may have legal restrictions on use, modification, or distribution. "+
			"Verify you have a valid license before using this package.",
			dep.Name, dep.Version, licenseDisplay(info))
	case sbom.LicenseCategoryUnknown:
		return fmt.Sprintf("Package %s@%s has no license information available. "+
			"Packages without a clear license cannot be safely used in production. "+
			"Contact the package author or check the source repository for license terms.",
			dep.Name, dep.Version)
	case sbom.LicenseCategoryWeakCopyleft:
		return fmt.Sprintf("Package %s@%s is licensed under %s (weak copyleft). "+
			"Weak copyleft licenses (LGPL, MPL, EPL) allow linking from proprietary code but "+
			"require modifications to the licensed component to be shared.",
			dep.Name, dep.Version, info.RawLicense)
	default:
		return fmt.Sprintf("Package %s@%s is licensed under %s.",
			dep.Name, dep.Version, info.RawLicense)
	}
}

// licenseRecommendation generates a recommendation for a license finding.
func licenseRecommendation(info sbom.LicenseInfo) string {
	switch info.Category {
	case sbom.LicenseCategoryCopyleft:
		return fmt.Sprintf("Review GPL/AGPL compliance obligations. If your project is not "+
			"open-source, consider replacing %s with a permissively-licensed alternative.", info.Dependency.Name)
	case sbom.LicenseCategoryProprietary:
		return fmt.Sprintf("Obtain a valid commercial license for %s or replace with an "+
			"open-source alternative.", info.Dependency.Name)
	case sbom.LicenseCategoryUnknown:
		return fmt.Sprintf("Verify the license of %s before use. Check the source repository "+
			"or contact the maintainer. Consider replacing with a package that has a clear license.",
			info.Dependency.Name)
	case sbom.LicenseCategoryWeakCopyleft:
		return fmt.Sprintf("Review LGPL/MPL/EPL compliance obligations for %s. Modifications "+
			"to this package must be shared under the same license.", info.Dependency.Name)
	default:
		return ""
	}
}

// now returns the current time. Wrapped in a variable for testing.
var now = func() time.Time { return time.Now() }
