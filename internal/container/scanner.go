// Package container provides container image scanning by wrapping Trivy as
// an external analyzer. This gives PatchFlow full container image scanning
// capabilities (OS packages, language dependencies, misconfigurations)
// without reimplementing Trivy's image analysis engine.
//
// The strategy is the same as for gosec, bandit, semgrep, gitleaks, and
// checkov: leverage the best-in-class external tool when available, and
// present results through PatchFlow's unified finding format.
package container

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
)

// ImageScanner scans container images for vulnerabilities and misconfigurations.
type ImageScanner struct {
	TrivyBinary string
	Timeout     time.Duration
}

// NewImageScanner creates a container image scanner that uses Trivy.
func NewImageScanner() *ImageScanner {
	return &ImageScanner{
		TrivyBinary: "trivy",
		Timeout:     10 * time.Minute,
	}
}

// IsAvailable returns true if Trivy is installed and available.
func (s *ImageScanner) IsAvailable() bool {
	_, err := exec.LookPath(s.TrivyBinary)
	return err == nil
}

// ScanResult holds the output of a container image scan.
type ScanResult struct {
	Findings []analysis.Finding
	Target   string
}

// ScanImage scans a container image for vulnerabilities and misconfigurations.
// The image can be a local image (e.g., "myapp:latest") or a remote image
// from a registry (e.g., "nginx:1.21").
func (s *ImageScanner) ScanImage(ctx context.Context, image string) (*ScanResult, error) {
	if !s.IsAvailable() {
		return nil, fmt.Errorf("trivy is not installed — install it to enable container image scanning")
	}
	if err := validateImageRef(image); err != nil {
		return nil, err
	}

	// Run trivy image --format json --quiet <image>
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	// Trivy is an intentional external scanner invocation; arguments are not passed through a shell.
	cmd := exec.CommandContext(ctx, s.TrivyBinary, "image", "--format", "json", "--quiet", "--", image) // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	output, err := cmd.Output()
	if err != nil {
		// Trivy returns non-zero when vulnerabilities are found
		if len(output) == 0 {
			return nil, fmt.Errorf("trivy image scan failed: %w", err)
		}
	}

	// Parse Trivy JSON output
	var trivyReport trivyImageReport
	if err := json.Unmarshal(output, &trivyReport); err != nil {
		return nil, fmt.Errorf("failed to parse trivy output: %w", err)
	}

	var findings []analysis.Finding
	for _, result := range trivyReport.Results {
		// Vulnerabilities
		for _, vuln := range result.Vulnerabilities {
			finding := analysis.Finding{
				ID:             fmt.Sprintf("container-vuln-%s-%s-%s", vuln.VulnerabilityID, vuln.PkgName, vuln.InstalledVersion),
				Type:           analysis.TypeSCA,
				Analyzer:       "trivy-image",
				Severity:       normalizeTrivySeverity(vuln.Severity),
				Confidence:     analysis.ConfidenceHigh,
				Title:          fmt.Sprintf("%s: %s in %s@%s", vuln.VulnerabilityID, vuln.PkgName, vuln.PkgName, vuln.InstalledVersion),
				Description:    vuln.Description,
				PackageName:    vuln.PkgName,
				PackageVersion: vuln.InstalledVersion,
				FixedVersion:   vuln.FixedVersion,
				CVEID:          vuln.VulnerabilityID,
				FilePath:       vuln.PkgPath,
				AdvisoryURL:    vuln.PrimaryURL,
				Recommendation: generateFixRecommendation(vuln),
				DetectedAt:     time.Now(),
			}
			findings = append(findings, finding)
		}

		// Misconfigurations
		for _, misconf := range result.Misconfigurations {
			finding := analysis.Finding{
				ID:             fmt.Sprintf("container-misconf-%s-%s-%d", misconf.ID, result.Target, misconf.StartLine),
				Type:           analysis.TypeIaC,
				Analyzer:       "trivy-image",
				Severity:       normalizeTrivySeverity(misconf.Severity),
				Confidence:     analysis.ConfidenceHigh,
				Title:          misconf.Title,
				Description:    misconf.Description,
				FilePath:       result.Target,
				LineStart:      misconf.StartLine,
				LineEnd:        misconf.EndLine,
				RuleID:         misconf.ID,
				Recommendation: misconf.Resolution,
				DetectedAt:     time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	return &ScanResult{
		Findings: findings,
		Target:   trivyReport.ArtifactName,
	}, nil
}

func validateImageRef(image string) error {
	if strings.TrimSpace(image) == "" {
		return fmt.Errorf("container image reference cannot be empty")
	}
	if strings.HasPrefix(image, "-") {
		return fmt.Errorf("container image reference cannot start with '-'")
	}
	if strings.ContainsAny(image, "\x00\r\n") {
		return fmt.Errorf("container image reference contains invalid control characters")
	}
	return nil
}

// generateFixRecommendation generates a fix recommendation for a vulnerability.
func generateFixRecommendation(v trivyVulnerability) string {
	if v.FixedVersion != "" {
		return fmt.Sprintf("Upgrade %s from %s to %s or later", v.PkgName, v.InstalledVersion, v.FixedVersion)
	}
	return fmt.Sprintf("No fix available for %s@%s. Consider replacing this package or mitigating the vulnerability.", v.PkgName, v.InstalledVersion)
}

// normalizeTrivySeverity converts Trivy severity strings to analysis.Severity.
func normalizeTrivySeverity(s string) analysis.Severity {
	switch s {
	case "CRITICAL":
		return analysis.SeverityCritical
	case "HIGH":
		return analysis.SeverityHigh
	case "MEDIUM":
		return analysis.SeverityMedium
	case "LOW":
		return analysis.SeverityLow
	case "UNKNOWN":
		return analysis.SeverityInfo
	default:
		return analysis.SeverityInfo
	}
}

// ─── Trivy JSON types ────────────────────────────────────────────────

type trivyImageReport struct {
	ArtifactName string        `json:"ArtifactName"`
	ArtifactType string        `json:"ArtifactType"`
	Results      []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target            string               `json:"Target"`
	Class             string               `json:"Class"`
	Type              string               `json:"Type"`
	Vulnerabilities   []trivyVulnerability `json:"Vulnerabilities"`
	Misconfigurations []trivyMisconf       `json:"Misconfigurations"`
}

type trivyVulnerability struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Description      string `json:"Description"`
	PrimaryURL       string `json:"PrimaryURL"`
	PkgPath          string `json:"PkgPath"`
	Title            string `json:"Title"`
}

type trivyMisconf struct {
	ID          string `json:"ID"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	Severity    string `json:"Severity"`
	Resolution  string `json:"Resolution"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
}
