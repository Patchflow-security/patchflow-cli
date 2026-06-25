// Package osv provides a client for the OSV.dev public vulnerability database API.
// OSV.dev is free, requires no authentication, and supports batch queries.
// API docs: https://google.github.io/osv.dev/
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/patchflow/patchflow-cli/internal/analysis"
)

const (
	// DefaultBaseURL is the OSV.dev API endpoint.
	DefaultBaseURL = "https://api.osv.dev/v1"
	// QueryBatchPath is the batch query endpoint.
	QueryBatchPath = "/querybatch"
	// QueryPath is the single query endpoint.
	QueryPath = "/query"
	// DefaultTimeout for HTTP requests.
	DefaultTimeout = 60 * time.Second
)

// Client queries the OSV.dev vulnerability database.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewClient creates a new OSV client with default settings.
func NewClient() *Client {
	return &Client{
		BaseURL:    DefaultBaseURL,
		HTTPClient: &http.Client{Timeout: DefaultTimeout},
	}
}

// NewClientWithHTTP creates a client with a custom HTTP client (for testing).
func NewClientWithHTTP(baseURL string, httpClient *http.Client) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: DefaultTimeout}
	}
	return &Client{BaseURL: baseURL, HTTPClient: httpClient}
}

// QueryRequest is the OSV.dev query payload for a single package.
type QueryRequest struct {
	Package *Package `json:"package,omitempty"`
	Version string   `json:"version,omitempty"`
}

// Package identifies a package in the OSV.dev schema.
type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// QueryBatchRequest is the batch query payload (up to 1000 queries).
type QueryBatchRequest struct {
	Queries []QueryRequest `json:"queries"`
}

// Response is the OSV.dev response for a single query.
type Response struct {
	Vulns []Vulnerability `json:"vulns"`
}

// QueryBatchResponse is the batch query response (one Results entry per query).
type QueryBatchResponse struct {
	Results []Response `json:"results"`
}

// Vulnerability represents an OSV.dev vulnerability entry.
type Vulnerability struct {
	ID         string    `json:"id"`
	Summary    string    `json:"summary,omitempty"`
	Details    string    `json:"details,omitempty"`
	Aliases    []string  `json:"aliases,omitempty"`
	Severity   []Severity `json:"severity,omitempty"`
	Affected   []Affected `json:"affected,omitempty"`
	References []Ref     `json:"references,omitempty"`
	DatabaseSpecific map[string]interface{} `json:"database_specific,omitempty"`
}

// Severity is the OSV.dev severity entry.
type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Affected describes which versions are affected and how to fix.
type Affected struct {
	Package       *Package        `json:"package,omitempty"`
	Ranges        []Range         `json:"ranges,omitempty"`
	DatabaseSpecific map[string]interface{} `json:"database_specific,omitempty"`
}

// Range describes a version range that is affected.
type Range struct {
	Type   string    `json:"type"`
	Events []Event   `json:"events"`
}

// Event is an introduced or fixed version boundary.
type Event struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
	Limit      string `json:"limit,omitempty"`
}

// Ref is a reference URL for a vulnerability.
type Ref struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// QueryBatch queries OSV.dev for vulnerabilities affecting multiple packages.
// It sends up to 1000 queries in a single request. If more are provided,
// they are chunked automatically. The returned slice is parallel to deps:
// results[i] contains the vulnerabilities for deps[i].
func (c *Client) QueryBatch(ctx context.Context, deps []analysis.Dependency) ([][]Vulnerability, error) {
	if len(deps) == 0 {
		return nil, nil
	}

	var allResults [][]Vulnerability

	// OSV.dev batch endpoint supports up to 1000 queries per request.
	const batchSize = 1000
	for i := 0; i < len(deps); i += batchSize {
		end := i + batchSize
		if end > len(deps) {
			end = len(deps)
		}
		chunk := deps[i:end]

		queries := make([]QueryRequest, 0, len(chunk))
		for _, dep := range chunk {
			eco := ecosystemToOSV(dep.Ecosystem)
			if eco == "" || dep.Version == "" {
				queries = append(queries, QueryRequest{}) // empty = no result
				continue
			}
			queries = append(queries, QueryRequest{
				Package: &Package{
					Name:      dep.Name,
					Ecosystem: eco,
				},
				Version: dep.Version,
			})
		}

		responses, err := c.postBatch(ctx, queries)
		if err != nil {
			return nil, err
		}
		// Convert []Response to [][]Vulnerability
		for _, resp := range responses {
			allResults = append(allResults, resp.Vulns)
		}
	}

	return allResults, nil
}

// Query queries OSV.dev for a single package version.
func (c *Client) Query(ctx context.Context, name, version string, ecosystem analysis.Ecosystem) ([]Vulnerability, error) {
	eco := ecosystemToOSV(ecosystem)
	if eco == "" || version == "" {
		return nil, nil
	}

	req := QueryRequest{
		Package: &Package{Name: name, Ecosystem: eco},
		Version: version,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	url := c.BaseURL + QueryPath
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("osv query failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // no vulnerabilities found
	}
	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("osv query returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result Response
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode osv response: %w", err)
	}

	return result.Vulns, nil
}

func (c *Client) postBatch(ctx context.Context, queries []QueryRequest) ([]Response, error) {
	reqBody := QueryBatchRequest{Queries: queries}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	url := c.BaseURL + QueryBatchPath
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("osv batch query failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("osv batch query returned %d: %s", resp.StatusCode, string(respBody))
	}

	var batchResp QueryBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, fmt.Errorf("failed to decode osv batch response: %w", err)
	}

	// Ensure results length matches queries length
	if len(batchResp.Results) < len(queries) {
		// Pad with empty responses
		for i := len(batchResp.Results); i < len(queries); i++ {
			batchResp.Results = append(batchResp.Results, Response{})
		}
	}

	return batchResp.Results, nil
}

// ecosystemToOSV maps our internal ecosystem to OSV.dev ecosystem strings.
func ecosystemToOSV(eco analysis.Ecosystem) string {
	switch eco {
	case analysis.EcosystemGo:
		return "Go"
	case analysis.EcosystemNPM:
		return "npm"
	case analysis.EcosystemPyPI:
		return "PyPI"
	case analysis.EcosystemCargo:
		return "crates.io"
	case analysis.EcosystemRubyGems:
		return "RubyGems"
	case analysis.EcosystemPackagist:
		return "Packagist"
	case analysis.EcosystemMaven:
		return "Maven"
	default:
		return ""
	}
}

// ExtractSeverity derives a severity level from an OSV vulnerability.
// It checks CVSS scores first, then database_specific severity, then GHSA aliases.
func ExtractSeverity(vuln Vulnerability) analysis.Severity {
	// Check CVSS v3/v4 scores
	for _, sev := range vuln.Severity {
		score := parseCVSSScore(sev.Score)
		if score > 0 {
			return cvssToSeverity(score)
		}
	}

	// Check database_specific for severity
	if ds, ok := vuln.DatabaseSpecific["severity"]; ok {
		if s, ok := ds.(string); ok {
			return normalizeSeverity(s)
		}
	}

	// Check affected entries for database_specific severity
	for _, aff := range vuln.Affected {
		if ds, ok := aff.DatabaseSpecific["severity"]; ok {
			if s, ok := ds.(string); ok {
				return normalizeSeverity(s)
			}
		}
	}

	// Try to infer from the vulnerability ID (GHSA severities are in the summary)
	if strings.HasPrefix(vuln.ID, "GHSA") {
		return inferFromSummary(vuln.Summary)
	}

	return analysis.SeverityMedium // default to medium if unknown
}

// ExtractFixedVersion finds the fixed version for a given package in a vulnerability.
func ExtractFixedVersion(vuln Vulnerability, pkgName, version string) string {
	for _, aff := range vuln.Affected {
		if aff.Package == nil || aff.Package.Name != pkgName {
			continue
		}
		for _, r := range aff.Ranges {
			for i, e := range r.Events {
				if e.Introduced != "" && e.Introduced != "0" {
					// Check if our version is >= introduced
					if compareVersions(version, e.Introduced) >= 0 {
						// Find the next "fixed" event
						for j := i + 1; j < len(r.Events); j++ {
							if r.Events[j].Fixed != "" {
								return r.Events[j].Fixed
							}
						}
					}
				}
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}

// ExtractCVEID finds the CVE alias from a vulnerability.
func ExtractCVEID(vuln Vulnerability) string {
	for _, alias := range vuln.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			return alias
		}
	}
	return ""
}

// ExtractAdvisoryURL finds the best advisory URL from references.
func ExtractAdvisoryURL(vuln Vulnerability) string {
	for _, ref := range vuln.References {
		if ref.Type == "ADVISORY" || ref.Type == "WEB" {
			return ref.URL
		}
	}
	if len(vuln.References) > 0 {
		return vuln.References[0].URL
	}
	return ""
}

func parseCVSSScore(score string) float64 {
	// CVSS strings like "CVSS_V3/8.1" or raw vector strings
	// Try to extract a numeric score
	parts := strings.Split(score, "/")
	for _, p := range parts {
		var f float64
		if _, err := fmt.Sscanf(p, "%f", &f); err == nil && f > 0 && f <= 10 {
			return f
		}
	}
	// Try parsing as a plain number
	var f float64
	if _, err := fmt.Sscanf(score, "%f", &f); err == nil && f > 0 && f <= 10 {
		return f
	}
	return 0
}

func cvssToSeverity(score float64) analysis.Severity {
	switch {
	case score >= 9.0:
		return analysis.SeverityCritical
	case score >= 7.0:
		return analysis.SeverityHigh
	case score >= 4.0:
		return analysis.SeverityMedium
	case score > 0:
		return analysis.SeverityLow
	default:
		return analysis.SeverityInfo
	}
}

func normalizeSeverity(s string) analysis.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "severe":
		return analysis.SeverityCritical
	case "high":
		return analysis.SeverityHigh
	case "moderate", "medium":
		return analysis.SeverityMedium
	case "low":
		return analysis.SeverityLow
	default:
		return analysis.SeverityInfo
	}
}

func inferFromSummary(summary string) analysis.Severity {
	lower := strings.ToLower(summary)
	if strings.Contains(lower, "critical") {
		return analysis.SeverityCritical
	}
	if strings.Contains(lower, "high") {
		return analysis.SeverityHigh
	}
	if strings.Contains(lower, "moderate") || strings.Contains(lower, "medium") {
		return analysis.SeverityMedium
	}
	if strings.Contains(lower, "low") {
		return analysis.SeverityLow
	}
	return analysis.SeverityMedium
}

// compareVersions does a simple semver-like comparison.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
func compareVersions(a, b string) int {
	aParts := strings.Split(strings.TrimPrefix(a, "v"), ".")
	bParts := strings.Split(strings.TrimPrefix(b, "v"), ".")

	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}

	for i := 0; i < maxLen; i++ {
		var aPart, bPart string
		if i < len(aParts) {
			aPart = stripNonNumeric(aParts[i])
		}
		if i < len(bParts) {
			bPart = stripNonNumeric(bParts[i])
		}

		var aNum, bNum int
		fmt.Sscanf(aPart, "%d", &aNum)
		fmt.Sscanf(bPart, "%d", &bNum)

		if aNum < bNum {
			return -1
		}
		if aNum > bNum {
			return 1
		}
	}
	return 0
}

func stripNonNumeric(s string) string {
	var result strings.Builder
	for _, c := range s {
		if c >= '0' && c <= '9' {
			result.WriteRune(c)
		} else {
			break
		}
	}
	return result.String()
}
