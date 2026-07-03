package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/sbom"
)

func TestLicenseAnalyzerEnrichesHelmChartFromRepositoryIndex(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/index.yaml" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/x-yaml")
		_, _ = w.Write([]byte(`apiVersion: v1
entries:
  redis:
    - version: 19.1.0
      annotations:
        artifacthub.io/license: Apache-2.0
`))
	}))
	defer server.Close()

	analyzer := NewLicenseAnalyzer()
	result, err := analyzer.Analyze(context.Background(), []analysis.Dependency{
		{
			Name:       "redis",
			Version:    "19.1.0",
			Ecosystem:  analysis.EcosystemHelm,
			Repository: server.URL,
		},
	})
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if result.Enriched != 1 {
		t.Fatalf("expected 1 enriched dependency, got %d", result.Enriched)
	}
	if result.Summary.ByRisk[sbom.LicenseRiskLow] != 1 {
		t.Fatalf("expected one low-risk license, got summary %+v", result.Summary)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected permissive Helm license to produce no findings, got %+v", result.Findings)
	}
}

func TestLicenseAnalyzerDoesNotFlagRootComponentMissingLicense(t *testing.T) {
	analyzer := NewLicenseAnalyzer()
	result, err := analyzer.Analyze(context.Background(), []analysis.Dependency{
		{
			Name:      "first-party-chart",
			Version:   "1.0.0",
			Ecosystem: analysis.EcosystemHelm,
			IsRoot:    true,
		},
	})
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if result.Summary.NoLicense != 1 {
		t.Fatalf("expected root missing license to remain in summary, got %+v", result.Summary)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no actionable finding for root missing license, got %+v", result.Findings)
	}
}
