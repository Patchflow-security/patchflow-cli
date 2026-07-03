package scan

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/report"
)

// sarifRoundtripDoc is a minimal SARIF 2.1.0 document shape used to parse the
// JSON emitted by report.Generator.SARIF back into Go for assertions.
type sarifRoundtripDoc struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				Rules   []struct {
					ID               string `json:"id"`
					Name             string `json:"name"`
					ShortDescription struct {
						Text string `json:"text"`
					} `json:"shortDescription"`
					FullDescription struct {
						Text string `json:"text"`
					} `json:"fullDescription"`
					HelpURI string `json:"helpUri"`
					Properties struct {
						Tags []string `json:"tags"`
					} `json:"properties"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID     string `json:"ruleId"`
			Level      string `json:"level"`
			Message    struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
						EndLine   int `json:"endLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
			Properties struct {
				SemanticFingerprint string `json:"semantic_fingerprint"`
				LocationFingerprint string `json:"location_fingerprint"`
				Severity            string `json:"severity"`
				CWEID               string `json:"cwe_id"`
			} `json:"properties"`
		} `json:"results"`
	} `json:"runs"`
}

// TestSARIFRoundtrip builds a Generator with three findings (distinct rule IDs
// and CWEs), serializes to SARIF JSON, parses it back, and verifies the
// tool.driver.rules contract, result/rule linkage, tags, fingerprints, and
// severity-to-level mapping.
func TestSARIFRoundtrip(t *testing.T) {
	now := time.Now().UTC()
	findings := []analysis.Finding{
		{
			ID:                  "f-1",
			Type:                analysis.TypeSAST,
			Analyzer:            "patterns",
			Severity:            analysis.SeverityCritical,
			Confidence:          analysis.ConfidenceHigh,
			Title:               "SQL Injection in query construction",
			Description:         "User input concatenated into SQL query allows injection.",
			FilePath:            "app/db.py",
			LineStart:           42,
			LineEnd:             42,
			CWEID:               "CWE-89",
			RuleID:              "TP-PY001",
			SemanticFingerprint: "sem-tp-py001-abc",
			LocationFingerprint: "loc-tp-py001-abc",
			DetectedAt:          now,
		},
		{
			ID:                  "f-2",
			Type:                analysis.TypeSAST,
			Analyzer:            "patterns",
			Severity:            analysis.SeverityHigh,
			Confidence:          analysis.ConfidenceMedium,
			Title:               "Reflected XSS in template output",
			Description:         "Unescaped user input rendered to HTML.",
			FilePath:            "app/views.py",
			LineStart:           10,
			LineEnd:             10,
			CWEID:               "CWE-79",
			RuleID:              "TP-PY002",
			SemanticFingerprint: "sem-tp-py002-def",
			LocationFingerprint: "loc-tp-py002-def",
			DetectedAt:          now,
		},
		{
			ID:                  "f-3",
			Type:                analysis.TypeSCA,
			Analyzer:            "osv",
			Severity:            analysis.SeverityMedium,
			Confidence:          analysis.ConfidenceHigh,
			Title:               "Vulnerable dependency: requests",
			Description:         "requests 2.20.0 has a known SSRF vulnerability.",
			FilePath:            "requirements.txt",
			CWEID:               "CWE-918",
			RuleID:              "SCA-OSV-001",
			PackageName:         "requests",
			PackageVersion:      "2.20.0",
			SemanticFingerprint: "sem-sca-osv-001-ghi",
			LocationFingerprint: "loc-sca-osv-001-ghi",
			DetectedAt:          now,
		},
	}

	result := &analysis.AnalysisResult{
		ScanID:      "scan-test-1",
		ProjectRoot: "/tmp/project",
		Findings:    findings,
		StartedAt:   now,
		CompletedAt: now,
	}

	gen := report.NewGenerator(result, nil)
	sarif := gen.SARIF("0.1.2")
	data, err := json.Marshal(sarif)
	if err != nil {
		t.Fatalf("marshal SARIF: %v", err)
	}

	var doc sarifRoundtripDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal SARIF: %v", err)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(doc.Runs))
	}
	run := doc.Runs[0]

	// --- tool.driver.rules ---
	rules := run.Tool.Driver.Rules
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(rules))
	}
	ruleByID := make(map[string]struct {
		Name    string
		HelpURI string
		Tags    []string
		Short   string
	})
	for _, r := range rules {
		ruleByID[r.ID] = struct {
			Name    string
			HelpURI string
			Tags    []string
			Short   string
		}{r.Name, r.HelpURI, r.Properties.Tags, r.ShortDescription.Text}
	}

	wantIDs := []string{"TP-PY001", "TP-PY002", "SCA-OSV-001"}
	for _, id := range wantIDs {
		if _, ok := ruleByID[id]; !ok {
			t.Errorf("rules array missing entry for rule ID %q", id)
		}
	}

	// Each rule must have the "security" tag and a help URI.
	for id, r := range ruleByID {
		if r.HelpURI != "https://patchflow.dev/docs/rules/"+id {
			t.Errorf("rule %q helpUri = %q, want %q", id, r.HelpURI, "https://patchflow.dev/docs/rules/"+id)
		}
		hasSecurity := false
		for _, tag := range r.Tags {
			if tag == "security" {
				hasSecurity = true
				break
			}
		}
		if !hasSecurity {
			t.Errorf("rule %q tags missing \"security\": %v", id, r.Tags)
		}
	}

	// CWE-derived tags for TP-PY001 (CWE-89 -> A03).
	if r, ok := ruleByID["TP-PY001"]; ok {
		expectContains(t, r.Tags, "cwe")
		expectContains(t, r.Tags, "CWE-89")
		expectContains(t, r.Tags, "owasp")
		expectContains(t, r.Tags, "A03")
		expectContains(t, r.Tags, "sast")
	}
	// CWE-79 -> A07.
	if r, ok := ruleByID["TP-PY002"]; ok {
		expectContains(t, r.Tags, "CWE-79")
		expectContains(t, r.Tags, "A07")
	}
	// SCA finding type tag.
	if r, ok := ruleByID["SCA-OSV-001"]; ok {
		expectContains(t, r.Tags, "sca")
		expectContains(t, r.Tags, "CWE-918")
		expectContains(t, r.Tags, "A10")
	}

	// --- results link to rules, fingerprints preserved, severity mapped ---
	if len(run.Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(run.Results))
	}
	for _, res := range run.Results {
		if _, ok := ruleByID[res.RuleID]; !ok {
			t.Errorf("result ruleId %q has no matching entry in rules array", res.RuleID)
		}
		if res.Properties.SemanticFingerprint == "" {
			t.Errorf("result %q missing semantic_fingerprint", res.RuleID)
		}
		if res.Properties.LocationFingerprint == "" {
			t.Errorf("result %q missing location_fingerprint", res.RuleID)
		}
		// Severity-to-level mapping.
		var wantLevel string
		switch res.Properties.Severity {
		case "critical", "high":
			wantLevel = "error"
		case "medium":
			wantLevel = "warning"
		case "low", "info":
			wantLevel = "note"
		default:
			t.Errorf("result %q unexpected severity %q", res.RuleID, res.Properties.Severity)
			continue
		}
		if res.Level != wantLevel {
			t.Errorf("result %q level = %q, want %q (severity %q)", res.RuleID, res.Level, wantLevel, res.Properties.Severity)
		}
	}
}

// expectContains fails the test if needle is not present in haystack.
func expectContains(t *testing.T, haystack []string, needle string) {
	t.Helper()
	for _, s := range haystack {
		if s == needle {
			return
		}
	}
	t.Errorf("expected tags to contain %q, got %v", needle, haystack)
}
