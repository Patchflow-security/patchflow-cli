package scan

import (
	"encoding/json"
	"testing"

	"github.com/patchflow/patchflow-cli/pkg/version"
)

func TestExportSARIF(t *testing.T) {
	scanResult := &Result{
		Root: "/fake/repo",
		Manifests: []Manifest{
			{Path: "package.json", Type: "node"},
			{Path: "backend/requirements.txt", Type: "python"},
		},
		ChangedFiles: []string{},
	}

	report, err := ExportSARIF(scanResult)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.Schema != "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json" {
		t.Errorf("unexpected schema: %s", report.Schema)
	}
	if report.Version != "2.1.0" {
		t.Errorf("unexpected version: %s", report.Version)
	}
	if len(report.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(report.Runs))
	}

	run := report.Runs[0]
	if run.Tool.Driver.Name != "PatchFlow CLI" {
		t.Errorf("unexpected driver name: %s", run.Tool.Driver.Name)
	}
	if run.Tool.Driver.Version != version.Version {
		t.Errorf("unexpected driver version: %s", run.Tool.Driver.Version)
	}
	if len(run.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(run.Results))
	}

	for i, m := range scanResult.Manifests {
		r := run.Results[i]
		if r.RuleID != "manifest-detection" {
			t.Errorf("result %d: unexpected ruleId: %s", i, r.RuleID)
		}
		expectedMsg := "Detected dependency manifest: " + m.Path
		if r.Message.Text != expectedMsg {
			t.Errorf("result %d: unexpected message: %s", i, r.Message.Text)
		}
		if len(r.Locations) != 1 {
			t.Fatalf("result %d: expected 1 location, got %d", i, len(r.Locations))
		}
		if r.Locations[0].PhysicalLocation.ArtifactLocation.URI != m.Path {
			t.Errorf("result %d: unexpected URI: %s", i, r.Locations[0].PhysicalLocation.ArtifactLocation.URI)
		}
	}
}

func TestExportSARIFEmptyManifests(t *testing.T) {
	scanResult := &Result{
		Root:         "/fake/repo",
		Manifests:    []Manifest{},
		ChangedFiles: []string{},
	}

	report, err := ExportSARIF(scanResult)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(report.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(report.Runs))
	}
	if len(report.Runs[0].Results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(report.Runs[0].Results))
	}
}

func TestExportJSON(t *testing.T) {
	scanResult := &Result{
		Root: "/fake/repo",
		Manifests: []Manifest{
			{Path: "go.mod", Type: "go"},
		},
		ChangedFiles: []string{"go.mod"},
	}

	data, err := ExportJSON(scanResult)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var decoded Result
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if decoded.Root != scanResult.Root {
		t.Errorf("unexpected root: %s", decoded.Root)
	}
	if len(decoded.Manifests) != 1 || decoded.Manifests[0].Path != "go.mod" {
		t.Errorf("unexpected manifests: %+v", decoded.Manifests)
	}
	if len(decoded.ChangedFiles) != 1 || decoded.ChangedFiles[0] != "go.mod" {
		t.Errorf("unexpected changed files: %+v", decoded.ChangedFiles)
	}
}
