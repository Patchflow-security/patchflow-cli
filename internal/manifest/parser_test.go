package manifest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/patchflow/patchflow-cli/internal/analysis"
)

func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write %s: %v", name, err)
	}
	return path
}

func TestParseGoMod(t *testing.T) {
	dir := t.TempDir()
	content := `module example.com/test

go 1.21

require (
	github.com/spf13/cobra v1.0.0
	github.com/spf13/viper v1.0.0 // indirect
)

require github.com/stretchr/testify v1.8.0
`
	path := writeTestFile(t, dir, "go.mod", content)

	deps, err := ParseGoMod(path)
	if err != nil {
		t.Fatalf("ParseGoMod failed: %v", err)
	}

	if len(deps) != 3 {
		t.Fatalf("expected 3 deps, got %d", len(deps))
	}

	// Check cobra is direct
	foundCobra := false
	foundViper := false
	foundTestify := false
	for _, dep := range deps {
		switch dep.Name {
		case "github.com/spf13/cobra":
			foundCobra = true
			if !dep.IsDirect {
				t.Error("cobra should be direct")
			}
			if dep.Version != "v1.0.0" {
				t.Errorf("cobra version: got %s, want v1.0.0", dep.Version)
			}
		case "github.com/spf13/viper":
			foundViper = true
			if dep.IsDirect {
				t.Error("viper should be indirect")
			}
		case "github.com/stretchr/testify":
			foundTestify = true
			if !dep.IsDirect {
				t.Error("testify should be direct (single-line require)")
			}
		}
	}
	if !foundCobra || !foundViper || !foundTestify {
		t.Errorf("missing deps: cobra=%v viper=%v testify=%v", foundCobra, foundViper, foundTestify)
	}

	// Verify ecosystem
	for _, dep := range deps {
		if dep.Ecosystem != analysis.EcosystemGo {
			t.Errorf("expected Go ecosystem, got %s", dep.Ecosystem)
		}
	}
}

func TestParsePackageJSON(t *testing.T) {
	dir := t.TempDir()
	content := `{
  "name": "test-pkg",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "~4.17.21"
  },
  "devDependencies": {
    "jest": ">=29.0.0"
  }
}`
	path := writeTestFile(t, dir, "package.json", content)

	deps, err := ParsePackageJSON(path)
	if err != nil {
		t.Fatalf("ParsePackageJSON failed: %v", err)
	}

	if len(deps) != 3 {
		t.Fatalf("expected 3 deps, got %d", len(deps))
	}

	// Check express
	foundExpress := false
	foundJest := false
	for _, dep := range deps {
		if dep.Name == "express" {
			foundExpress = true
			if dep.Version != "4.18.0" {
				t.Errorf("express version: got %s, want 4.18.0", dep.Version)
			}
			if dep.IsDev {
				t.Error("express should not be dev")
			}
		}
		if dep.Name == "jest" {
			foundJest = true
			if !dep.IsDev {
				t.Error("jest should be dev")
			}
		}
	}
	if !foundExpress || !foundJest {
		t.Errorf("missing deps: express=%v jest=%v", foundExpress, foundJest)
	}
}

func TestParseRequirementsTxt(t *testing.T) {
	dir := t.TempDir()
	content := `# requirements
flask==2.3.0
django>=4.0,<5.0
requests[security]==2.28.0
# comment
numpy
`
	path := writeTestFile(t, dir, "requirements.txt", content)

	deps, err := ParseRequirementsTxt(path)
	if err != nil {
		t.Fatalf("ParseRequirementsTxt failed: %v", err)
	}

	if len(deps) != 4 {
		t.Fatalf("expected 4 deps, got %d: %+v", len(deps), deps)
	}

	// Check flask
	foundFlask := false
	foundDjango := false
	foundRequests := false
	for _, dep := range deps {
		switch dep.Name {
		case "flask":
			foundFlask = true
			if dep.Version != "2.3.0" {
				t.Errorf("flask version: got %s, want 2.3.0", dep.Version)
			}
		case "django":
			foundDjango = true
			if dep.Version != "4.0" {
				t.Errorf("django version: got %s, want 4.0", dep.Version)
			}
		case "requests":
			foundRequests = true
		}
	}
	if !foundFlask || !foundDjango || !foundRequests {
		t.Errorf("missing deps: flask=%v django=%v requests=%v", foundFlask, foundDjango, foundRequests)
	}
}

func TestParseCargoToml(t *testing.T) {
	dir := t.TempDir()
	content := `[package]
name = "test"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }

[dev-dependencies]
criterion = "0.5"
`
	path := writeTestFile(t, dir, "Cargo.toml", content)

	deps, err := ParseCargoToml(path)
	if err != nil {
		t.Fatalf("ParseCargoToml failed: %v", err)
	}

	if len(deps) != 2 {
		t.Fatalf("expected 2 deps (serde + criterion), got %d: %+v", len(deps), deps)
	}

	foundSerde := false
	foundCriterion := false
	for _, dep := range deps {
		if dep.Name == "serde" {
			foundSerde = true
			if dep.Version != "1.0" {
				t.Errorf("serde version: got %s, want 1.0", dep.Version)
			}
			if dep.IsDev {
				t.Error("serde should not be dev")
			}
		}
		if dep.Name == "criterion" {
			foundCriterion = true
			if !dep.IsDev {
				t.Error("criterion should be dev")
			}
		}
	}
	if !foundSerde || !foundCriterion {
		t.Errorf("missing deps: serde=%v criterion=%v", foundSerde, foundCriterion)
	}
}

func TestDetect(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "go.mod", "module test\n\ngo 1.21\n")
	writeTestFile(t, dir, "package.json", `{"name":"test"}`)

	// Create a subdirectory with a manifest
	subDir := filepath.Join(dir, "subdir")
	os.MkdirAll(subDir, 0755)
	writeTestFile(t, subDir, "requirements.txt", "flask==2.0.0")

	manifests, err := Detect(dir, 3)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if len(manifests) != 3 {
		t.Fatalf("expected 3 manifests, got %d: %+v", len(manifests), manifests)
	}
}

func TestDetectSkipsNodeModules(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "go.mod", "module test\n\ngo 1.21\n")

	// Create node_modules with a package.json that should be skipped
	nmDir := filepath.Join(dir, "node_modules", "somepkg")
	os.MkdirAll(nmDir, 0755)
	writeTestFile(t, nmDir, "package.json", `{"name":"somepkg"}`)

	manifests, err := Detect(dir, 3)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest (node_modules skipped), got %d: %+v", len(manifests), manifests)
	}
}

func TestParseAll(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "go.mod", `module test

go 1.21

require (
	github.com/spf13/cobra v1.0.0
)
`)
	writeTestFile(t, dir, "package.json", `{
  "name": "test",
  "dependencies": { "express": "^4.18.0" }
}`)

	deps, manifests, err := ParseAll(dir, 3)
	if err != nil {
		t.Fatalf("ParseAll failed: %v", err)
	}

	if len(manifests) != 2 {
		t.Fatalf("expected 2 manifests, got %d", len(manifests))
	}

	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}

	// Check manifest paths are set
	for _, dep := range deps {
		if dep.ManifestPath == "" {
			t.Error("manifest path should be set")
		}
	}
}
