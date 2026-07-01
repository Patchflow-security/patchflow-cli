package scan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectManifests(t *testing.T) {
	tmpDir := t.TempDir()

	// Create manifests at root
	_ = os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte("{}"), 0644)
	_ = os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte("module test"), 0644)
	_ = os.WriteFile(filepath.Join(tmpDir, "README.md"), []byte("hello"), 0644)

	// Create subdir with manifest at depth 1
	_ = os.MkdirAll(filepath.Join(tmpDir, "backend"), 0755)
	_ = os.WriteFile(filepath.Join(tmpDir, "backend", "requirements.txt"), []byte("flask"), 0644)

	// Create nested dir at depth 2 (should be skipped)
	_ = os.MkdirAll(filepath.Join(tmpDir, "backend", "nested"), 0755)
	_ = os.WriteFile(filepath.Join(tmpDir, "backend", "nested", "package.json"), []byte("{}"), 0644)

	manifests, err := DetectManifests(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(manifests) != 3 {
		t.Fatalf("expected 3 manifests, got %d: %+v", len(manifests), manifests)
	}

	paths := make([]string, len(manifests))
	for i, m := range manifests {
		paths[i] = m.Path
	}

	expected := []string{"backend/requirements.txt", "go.mod", "package.json"}
	for _, p := range expected {
		found := false
		for _, mp := range paths {
			if mp == p {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected manifest %q not found", p)
		}
	}
}

func TestDetectManifestsSkipsIgnoredDirs(t *testing.T) {
	tmpDir := t.TempDir()

	_ = os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte("{}"), 0644)

	// .git dir with manifest
	_ = os.MkdirAll(filepath.Join(tmpDir, ".git"), 0755)
	_ = os.WriteFile(filepath.Join(tmpDir, ".git", "go.mod"), []byte("module bad"), 0644)

	// vendor dir with manifest
	_ = os.MkdirAll(filepath.Join(tmpDir, "vendor"), 0755)
	_ = os.WriteFile(filepath.Join(tmpDir, "vendor", "Cargo.toml"), []byte("[package]"), 0644)

	// node_modules dir with manifest
	_ = os.MkdirAll(filepath.Join(tmpDir, "node_modules"), 0755)
	_ = os.WriteFile(filepath.Join(tmpDir, "node_modules", "package.json"), []byte("{}"), 0644)

	manifests, err := DetectManifests(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d: %+v", len(manifests), manifests)
	}
	if manifests[0].Path != "package.json" {
		t.Errorf("expected package.json, got %s", manifests[0].Path)
	}
}

func TestDetectManifestsDepthLimit(t *testing.T) {
	tmpDir := t.TempDir()

	_ = os.MkdirAll(filepath.Join(tmpDir, "a", "b"), 0755)
	_ = os.WriteFile(filepath.Join(tmpDir, "a", "b", "pom.xml"), []byte(""), 0644)

	manifests, err := DetectManifests(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(manifests) != 0 {
		t.Fatalf("expected 0 manifests, got %d", len(manifests))
	}
}
