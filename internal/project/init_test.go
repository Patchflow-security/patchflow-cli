package project

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInitCreatesDirectory(t *testing.T) {
	dir := t.TempDir()

	result, err := Init(dir)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	if !result.Created {
		t.Error("expected Created=true for new init")
	}

	// Check directory exists
	if _, err := os.Stat(result.Dir); err != nil {
		t.Errorf("directory not created: %v", err)
	}

	// Check config.yml exists
	if _, err := os.Stat(result.ConfigPath); err != nil {
		t.Errorf("config.yml not created: %v", err)
	}

	// Check subdirectories
	for _, sub := range []string{"cache", "baselines", "reports"} {
		path := filepath.Join(result.Dir, sub)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("subdirectory %s not created: %v", sub, err)
		}
	}

	// Check .gitignore
	gitignorePath := filepath.Join(result.Dir, ".gitignore")
	if _, err := os.Stat(gitignorePath); err != nil {
		t.Errorf(".gitignore not created: %v", err)
	}
}

func TestInitIdempotent(t *testing.T) {
	dir := t.TempDir()

	// First init
	_, err := Init(dir)
	if err != nil {
		t.Fatalf("first Init failed: %v", err)
	}

	// Second init should not overwrite
	result, err := Init(dir)
	if err != nil {
		t.Fatalf("second Init failed: %v", err)
	}

	if result.Created {
		t.Error("expected Created=false for existing .patchflow/")
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()

	_, err := Init(dir)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	cfg, err := LoadConfig(dir)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.Mode != "local" {
		t.Errorf("expected mode=local, got %s", cfg.Mode)
	}
	if !cfg.Analysis.IncludeReachability {
		t.Error("expected IncludeReachability=true by default")
	}
	if !cfg.Privacy.RedactSecrets {
		t.Error("expected RedactSecrets=true by default")
	}
}

func TestIsInitialized(t *testing.T) {
	dir := t.TempDir()

	if IsInitialized(dir) {
		t.Error("should not be initialized before Init")
	}

	_, _ = Init(dir)

	if !IsInitialized(dir) {
		t.Error("should be initialized after Init")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Mode != "local" {
		t.Errorf("expected local mode, got %s", cfg.Mode)
	}
	if cfg.Analysis.DefaultProfile != "standard" {
		t.Errorf("expected standard profile, got %s", cfg.Analysis.DefaultProfile)
	}
	if len(cfg.Ignore.Paths) == 0 {
		t.Error("expected default ignore paths")
	}
}
