package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadEmptyPathDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.APIURL != "https://api.patchflow.dev" {
		t.Fatalf("expected default APIURL, got %q", cfg.APIURL)
	}
	if cfg.Token != "" {
		t.Fatalf("expected empty token, got %q", cfg.Token)
	}
	if cfg.Org != "" {
		t.Fatalf("expected empty org, got %q", cfg.Org)
	}
	if cfg.LogLevel != "" {
		t.Fatalf("expected empty loglevel, got %q", cfg.LogLevel)
	}
}

func TestLoadOverridesWithEnvVars(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("PATCHFLOW_API_URL", "https://env.api.com")
	t.Setenv("PATCHFLOW_ORG", "env-org")
	t.Setenv("PATCHFLOW_TOKEN", "env-token")
	t.Setenv("PATCHFLOW_LOG_LEVEL", "debug")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.APIURL != "https://env.api.com" {
		t.Fatalf("expected APIURL from env, got %q", cfg.APIURL)
	}
	if cfg.Org != "env-org" {
		t.Fatalf("expected Org from env, got %q", cfg.Org)
	}
	if cfg.Token != "env-token" {
		t.Fatalf("expected Token from env, got %q", cfg.Token)
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("expected LogLevel from env, got %q", cfg.LogLevel)
	}
}

func TestSaveAndLoadRoundtrip(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	cfg := &Config{
		APIURL:   "https://custom.api.com",
		Token:    "secret-token",
		Org:      "my-org",
		LogLevel: "info",
	}

	err := Save(cfg)
	if err != nil {
		t.Fatalf("unexpected save error: %v", err)
	}

	loaded, err := Load("")
	if err != nil {
		t.Fatalf("unexpected load error: %v", err)
	}
	if loaded.APIURL != cfg.APIURL {
		t.Fatalf("expected APIURL %q, got %q", cfg.APIURL, loaded.APIURL)
	}
	// Token is intentionally NOT persisted to config file for security.
	if loaded.Token != "" {
		t.Fatalf("expected Token to be empty in config file, got %q", loaded.Token)
	}
	if loaded.Org != cfg.Org {
		t.Fatalf("expected Org %q, got %q", cfg.Org, loaded.Org)
	}
	if loaded.LogLevel != cfg.LogLevel {
		t.Fatalf("expected LogLevel %q, got %q", cfg.LogLevel, loaded.LogLevel)
	}
}

func TestGetConfigDir(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	dir := GetConfigDir()
	if !strings.Contains(dir, ".patchflow") {
		t.Fatalf("expected config dir to contain '.patchflow', got %q", dir)
	}
	expected := filepath.Join(tmpDir, ".patchflow")
	if dir != expected {
		t.Fatalf("expected config dir %q, got %q", expected, dir)
	}
}

func TestGetConfigDirFallback(t *testing.T) {
	// Remove HOME env var to trigger fallback
	t.Setenv("HOME", "")
	// UserHomeDir will return error when HOME is empty on Unix,
	// but on some systems it may still work. Just verify it contains .patchflow.
	dir := GetConfigDir()
	if !strings.Contains(dir, ".patchflow") {
		t.Fatalf("expected config dir to contain '.patchflow', got %q", dir)
	}
}

func TestLoadSpecificPath(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configPath := filepath.Join(tmpDir, "custom.yaml")
	content := `apiurl: https://file.api.com
org: file-org
loglevel: warn
`
	err := os.WriteFile(configPath, []byte(content), 0644)
	if err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.APIURL != "https://file.api.com" {
		t.Fatalf("expected APIURL from file, got %q", cfg.APIURL)
	}
	if cfg.Org != "file-org" {
		t.Fatalf("expected Org from file, got %q", cfg.Org)
	}
	if cfg.LogLevel != "warn" {
		t.Fatalf("expected LogLevel from file, got %q", cfg.LogLevel)
	}
}
