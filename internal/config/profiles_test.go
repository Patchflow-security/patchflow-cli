package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestLoadProfilesEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	profiles, err := LoadProfiles()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if profiles.Active != "" {
		t.Fatalf("expected empty active profile, got %q", profiles.Active)
	}
	if len(profiles.Items) != 0 {
		t.Fatalf("expected empty items, got %d", len(profiles.Items))
	}
}

func TestSaveAndLoadProfilesRoundtrip(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	p := &Profiles{
		Active: "prod",
		Items: map[string]Profile{
			"dev": {
				Name:     "dev",
				APIURL:   "https://dev.api.com",
				Org:      "dev-org",
				LogLevel: "debug",
			},
			"prod": {
				Name:     "prod",
				APIURL:   "https://api.patchflow.dev",
				Org:      "prod-org",
				LogLevel: "warn",
			},
		},
	}

	if err := SaveProfiles(p); err != nil {
		t.Fatalf("unexpected save error: %v", err)
	}

	loaded, err := LoadProfiles()
	if err != nil {
		t.Fatalf("unexpected load error: %v", err)
	}

	if loaded.Active != "prod" {
		t.Fatalf("expected active 'prod', got %q", loaded.Active)
	}

	dev, ok := loaded.Get("dev")
	if !ok {
		t.Fatal("expected 'dev' profile to exist")
	}
	if dev.APIURL != "https://dev.api.com" {
		t.Fatalf("expected dev APIURL %q, got %q", "https://dev.api.com", dev.APIURL)
	}
	if dev.Org != "dev-org" {
		t.Fatalf("expected dev Org %q, got %q", "dev-org", dev.Org)
	}
	if dev.LogLevel != "debug" {
		t.Fatalf("expected dev LogLevel %q, got %q", "debug", dev.LogLevel)
	}

	prod, ok := loaded.Get("prod")
	if !ok {
		t.Fatal("expected 'prod' profile to exist")
	}
	if prod.APIURL != "https://api.patchflow.dev" {
		t.Fatalf("expected prod APIURL %q, got %q", "https://api.patchflow.dev", prod.APIURL)
	}
}

func TestProfilesCRUD(t *testing.T) {
	p := &Profiles{
		Items: make(map[string]Profile),
	}

	// Create
	p.Set("alpha", Profile{APIURL: "https://alpha.com", Org: "alpha-org"})
	prof, ok := p.Get("alpha")
	if !ok {
		t.Fatal("expected 'alpha' to exist after Set")
	}
	if prof.Org != "alpha-org" {
		t.Fatalf("expected org 'alpha-org', got %q", prof.Org)
	}

	// Update
	p.Set("alpha", Profile{APIURL: "https://alpha.com", Org: "alpha-updated"})
	prof, ok = p.Get("alpha")
	if !ok {
		t.Fatal("expected 'alpha' to exist after update")
	}
	if prof.Org != "alpha-updated" {
		t.Fatalf("expected org 'alpha-updated', got %q", prof.Org)
	}

	// List
	p.Set("beta", Profile{APIURL: "https://beta.com"})
	list := p.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 profiles, got %d", len(list))
	}
	if !slices.Equal(list, []string{"alpha", "beta"}) {
		t.Fatalf("expected sorted list [alpha beta], got %v", list)
	}

	// Delete
	p.Delete("alpha")
	_, ok = p.Get("alpha")
	if ok {
		t.Fatal("expected 'alpha' to be deleted")
	}
	list = p.List()
	if len(list) != 1 || list[0] != "beta" {
		t.Fatalf("expected [beta], got %v", list)
	}
}

func TestProfilesDeleteNilItems(t *testing.T) {
	p := &Profiles{}
	// Should not panic when Items is nil
	p.Delete("nonexistent")
	if p.Items != nil {
		t.Fatal("expected Items to remain nil")
	}
}

func TestLoadProfilesMergesIntoConfig(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	// Write a base config file
	configDir := filepath.Join(tmpDir, ".patchflow")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}
	configContent := `apiurl: https://base.api.com
org: base-org
loglevel: info
`
	if err := os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	// Write profiles with an active profile
	profiles := &Profiles{
		Active: "work",
		Items: map[string]Profile{
			"work": {
				Name:     "work",
				APIURL:   "https://work.api.com",
				Org:      "work-org",
				LogLevel: "debug",
			},
		},
	}
	if err := SaveProfiles(profiles); err != nil {
		t.Fatalf("failed to save profiles: %v", err)
	}

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("unexpected load error: %v", err)
	}

	// Active profile should override base config values
	if cfg.APIURL != "https://work.api.com" {
		t.Fatalf("expected APIURL from profile, got %q", cfg.APIURL)
	}
	if cfg.Org != "work-org" {
		t.Fatalf("expected Org from profile, got %q", cfg.Org)
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("expected LogLevel from profile, got %q", cfg.LogLevel)
	}
}

func TestLoadProfilesPartialOverride(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".patchflow")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}
	configContent := `apiurl: https://base.api.com
org: base-org
loglevel: info
`
	if err := os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	// Profile only overrides Org; APIURL and LogLevel should come from base config
	profiles := &Profiles{
		Active: "partial",
		Items: map[string]Profile{
			"partial": {
				Name: "partial",
				Org:  "partial-org",
			},
		},
	}
	if err := SaveProfiles(profiles); err != nil {
		t.Fatalf("failed to save profiles: %v", err)
	}

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("unexpected load error: %v", err)
	}

	if cfg.APIURL != "https://base.api.com" {
		t.Fatalf("expected base APIURL, got %q", cfg.APIURL)
	}
	if cfg.Org != "partial-org" {
		t.Fatalf("expected overridden Org, got %q", cfg.Org)
	}
	if cfg.LogLevel != "info" {
		t.Fatalf("expected base LogLevel, got %q", cfg.LogLevel)
	}
}

func TestGetProfilesPath(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	path := GetProfilesPath()
	expected := filepath.Join(tmpDir, ".patchflow", "profiles.yaml")
	if path != expected {
		t.Fatalf("expected profiles path %q, got %q", expected, path)
	}
}
