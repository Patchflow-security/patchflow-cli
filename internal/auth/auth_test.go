package auth

import (
	"testing"

	"github.com/patchflow/patchflow-cli/internal/config"
)

func setupTempConfig(t *testing.T) *config.Config {
	t.Helper()
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}
	return cfg
}

func TestLoginValidToken(t *testing.T) {
	cfg := setupTempConfig(t)
	mgr := NewManager(cfg)

	err := mgr.Login("my-secret-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Token != "my-secret-token" {
		t.Fatalf("expected token to be set, got %q", cfg.Token)
	}

	// Verify persisted
	loaded, err := config.Load("")
	if err != nil {
		t.Fatalf("failed to reload config: %v", err)
	}
	if loaded.Token != "my-secret-token" {
		t.Fatalf("expected persisted token %q, got %q", "my-secret-token", loaded.Token)
	}
}

func TestLoginEmptyToken(t *testing.T) {
	cfg := setupTempConfig(t)
	mgr := NewManager(cfg)

	err := mgr.Login("")
	if err == nil {
		t.Fatal("expected error for empty token, got nil")
	}
	if err.Error() != "token cannot be empty" {
		t.Fatalf("expected error %q, got %q", "token cannot be empty", err.Error())
	}

	err = mgr.Login("   ")
	if err == nil {
		t.Fatal("expected error for whitespace-only token, got nil")
	}
}

func TestLogoutClearsToken(t *testing.T) {
	cfg := setupTempConfig(t)
	mgr := NewManager(cfg)

	_ = mgr.Login("my-secret-token")
	err := mgr.Logout()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Token != "" {
		t.Fatalf("expected token to be cleared, got %q", cfg.Token)
	}

	loaded, err := config.Load("")
	if err != nil {
		t.Fatalf("failed to reload config: %v", err)
	}
	if loaded.Token != "" {
		t.Fatalf("expected persisted token to be cleared, got %q", loaded.Token)
	}
}

func TestStatusAuthenticated(t *testing.T) {
	cfg := setupTempConfig(t)
	mgr := NewManager(cfg)

	_ = mgr.Login("my-secret-token")
	status, err := mgr.Status()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !status.Authenticated {
		t.Fatal("expected Authenticated to be true")
	}
	if status.MaskedToken != "****oken" {
		t.Fatalf("expected masked token %q, got %q", "****oken", status.MaskedToken)
	}
}

func TestStatusNotAuthenticated(t *testing.T) {
	cfg := setupTempConfig(t)
	mgr := NewManager(cfg)

	status, err := mgr.Status()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Authenticated {
		t.Fatal("expected Authenticated to be false")
	}
	if status.MaskedToken != "none" {
		t.Fatalf("expected masked token %q, got %q", "none", status.MaskedToken)
	}
}

func TestMaskTokenLogic(t *testing.T) {
	cfg := setupTempConfig(t)
	mgr := NewManager(cfg)

	tests := []struct {
		token    string
		expected string
	}{
		{"", "none"},
		{"a", "*"},
		{"ab", "**"},
		{"abc", "***"},
		{"abcd", "****abcd"},
		{"my-secret-token", "****oken"},
	}

	for _, tc := range tests {
		cfg.Token = tc.token
		status, err := mgr.Status()
		if err != nil {
			t.Fatalf("unexpected error for token %q: %v", tc.token, err)
		}
		if status.MaskedToken != tc.expected {
			t.Fatalf("token %q: expected masked %q, got %q", tc.token, tc.expected, status.MaskedToken)
		}
	}
}

func TestLoginSavesOtherFields(t *testing.T) {
	cfg := setupTempConfig(t)
	cfg.APIURL = "https://custom.api.com"
	cfg.Org = "my-org"
	_ = config.Save(cfg)

	mgr := NewManager(cfg)
	_ = mgr.Login("token123")

	loaded, err := config.Load("")
	if err != nil {
		t.Fatalf("failed to reload config: %v", err)
	}
	if loaded.APIURL != "https://custom.api.com" {
		t.Fatalf("expected APIURL preserved, got %q", loaded.APIURL)
	}
	if loaded.Org != "my-org" {
		t.Fatalf("expected Org preserved, got %q", loaded.Org)
	}
}
