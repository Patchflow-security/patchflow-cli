package auth

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/config"
)

func setupTempFileStorage(t *testing.T) (*config.Config, *FileStorage) {
	t.Helper()
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}
	storage := NewFileStorage(filepath.Join(tmpDir, ".patchflow", "token"))
	return cfg, storage
}

func TestLoginValidToken(t *testing.T) {
	cfg, storage := setupTempFileStorage(t)
	mgr := NewManagerWithStorage(cfg, storage)

	err := mgr.Login("my-secret-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	loaded, err := storage.Load()
	if err != nil {
		t.Fatalf("failed to load token from storage: %v", err)
	}
	if loaded != "my-secret-token" {
		t.Fatalf("expected token %q, got %q", "my-secret-token", loaded)
	}
}

func TestLoginEmptyToken(t *testing.T) {
	cfg, storage := setupTempFileStorage(t)
	mgr := NewManagerWithStorage(cfg, storage)

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
	cfg, storage := setupTempFileStorage(t)
	mgr := NewManagerWithStorage(cfg, storage)

	_ = mgr.Login("my-secret-token")
	err := mgr.Logout()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = storage.Load()
	if err == nil {
		t.Fatal("expected token to be deleted from storage")
	}
}

func TestStatusAuthenticated(t *testing.T) {
	cfg, storage := setupTempFileStorage(t)
	mgr := NewManagerWithStorage(cfg, storage)

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
	if status.StorageType != "file" {
		t.Fatalf("expected storage type %q, got %q", "file", status.StorageType)
	}
}

func TestTokenUsesSecureStorage(t *testing.T) {
	cfg, storage := setupTempFileStorage(t)
	cfg.Token = "config-token"
	mgr := NewManagerWithStorage(cfg, storage)

	_ = mgr.Login("storage-token")
	if got := mgr.Token(); got != "storage-token" {
		t.Fatalf("expected storage token, got %q", got)
	}
}

func TestTokenFallsBackToConfig(t *testing.T) {
	cfg, storage := setupTempFileStorage(t)
	cfg.Token = "config-token"
	mgr := NewManagerWithStorage(cfg, storage)

	if got := mgr.Token(); got != "config-token" {
		t.Fatalf("expected config token fallback, got %q", got)
	}
}

func TestStatusNotAuthenticated(t *testing.T) {
	cfg, storage := setupTempFileStorage(t)
	mgr := NewManagerWithStorage(cfg, storage)

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
	if status.StorageType != "none" {
		t.Fatalf("expected storage type %q, got %q", "none", status.StorageType)
	}
}

func TestMaskTokenLogic(t *testing.T) {
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
		got := maskToken(tc.token)
		if got != tc.expected {
			t.Fatalf("token %q: expected masked %q, got %q", tc.token, tc.expected, got)
		}
	}
}

func TestIsAuthenticated(t *testing.T) {
	cfg, storage := setupTempFileStorage(t)
	mgr := NewManagerWithStorage(cfg, storage)

	if mgr.IsAuthenticated() {
		t.Fatal("expected IsAuthenticated to be false before login")
	}

	_ = mgr.Login("token123")
	if !mgr.IsAuthenticated() {
		t.Fatal("expected IsAuthenticated to be true after login")
	}

	_ = mgr.Logout()
	if mgr.IsAuthenticated() {
		t.Fatal("expected IsAuthenticated to be false after logout")
	}
}

func TestStatusConfigMigrationFallback(t *testing.T) {
	cfg, storage := setupTempFileStorage(t)
	// Simulate a token still stored in config (migration scenario).
	cfg.Token = "config-migration-token"
	mgr := NewManagerWithStorage(cfg, storage)

	status, err := mgr.Status()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !status.Authenticated {
		t.Fatal("expected Authenticated to be true via config fallback")
	}
	if status.MaskedToken != "****oken" {
		t.Fatalf("expected masked token %q, got %q", "****oken", status.MaskedToken)
	}
	if status.StorageType != "config" {
		t.Fatalf("expected storage type %q, got %q", "config", status.StorageType)
	}
}

func TestLoginClearsConfigToken(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}
	cfg.Token = "old-config-token"
	_ = config.Save(cfg)

	storage := NewFileStorage(filepath.Join(tmpDir, ".patchflow", "token"))
	mgr := NewManagerWithStorage(cfg, storage)

	err = mgr.Login("new-storage-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Config token should be cleared.
	if cfg.Token != "" {
		t.Fatalf("expected config.Token to be cleared, got %q", cfg.Token)
	}

	// Config file should not contain the token.
	configFile := filepath.Join(tmpDir, ".patchflow", "config.yaml")
	data, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("failed to read config file: %v", err)
	}
	if string(data) == "" {
		t.Fatal("expected config file to exist")
	}
}
