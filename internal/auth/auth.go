package auth

import (
	"errors"
	"strings"

	"github.com/patchflow/patchflow-cli/internal/config"
)

// AuthStatus represents the current authentication state.
type AuthStatus struct {
	Authenticated bool
	MaskedToken   string
	StorageType   string
}

// Manager handles authentication state and token lifecycle.
type Manager struct {
	config  *config.Config
	storage TokenStorage
}

// NewManager creates a new auth manager bound to the given config.
func NewManager(cfg *config.Config) *Manager {
	return &Manager{
		config:  cfg,
		storage: NewTokenStorage(),
	}
}

// NewManagerWithStorage creates a new auth manager with a specific storage backend.
// Useful for testing.
func NewManagerWithStorage(cfg *config.Config, storage TokenStorage) *Manager {
	return &Manager{
		config:  cfg,
		storage: storage,
	}
}

// Login validates the token and persists it to secure storage (not config file).
// Never logs or exposes the raw token.
func (m *Manager) Login(token string) error {
	if strings.TrimSpace(token) == "" {
		return errors.New("token cannot be empty")
	}
	if err := m.storage.Save(token); err != nil {
		return err
	}
	// Clear token from config file for migration safety.
	if m.config.Token != "" {
		m.config.Token = ""
		_ = config.Save(m.config)
	}
	return nil
}

// Logout deletes the token from secure storage and clears it from config.
func (m *Manager) Logout() error {
	if err := m.storage.Delete(); err != nil {
		// Ignore "not found" errors so logout is idempotent.
		if !strings.Contains(err.Error(), "not found") {
			return err
		}
	}
	if m.config.Token != "" {
		m.config.Token = ""
		if err := config.Save(m.config); err != nil {
			return err
		}
	}
	return nil
}

// Status returns whether the user is authenticated, a masked token, and the storage type.
// It checks secure storage first, falling back to config.Token for migration.
func (m *Manager) Status() (AuthStatus, error) {
	token, err := m.storage.Load()
	if err == nil && strings.TrimSpace(token) != "" {
		return AuthStatus{
			Authenticated: true,
			MaskedToken:   maskToken(token),
			StorageType:   storageTypeName(m.storage),
		}, nil
	}

	// Migration fallback: token stored in config file.
	if strings.TrimSpace(m.config.Token) != "" {
		return AuthStatus{
			Authenticated: true,
			MaskedToken:   maskToken(m.config.Token),
			StorageType:   "config",
		}, nil
	}

	return AuthStatus{
		Authenticated: false,
		MaskedToken:   "none",
		StorageType:   "none",
	}, nil
}

// IsAuthenticated returns true if a non-empty token exists in storage or config.
func (m *Manager) IsAuthenticated() bool {
	status, err := m.Status()
	if err != nil {
		return false
	}
	return status.Authenticated
}

// storageTypeName returns a human-readable name for the storage backend.
func storageTypeName(s TokenStorage) string {
	switch s.(type) {
	case *KeychainStorage:
		return "keychain"
	case *FileStorage:
		return "file"
	default:
		return "unknown"
	}
}

// maskToken masks a raw token so it is safe for display.
// Tokens with 4+ characters show the last 4 chars prefixed by asterisks.
// Shorter tokens are fully masked. An empty token returns "none".
func maskToken(token string) string {
	if token == "" {
		return "none"
	}
	t := strings.TrimSpace(token)
	if len(t) < 4 {
		return strings.Repeat("*", len(t))
	}
	return "****" + t[len(t)-4:]
}
