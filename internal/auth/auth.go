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
}

// Manager handles authentication state and token lifecycle.
// All token storage logic is isolated here and in internal/config,
// making it easy to swap to an OS keychain later.
type Manager struct {
	config *config.Config
}

// NewManager creates a new auth manager bound to the given config.
func NewManager(cfg *config.Config) *Manager {
	return &Manager{config: cfg}
}

// Login validates the token and persists it to config.
// Never logs or exposes the raw token.
func (m *Manager) Login(token string) error {
	if strings.TrimSpace(token) == "" {
		return errors.New("token cannot be empty")
	}
	m.config.Token = token
	if err := config.Save(m.config); err != nil {
		return err
	}
	return nil
}

// Logout clears the stored token and persists the change.
func (m *Manager) Logout() error {
	m.config.Token = ""
	if err := config.Save(m.config); err != nil {
		return err
	}
	return nil
}

// Status returns whether the user is authenticated and a masked view of the token.
func (m *Manager) Status() (AuthStatus, error) {
	return AuthStatus{
		Authenticated: m.config.Token != "",
		MaskedToken:   maskToken(m.config.Token),
	}, nil
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
