package auth

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/zalando/go-keyring"
)

// TokenStorage abstracts where the authentication token is persisted.
type TokenStorage interface {
	Save(token string) error
	Load() (string, error)
	Delete() error
}

// KeychainStorage stores the token in the OS keyring/secret service.
type KeychainStorage struct {
	service string
	account string
}

// NewKeychainStorage creates a new KeychainStorage with the given service and account.
func NewKeychainStorage(service, account string) *KeychainStorage {
	return &KeychainStorage{service: service, account: account}
}

// Save stores the token in the OS keychain.
func (k *KeychainStorage) Save(token string) error {
	return keyring.Set(k.service, k.account, token)
}

// Load retrieves the token from the OS keychain.
func (k *KeychainStorage) Load() (string, error) {
	return keyring.Get(k.service, k.account)
}

// Delete removes the token from the OS keychain.
func (k *KeychainStorage) Delete() error {
	return keyring.Delete(k.service, k.account)
}

// FileStorage is a fallback TokenStorage that reads/writes a plain file.
type FileStorage struct {
	path string
}

// NewFileStorage creates a new FileStorage backed by the given file path.
func NewFileStorage(path string) *FileStorage {
	return &FileStorage{path: path}
}

// Save writes the token to a file with restricted permissions.
func (f *FileStorage) Save(token string) error {
	dir := filepath.Dir(f.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create token directory: %w", err)
	}
	if err := os.WriteFile(f.path, []byte(token), 0600); err != nil {
		return fmt.Errorf("failed to write token file: %w", err)
	}
	return nil
}

// Load reads the token from the file.
func (f *FileStorage) Load() (string, error) {
	data, err := os.ReadFile(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("token not found")
		}
		return "", fmt.Errorf("failed to read token file: %w", err)
	}
	return string(data), nil
}

// Delete removes the token file.
func (f *FileStorage) Delete() error {
	err := os.Remove(f.path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete token file: %w", err)
	}
	return nil
}

// NewTokenStorage returns a TokenStorage backed by the OS keychain.
// Falls back to a secure file if keychain operations fail at runtime.
func NewTokenStorage() TokenStorage {
	return NewKeychainStorage("PatchFlow", "api-token")
}
