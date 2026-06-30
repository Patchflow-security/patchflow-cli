package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// DefaultProfileName is the name of the default profile.
const DefaultProfileName = "default"

// Profile holds configuration settings for a single profile.
// Token is intentionally excluded; tokens are stored in the system keychain.
type Profile struct {
	Name     string `yaml:"name"`
	APIURL   string `yaml:"api_url,omitempty"`
	Org      string `yaml:"org,omitempty"`
	LogLevel string `yaml:"log_level,omitempty"`
}

// Profiles manages a collection of named profiles and the active selection.
type Profiles struct {
	Active string             `yaml:"active"`
	Items  map[string]Profile `yaml:"items"`
}

// GetProfilesPath returns the path to the profiles YAML file.
func GetProfilesPath() string {
	return filepath.Join(GetConfigDir(), "profiles.yaml")
}

// LoadProfiles reads profiles from disk.
// If the file does not exist, it returns an empty Profiles struct.
func LoadProfiles() (*Profiles, error) {
	path := GetProfilesPath()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Profiles{
				Active: "",
				Items:  make(map[string]Profile),
			}, nil
		}
		return nil, fmt.Errorf("failed to read profiles: %w", err)
	}

	var p Profiles
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("failed to unmarshal profiles: %w", err)
	}

	if p.Items == nil {
		p.Items = make(map[string]Profile)
	}

	return &p, nil
}

// SaveProfiles writes profiles to disk, creating the config directory if needed.
func SaveProfiles(p *Profiles) error {
	if p.Items == nil {
		p.Items = make(map[string]Profile)
	}

	configDir := GetConfigDir()
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	path := GetProfilesPath()
	data, err := yaml.Marshal(p)
	if err != nil {
		return fmt.Errorf("failed to marshal profiles: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write profiles: %w", err)
	}

	return nil
}

// Get retrieves a profile by name.
func (p *Profiles) Get(name string) (Profile, bool) {
	prof, ok := p.Items[name]
	return prof, ok
}

// Set adds or updates a profile.
func (p *Profiles) Set(name string, profile Profile) {
	if p.Items == nil {
		p.Items = make(map[string]Profile)
	}
	profile.Name = name
	p.Items[name] = profile
}

// Delete removes a profile by name.
func (p *Profiles) Delete(name string) {
	if p.Items == nil {
		return
	}
	delete(p.Items, name)
}

// List returns sorted profile names.
func (p *Profiles) List() []string {
	if p.Items == nil {
		return nil
	}
	names := make([]string, 0, len(p.Items))
	for name := range p.Items {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
