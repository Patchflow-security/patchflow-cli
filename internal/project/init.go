// Package project handles the initialization of a PatchFlow project directory
// (.patchflow/) with configuration, baselines, and reports subdirectories.
// Cache data is stored in a global XDG-compliant location (~/.cache/patchflow/)
// and is NOT created under .patchflow/ — this keeps project directories clean.
package project

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// ProjectConfig is the .patchflow/config.yml structure.
type ProjectConfig struct {
	ProjectID      string `yaml:"project_id,omitempty"`
	OrganizationID string `yaml:"organization_id,omitempty"`
	BackendURL     string `yaml:"backend_url,omitempty"`
	Mode           string `yaml:"mode"`

	Analysis   AnalysisConfig   `yaml:"analysis"`
	Privacy    PrivacyConfig    `yaml:"privacy"`
	Ignore     IgnoreConfig     `yaml:"ignore"`
	Frameworks FrameworksConfig `yaml:"frameworks"`
}

// AnalysisConfig controls which analyzers run and their behavior.
type AnalysisConfig struct {
	DefaultProfile      string `yaml:"default_profile"`
	ChangedFilesOnly    bool   `yaml:"changed_files_only"`
	IncludeReachability bool   `yaml:"include_reachability"`
	IncludeSAST         bool   `yaml:"include_sast"`
	IncludeSecrets      bool   `yaml:"include_secrets"`
	IncludeFixProposals bool   `yaml:"include_fix_proposals"`
}

// PrivacyConfig controls data handling.
type PrivacyConfig struct {
	RedactSecrets        bool `yaml:"redact_secrets"`
	SendCodeToRemoteAI   bool `yaml:"send_code_to_remote_ai"`
	RetainLocalCacheDays int  `yaml:"retain_local_cache_days"`
}

// IgnoreConfig specifies paths to exclude from analysis.
type IgnoreConfig struct {
	Paths []string `yaml:"paths"`
}

// FrameworksConfig controls framework pack auto-detection and explicit pack
// selection at the project level.
type FrameworksConfig struct {
	AutoDetect bool     `yaml:"auto_detect"`
	Enabled    []string `yaml:"enabled,omitempty"`
	Disabled   []string `yaml:"disabled,omitempty"`
}

// DefaultConfig returns the default project configuration.
func DefaultConfig() ProjectConfig {
	return ProjectConfig{
		Mode: "local",
		Analysis: AnalysisConfig{
			DefaultProfile:      "standard",
			ChangedFilesOnly:    true,
			IncludeReachability: true,
			IncludeSAST:         true,
			IncludeSecrets:      true,
			IncludeFixProposals: false,
		},
		Privacy: PrivacyConfig{
			RedactSecrets:        true,
			SendCodeToRemoteAI:   false,
			RetainLocalCacheDays: 7,
		},
		Ignore: IgnoreConfig{
			Paths: []string{
				"node_modules/**",
				"dist/**",
				"build/**",
				"coverage/**",
				"vendor/**",
				"*.lock",
				".git/**",
			},
		},
		Frameworks: FrameworksConfig{
			AutoDetect: true,
		},
	}
}

// InitResult contains the result of an initialization.
type InitResult struct {
	ConfigPath string `json:"config_path"`
	Dir        string `json:"dir"`
	Created    bool   `json:"created"`
}

// Init creates the .patchflow/ directory structure in the given root.
// If the directory already exists, it returns the existing path without overwriting.
func Init(root string) (*InitResult, error) {
	pfDir := filepath.Join(root, ".patchflow")
	configPath := filepath.Join(pfDir, "config.yml")

	// Check if already initialized
	if _, err := os.Stat(pfDir); err == nil {
		return &InitResult{
			ConfigPath: configPath,
			Dir:        pfDir,
			Created:    false,
		}, nil
	}

	// Create directory structure.
	// Note: cache/ is NOT created here — it lives in a global XDG-compliant
	// location (~/.cache/patchflow/<project-hash>/) to avoid polluting the
	// project directory. Only project-specific artifacts (baselines, reports)
	// remain under .patchflow/.
	subdirs := []string{"baselines", "reports"}
	if err := os.MkdirAll(pfDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create .patchflow directory: %w", err)
	}
	for _, sub := range subdirs {
		path := filepath.Join(pfDir, sub)
		if err := os.MkdirAll(path, 0755); err != nil {
			return nil, fmt.Errorf("failed to create %s: %w", sub, err)
		}
	}

	// Write config.yml
	cfg := DefaultConfig()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return nil, fmt.Errorf("failed to write config.yml: %w", err)
	}

	// Write state.json
	state := map[string]interface{}{
		"initialized_at": time.Now().UTC().Format(time.RFC3339),
		"last_scan":      "",
		"baseline":       "",
	}
	stateData, _ := yaml.Marshal(state)
	statePath := filepath.Join(pfDir, "state.json")
	_ = os.WriteFile(statePath, stateData, 0600)

	// Write .gitignore (keep reports and baselines tracked, nothing to ignore
	// since cache is no longer stored under .patchflow/)
	gitignoreContent := "# PatchFlow project directory\n# Reports and baselines are project artifacts.\n# Cache is stored globally at ~/.cache/patchflow/ (XDG-compliant).\n"
	gitignorePath := filepath.Join(pfDir, ".gitignore")
	_ = os.WriteFile(gitignorePath, []byte(gitignoreContent), 0644)

	return &InitResult{
		ConfigPath: configPath,
		Dir:        pfDir,
		Created:    true,
	}, nil
}

// LoadConfig reads the .patchflow/config.yml file.
func LoadConfig(root string) (*ProjectConfig, error) {
	configPath := filepath.Join(root, ".patchflow", "config.yml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var cfg ProjectConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config.yml: %w", err)
	}
	return &cfg, nil
}

// IsInitialized checks whether .patchflow/ exists in the given root.
func IsInitialized(root string) bool {
	pfDir := filepath.Join(root, ".patchflow")
	_, err := os.Stat(pfDir)
	return err == nil
}
