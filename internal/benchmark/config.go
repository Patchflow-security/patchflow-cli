package benchmark

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Load reads and validates a benchmark config from a YAML file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read benchmark config %q: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse benchmark config %q: %w", path, err)
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	// Default the date to today if omitted.
	if cfg.Date == "" {
		cfg.Date = time.Now().UTC().Format("2006-01-02")
	}

	// Default the suite name.
	if cfg.Suite == "" {
		cfg.Suite = "patchflow-cli-benchmark"
	}

	// Default PatchFlow binary.
	if cfg.PatchFlow.Binary == "" {
		cfg.PatchFlow.Binary = "patchflow"
	}
	if cfg.PatchFlow.Profile == "" {
		cfg.PatchFlow.Profile = "standard"
	}

	return &cfg, nil
}

func (c *Config) validate() error {
	if len(c.Repos) == 0 {
		return fmt.Errorf("benchmark config has no repos")
	}
	seen := map[string]bool{}
	for i, r := range c.Repos {
		if r.Name == "" {
			return fmt.Errorf("repo #%d is missing a name", i)
		}
		if seen[r.Name] {
			return fmt.Errorf("duplicate repo name %q", r.Name)
		}
		seen[r.Name] = true
		if r.URL == "" && r.Path == "" {
			return fmt.Errorf("repo %q must have either url or path", r.Name)
		}
		switch r.Type {
		case RepoIntentionallyVulnerable, RepoHistoricalVulnerable, RepoCleanRealWorld:
		default:
			return fmt.Errorf("repo %q has invalid type %q (want: intentionally-vulnerable, historical-vulnerable, clean-real-world)", r.Name, r.Type)
		}
	}
	return nil
}

// PublishDetailFor returns whether per-finding detail may be published for a
// repo. It respects an explicit override; otherwise it defaults to true for
// intentionally-vulnerable and historical repos, false for clean real-world.
func (r RepoSpec) PublishDetailFor() bool {
	if r.PublishDetail != nil {
		return *r.PublishDetail
	}
	switch r.Type {
	case RepoIntentionallyVulnerable, RepoHistoricalVulnerable:
		return true
	default:
		return false
	}
}

// ResultsRoot resolves the results directory, defaulting to "results/<YYYY-MM>/".
func (c *Config) ResultsRoot() string {
	if c.ResultsDir != "" {
		return c.ResultsDir
	}
	month := c.Date
	if len(month) >= 7 {
		month = month[:7] // YYYY-MM
	}
	return filepath.Join("results", month)
}

// WorkRoot resolves the working directory for clones, defaulting to ".bench-work".
func (c *Config) WorkRoot() string {
	if c.WorkDir != "" {
		return c.WorkDir
	}
	return ".bench-work"
}
