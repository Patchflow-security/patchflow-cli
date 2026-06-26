package osv

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/patchflow/patchflow-cli/internal/analysis"
)

// DefaultCacheTTL is the default time-to-live for cached OSV responses.
const DefaultCacheTTL = 24 * time.Hour

// Cache stores OSV vulnerability responses on disk so repeated scans of the
// same project skip API calls for unchanged dependencies.
type Cache struct {
	dir string
	ttl time.Duration
}

// cacheEntry is the on-disk JSON structure for a single cached response.
type cacheEntry struct {
	CachedAt time.Time        `json:"cached_at"`
	Vulns    []Vulnerability  `json:"vulns"`
}

// NewCache creates a new disk-backed cache rooted at rootDir/.patchflow/cache/osv.
func NewCache(rootDir string) *Cache {
	return &Cache{
		dir: filepath.Join(rootDir, ".patchflow", "cache", "osv"),
		ttl: DefaultCacheTTL,
	}
}

// Get returns the cached vulnerabilities for key if present and not expired.
// A miss or any error returns (nil, false); cache failures never block scanning.
func (c *Cache) Get(key string) ([]Vulnerability, bool) {
	if c == nil || key == "" {
		return nil, false
	}
	path := c.entryPath(key)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var entry cacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		// Corrupted cache file — remove it and treat as a miss.
		_ = os.Remove(path)
		return nil, false
	}
	if time.Since(entry.CachedAt) > c.ttl {
		return nil, false
	}
	return entry.Vulns, true
}

// Set saves vulnerabilities for key to disk. The cache directory is created
// lazily on the first Set call. Any error is ignored; cache failures never
// block scanning.
func (c *Cache) Set(key string, vulns []Vulnerability) {
	if c == nil || key == "" {
		return
	}
	if err := os.MkdirAll(c.dir, 0o755); err != nil {
		return
	}
	entry := cacheEntry{
		CachedAt: time.Now(),
		Vulns:    vulns,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	path := c.entryPath(key)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return
	}
}

// cacheKey computes a SHA256 hash of "ecosystem:name:version" for a dependency.
func cacheKey(dep analysis.Dependency) string {
	eco := ecosystemToOSV(dep.Ecosystem)
	raw := fmt.Sprintf("%s:%s:%s", eco, dep.Name, dep.Version)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// entryPath returns the full path for a cache entry file.
func (c *Cache) entryPath(key string) string {
	return filepath.Join(c.dir, key+".json")
}
