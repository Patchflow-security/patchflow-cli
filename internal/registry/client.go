// Package registry provides package registry metadata lookup for license
// information. It queries npm, PyPI, and Maven Central registries to fetch
// license data for dependencies where the lockfile/manifest does not include
// license fields.
//
// All lookups are cached on disk in a global XDG-compliant cache location
// (resolved via cacheutil) so repeated scans skip network calls for unchanged
// packages without polluting the project directory.
package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/cacheutil"
	"gopkg.in/yaml.v3"
)

const (
	// Registry API endpoints.
	NPMRegistryURL  = "https://registry.npmjs.org"
	PyPIRegistryURL = "https://pypi.org/pypi"
	MavenCentralURL = "https://search.maven.org/solrsearch/select"
	DefaultTimeout  = 30 * time.Second

	// CacheTTL is how long registry metadata is cached before re-fetching.
	CacheTTL = 24 * time.Hour
)

// MetadataClient fetches package license info from public registries.
type MetadataClient struct {
	HTTPClient *http.Client
	cache      *Cache
}

// NewMetadataClient creates a registry metadata client with default settings.
func NewMetadataClient() *MetadataClient {
	return &MetadataClient{
		HTTPClient: &http.Client{Timeout: DefaultTimeout},
	}
}

// SetCache attaches an optional disk cache.
func (c *MetadataClient) SetCache(cache *Cache) {
	c.cache = cache
}

// FetchLicenses fetches license info for all dependencies that don't already
// have a license string. Dependencies with a non-empty License field are
// skipped. Returns a map of dep name@version -> license string.
//
// Lookups are parallelized per ecosystem with a concurrency limit to avoid
// overwhelming registry APIs. Network errors for individual packages are
// non-fatal — the function returns whatever it can fetch.
func (c *MetadataClient) FetchLicenses(ctx context.Context, deps []analysis.Dependency) map[string]string {
	results := make(map[string]string)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Semaphore to limit concurrent HTTP requests (avoid rate limiting).
	sem := make(chan struct{}, 10)

	for _, dep := range deps {
		if dep.License != "" {
			// Already have license info from the manifest — skip.
			mu.Lock()
			results[depKey(dep)] = dep.License
			mu.Unlock()
			continue
		}
		if dep.Name == "" || dep.Version == "" {
			continue
		}

		wg.Add(1)
		go func(d analysis.Dependency) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			license := c.fetchLicenseForDep(ctx, d)
			if license != "" {
				mu.Lock()
				results[depKey(d)] = license
				mu.Unlock()
			}
		}(dep)
	}

	wg.Wait()
	return results
}

// depKey creates a unique key for a dependency: "ecosystem:name@version".
func depKey(d analysis.Dependency) string {
	if d.Repository != "" {
		return fmt.Sprintf("%s:%s:%s@%s", d.Ecosystem, d.Repository, d.Name, d.Version)
	}
	return fmt.Sprintf("%s:%s@%s", d.Ecosystem, d.Name, d.Version)
}

// fetchLicenseForDep dispatches to the appropriate registry based on ecosystem.
func (c *MetadataClient) fetchLicenseForDep(ctx context.Context, dep analysis.Dependency) string {
	// Check cache first
	if c.cache != nil {
		if cached := c.cache.Get(dep); cached != "" {
			return cached
		}
	}

	var license string
	switch dep.Ecosystem {
	case analysis.EcosystemNPM:
		license = c.fetchNPMLicense(ctx, dep.Name, dep.Version)
	case analysis.EcosystemPyPI:
		license = c.fetchPyPILicense(ctx, dep.Name, dep.Version)
	case analysis.EcosystemMaven:
		license = c.fetchMavenLicense(ctx, dep.Name, dep.Version)
	case analysis.EcosystemRubyGems:
		license = c.fetchRubyGemsLicense(ctx, dep.Name, dep.Version)
	case analysis.EcosystemPackagist:
		license = c.fetchPackagistLicense(ctx, dep.Name, dep.Version)
	case analysis.EcosystemHelm:
		license = c.fetchHelmLicense(ctx, dep.Name, dep.Version, dep.Repository)
	default:
		// Go, Cargo: license info is in the manifest itself (go.mod, Cargo.toml)
		return ""
	}

	// Cache the result (including empty results to avoid re-fetching)
	if c.cache != nil {
		c.cache.Set(dep, license)
	}

	return license
}

// fetchHelmLicense fetches license metadata from a Helm repository index.yaml.
func (c *MetadataClient) fetchHelmLicense(ctx context.Context, name, version, repository string) string {
	if repository == "" || strings.HasPrefix(repository, "oci://") {
		return ""
	}

	url := strings.TrimRight(repository, "/") + "/index.yaml"
	body, err := c.httpGet(ctx, url)
	if err != nil {
		return ""
	}

	var index struct {
		Entries map[string][]struct {
			Version     string            `yaml:"version"`
			Annotations map[string]string `yaml:"annotations"`
		} `yaml:"entries"`
	}
	if err := yaml.Unmarshal(body, &index); err != nil {
		return ""
	}

	charts := index.Entries[name]
	for _, chart := range charts {
		if chart.Version == version {
			return helmLicenseFromAnnotations(chart.Annotations)
		}
	}
	if len(charts) > 0 {
		return helmLicenseFromAnnotations(charts[0].Annotations)
	}
	return ""
}

func helmLicenseFromAnnotations(annotations map[string]string) string {
	for _, key := range []string{
		"artifacthub.io/license",
		"artifacthub.io/licenses",
		"license",
		"licenses",
	} {
		if value := strings.TrimSpace(annotations[key]); value != "" {
			return value
		}
	}
	return ""
}

// fetchNPMLicense fetches license from the npm registry.
// API: GET https://registry.npmjs.org/{package}/{version}
func (c *MetadataClient) fetchNPMLicense(ctx context.Context, name, version string) string {
	// Scoped packages (@scope/pkg) need the scope encoded in the URL.
	apiName := name
	if strings.HasPrefix(name, "@") {
		// npm registry expects scoped packages with unencoded slash
		// but some CDNs require encoding. Use the plain form.
		apiName = name
	}

	url := fmt.Sprintf("%s/%s/%s", NPMRegistryURL, apiName, version)
	body, err := c.httpGet(ctx, url)
	if err != nil {
		return ""
	}

	var resp struct {
		License  string `json:"license"`
		Licenses []struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"licenses"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return ""
	}

	if resp.License != "" {
		return resp.License
	}
	if len(resp.Licenses) > 0 && resp.Licenses[0].Type != "" {
		return resp.Licenses[0].Type
	}
	return ""
}

// fetchPyPILicense fetches license from PyPI JSON API.
// API: GET https://pypi.org/pypi/{package}/{version}/json
func (c *MetadataClient) fetchPyPILicense(ctx context.Context, name, version string) string {
	url := fmt.Sprintf("%s/%s/%s/json", PyPIRegistryURL, name, version)
	body, err := c.httpGet(ctx, url)
	if err != nil {
		// Try without version (latest)
		url = fmt.Sprintf("%s/%s/json", PyPIRegistryURL, name)
		body, err = c.httpGet(ctx, url)
		if err != nil {
			return ""
		}
	}

	var resp struct {
		Info struct {
			License     string   `json:"license"`
			Classifiers []string `json:"classifiers"`
		} `json:"info"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return ""
	}

	if resp.Info.License != "" && resp.Info.License != "UNKNOWN" {
		return resp.Info.License
	}

	// Fallback: extract from classifiers (e.g., "License :: OSI Approved :: MIT License")
	for _, c := range resp.Info.Classifiers {
		if strings.HasPrefix(c, "License ::") {
			parts := strings.Split(c, " :: ")
			if len(parts) >= 3 {
				return parts[len(parts)-1]
			}
		}
	}
	return ""
}

// fetchMavenLicense fetches license from Maven Central search API.
// API: GET https://search.maven.org/solrsearch/select?q=g:{groupId}+AND+a:{artifactId}&rows=1&wt=json
func (c *MetadataClient) fetchMavenLicense(ctx context.Context, name, version string) string {
	// Maven coordinates are groupId:artifactId
	parts := strings.SplitN(name, ":", 2)
	if len(parts) < 2 {
		return ""
	}
	groupID := parts[0]
	artifactID := parts[1]

	url := fmt.Sprintf("%s?q=g:%s+AND+a:%s&rows=1&wt=json", MavenCentralURL, groupID, artifactID)
	body, err := c.httpGet(ctx, url)
	if err != nil {
		return ""
	}

	var resp struct {
		Response struct {
			Docs []struct {
				Licenses []string `json:"licenses"`
			} `json:"docs"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return ""
	}

	if len(resp.Response.Docs) > 0 && len(resp.Response.Docs[0].Licenses) > 0 {
		return resp.Response.Docs[0].Licenses[0]
	}
	return ""
}

// fetchRubyGemsLicense fetches license from RubyGems API.
// API: GET https://rubygems.org/api/v1/gems/{name}.json
func (c *MetadataClient) fetchRubyGemsLicense(ctx context.Context, name, version string) string {
	url := fmt.Sprintf("https://rubygems.org/api/v1/gems/%s.json", name)
	body, err := c.httpGet(ctx, url)
	if err != nil {
		return ""
	}

	var resp struct {
		Licenses []string `json:"licenses"`
		License  string   `json:"license"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return ""
	}

	if len(resp.Licenses) > 0 {
		return resp.Licenses[0]
	}
	return resp.License
}

// fetchPackagistLicense fetches license from Packagist API.
// API: GET https://repo.packagist.org/p2/{vendor/package}.json
func (c *MetadataClient) fetchPackagistLicense(ctx context.Context, name, version string) string {
	url := fmt.Sprintf("https://repo.packagist.org/p2/%s.json", name)
	body, err := c.httpGet(ctx, url)
	if err != nil {
		return ""
	}

	var resp struct {
		Packages map[string][]struct {
			Version string   `json:"version"`
			License []string `json:"license"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return ""
	}

	if pkgs, ok := resp.Packages[name]; ok {
		for _, p := range pkgs {
			if p.Version == version && len(p.License) > 0 {
				return p.License[0]
			}
		}
		// Fallback: first entry
		if len(pkgs) > 0 && len(pkgs[0].License) > 0 {
			return pkgs[0].License[0]
		}
	}
	return ""
}

// httpGet performs an HTTP GET request and returns the response body.
func (c *MetadataClient) httpGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, application/x-yaml, text/yaml, */*")
	req.Header.Set("User-Agent", "PatchFlow-CLI/0.1")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned %d for %s", resp.StatusCode, url)
	}

	return io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
}

// ─── Disk Cache ──────────────────────────────────────────────────────

// Cache stores registry metadata on disk to avoid repeated API calls.
type Cache struct {
	dir string
	mu  sync.RWMutex
}

// NewCache creates a disk cache for the given repository root. The cache
// directory is resolved via cacheutil (XDG-compliant global location).
func NewCache(repoRoot string) *Cache {
	dir := cacheutil.ResolveSubdir(repoRoot, "registry")
	return &Cache{dir: dir}
}

// Get returns a cached license string, or "" if not cached or expired.
func (c *Cache) Get(dep analysis.Dependency) string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	path := c.cachePath(dep)
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}

	var entry cacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return ""
	}

	// Check TTL
	if time.Since(entry.FetchedAt) > CacheTTL {
		return ""
	}

	return entry.License
}

// Set stores a license string in the cache.
func (c *Cache) Set(dep analysis.Dependency, license string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	dir := filepath.Dir(c.cachePath(dep))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}

	entry := cacheEntry{
		License:   license,
		FetchedAt: time.Now(),
		Ecosystem: string(dep.Ecosystem),
		Package:   dep.Name,
		Version:   dep.Version,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	_ = os.WriteFile(c.cachePath(dep), data, 0o644)
}

type cacheEntry struct {
	License   string    `json:"license"`
	FetchedAt time.Time `json:"fetched_at"`
	Ecosystem string    `json:"ecosystem"`
	Package   string    `json:"package"`
	Version   string    `json:"version"`
}

func (c *Cache) cachePath(dep analysis.Dependency) string {
	// Sanitize package name for filesystem (scoped npm packages have @ and /)
	safeName := strings.ReplaceAll(dep.Name, "/", "_")
	safeName = strings.ReplaceAll(safeName, "@", "_at_")
	if dep.Repository != "" {
		replacer := strings.NewReplacer("/", "_", ":", "_", "@", "_at_", "?", "_", "&", "_", "=", "_")
		safeName = replacer.Replace(dep.Repository) + "_" + safeName
	}
	return filepath.Join(c.dir, string(dep.Ecosystem), safeName+"@"+dep.Version+".json")
}
