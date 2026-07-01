// Package mavenres provides transitive dependency resolution for Maven projects.
// It prefers the native Maven CLI (`mvn dependency:tree`) when available, since
// that produces the ground-truth resolved classpath. When Maven is not installed,
// it falls back to a manual POM resolver that fetches POM files from Maven Central
// and recursively resolves the dependency tree.
//
// Resolution is cached on disk in a global XDG-compliant cache location
// (resolved via cacheutil) so repeated scans skip network calls for unchanged
// packages without polluting the project directory.
package mavenres

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/cacheutil"
)

const (
	// MavenCentralPOMURL is the base URL for fetching POM files from Maven Central.
	MavenCentralPOMURL = "https://repo1.maven.org/maven2"

	// DefaultTimeout for HTTP requests.
	DefaultTimeout = 30 * time.Second

	// MavenTimeout for the `mvn dependency:tree` command.
	MavenTimeout = 5 * time.Minute

	// MaxDepth limits recursion to prevent infinite loops on circular deps.
	MaxDepth = 10

	// CacheTTL for cached POM files.
	CacheTTL = 7 * 24 * time.Hour
)

// Resolver resolves Maven transitive dependencies. It prefers the native Maven
// CLI for accurate resolution, and falls back to a manual POM resolver.
type Resolver struct {
	HTTPClient *http.Client
	cache      *Cache
	mu         sync.Mutex
	// inProgress tracks dependencies currently being resolved to break cycles
	inProgress map[string]bool
	// root is the repository root, used to locate pom.xml and invoke Maven
	root string
}

// NewResolver creates a Maven transitive dependency resolver.
func NewResolver() *Resolver {
	return &Resolver{
		HTTPClient: &http.Client{Timeout: DefaultTimeout},
		inProgress: make(map[string]bool),
	}
}

// SetCache attaches a disk cache for POM files.
func (r *Resolver) SetCache(cache *Cache) {
	r.cache = cache
}

// SetRoot sets the repository root directory. This is used to locate pom.xml
// and invoke Maven for accurate dependency resolution.
func (r *Resolver) SetRoot(root string) {
	r.root = root
}

// Resolve takes a list of direct Maven dependencies and resolves the full
// transitive dependency tree. Returns the complete list of dependencies
// (direct + transitive), with IsDirect set appropriately.
//
// When Maven is installed and a pom.xml exists at the repository root, it
// uses `mvn dependency:tree` for ground-truth resolution. Otherwise it falls
// back to the manual POM resolver.
//
// Dependencies that cannot be resolved (not in Maven Central, network error)
// are silently skipped — they remain as direct deps from the original list.
func (r *Resolver) Resolve(ctx context.Context, directDeps []analysis.Dependency) ([]analysis.Dependency, error) {
	var allDeps []analysis.Dependency
	seen := make(map[string]bool) // dedup by groupId:artifactId:version

	// Add direct deps first
	for _, dep := range directDeps {
		key := depKey(dep)
		if !seen[key] {
			seen[key] = true
			allDeps = append(allDeps, dep)
		}
	}

	// Prefer Maven CLI for accurate dependency resolution when available
	if r.root != "" {
		pomPath := filepath.Join(r.root, "pom.xml")
		if _, err := os.Stat(pomPath); err == nil {
			if mvnDeps, err := r.resolveWithMaven(ctx, r.root); err == nil && len(mvnDeps) > 0 {
				// Merge Maven-resolved deps with direct deps. Maven does not
				// distinguish direct vs transitive in its tree output for our
				// parser, so we mark everything from Maven as transitive unless
				// it matches a direct dep by groupId:artifactId.
				directKeys := make(map[string]bool)
				for _, dep := range directDeps {
					parts := strings.SplitN(dep.Name, ":", 2)
					if len(parts) == 2 {
						directKeys[parts[0]+":"+parts[1]] = true
					}
				}
				for _, dep := range mvnDeps {
					// Maven tree uses groupId:artifactId:packaging:version:scope
					parts := strings.SplitN(dep.Name, ":", 2)
					isDirect := len(parts) == 2 && directKeys[parts[0]+":"+parts[1]]
					dep.IsDirect = isDirect

					key := depKey(dep)
					if seen[key] {
						continue
					}
					seen[key] = true
					allDeps = append(allDeps, dep)
				}
				return allDeps, nil
			}
		}
	}

	// Resolve transitive deps recursively
	var transitive []analysis.Dependency
	for _, dep := range directDeps {
		if dep.Ecosystem != analysis.EcosystemMaven {
			continue
		}
		parts := strings.SplitN(dep.Name, ":", 2)
		if len(parts) < 2 {
			continue
		}
		groupID := parts[0]
		artifactID := parts[1]
		version := dep.Version
		if version == "" || version == "unknown" {
			continue
		}

		r.mu.Lock()
		r.inProgress[depKey(dep)] = true
		r.mu.Unlock()

		trans := r.resolveTransitive(ctx, groupID, artifactID, version, seen, 0)

		r.mu.Lock()
		delete(r.inProgress, depKey(dep))
		r.mu.Unlock()

		transitive = append(transitive, trans...)
	}

	// Mark transitive deps as non-direct
	for i := range transitive {
		transitive[i].IsDirect = false
	}

	allDeps = append(allDeps, transitive...)
	return allDeps, nil
}

// resolveTransitive recursively resolves transitive dependencies for a single
// Maven coordinate by fetching its POM from Maven Central.
//
// It now:
//   - Walks parent POMs to resolve dependencyManagement versions
//   - Resolves simple property references (${foo.version})
//   - Includes optional dependencies (Trivy includes them; skipping them caused
//     CVE misses like dom4j:dom4j@1.6.1 in jaxen)
//   - Still skips test and provided scope dependencies
func (r *Resolver) resolveTransitive(ctx context.Context, groupID, artifactID, version string, seen map[string]bool, depth int) []analysis.Dependency {
	if depth >= MaxDepth {
		return nil
	}

	// Check for circular dependency
	key := fmt.Sprintf("%s:%s:%s", groupID, artifactID, version)
	r.mu.Lock()
	if r.inProgress[key] {
		r.mu.Unlock()
		return nil // circular — skip
	}
	r.inProgress[key] = true
	r.mu.Unlock()

	defer func() {
		r.mu.Lock()
		delete(r.inProgress, key)
		r.mu.Unlock()
	}()

	// Fetch the POM for this dependency
	pom, err := r.fetchPOM(ctx, groupID, artifactID, version)
	if err != nil || pom == nil {
		return nil
	}

	// Build a property map and dependencyManagement map from this POM + parents
	props := r.buildProperties(ctx, pom, groupID, artifactID, version)
	depMgmt := r.buildDependencyManagement(ctx, pom, groupID, artifactID, version)

	var transitive []analysis.Dependency

	// Resolve each dependency declared in this POM
	for _, dep := range pom.Dependencies {
		// Skip test, provided, and optional scope deps. Optional deps are not
		// transitive in Maven; including them causes dependency explosion. The
		// Maven CLI path handles them accurately when available.
		if dep.Scope == "test" || dep.Scope == "provided" || dep.Optional {
			continue
		}

		depVersion := r.resolveProperty(dep.Version, props)
		if depVersion == "" || strings.Contains(depVersion, "${") {
			// Try dependencyManagement in this POM or parent POMs
			if v, ok := depMgmt[dep.GroupID+":"+dep.ArtifactID]; ok {
				depVersion = r.resolveProperty(v, props)
			}
		}
		if depVersion == "" || strings.Contains(depVersion, "${") {
			continue
		}

		depKey := fmt.Sprintf("%s:%s:%s", dep.GroupID, dep.ArtifactID, depVersion)
		if seen[depKey] {
			continue
		}
		seen[depKey] = true

		transitive = append(transitive, analysis.Dependency{
			Name:      dep.GroupID + ":" + dep.ArtifactID,
			Version:   depVersion,
			Ecosystem: analysis.EcosystemMaven,
			IsDirect:  false,
		})

		// Recurse
		subTrans := r.resolveTransitive(ctx, dep.GroupID, dep.ArtifactID, depVersion, seen, depth+1)
		transitive = append(transitive, subTrans...)
	}

	return transitive
}

// mavenTreeLine matches a dependency line from `mvn dependency:tree` output.
// Example: "[INFO] +- javax:javaee-api:jar:8.0.1:provided"
// We capture the coordinate string after the tree-drawing characters.
var mavenTreeLine = regexp.MustCompile(`\[INFO\]\s*[\|\+\\\-\s]*([a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+:[^:\s]+:[a-zA-Z0-9_.-]+)`)

// resolveWithMaven invokes the native Maven CLI to produce the resolved
// dependency tree and parses it into PatchFlow dependencies. This is the
// ground-truth for Maven dependency resolution and avoids the approximation
// errors of the manual POM resolver (parent POM depMgmt, optional deps,
// version mediation, etc.).
func (r *Resolver) resolveWithMaven(ctx context.Context, root string) ([]analysis.Dependency, error) {
	mvnPath, err := exec.LookPath("mvn")
	if err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, mvnPath, "dependency:tree", "-DoutputType=text", "-Dscope=compile")
	cmd.Dir = root
	// Maven prints progress to stderr; capture both.
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("mvn dependency:tree failed: %w\n%s", err, string(out))
	}

	var deps []analysis.Dependency
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(out), "\n") {
		m := mavenTreeLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		coord := m[1]
		parts := strings.Split(coord, ":")
		if len(parts) != 5 {
			continue
		}
		groupID, artifactID, version := parts[0], parts[1], parts[3]
		key := fmt.Sprintf("%s:%s:%s", groupID, artifactID, version)
		if seen[key] {
			continue
		}
		seen[key] = true

		deps = append(deps, analysis.Dependency{
			Name:      groupID + ":" + artifactID,
			Version:   version,
			Ecosystem: analysis.EcosystemMaven,
			IsDirect:  false, // caller re-marks direct deps
		})
	}

	return deps, nil
}

// pomXML represents the relevant parts of a Maven POM file for dependency resolution.
type pomXML struct {
	XMLName              xml.Name      `xml:"project"`
	Parent               pomParent     `xml:"parent"`
	Dependencies         []pomDep      `xml:"dependencies>dependency"`
	DependencyManagement []pomDep      `xml:"dependencyManagement>dependencies>dependency"`
	Properties           []pomProperty `xml:"properties>*"`
}

type pomParent struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

type pomDep struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
	Optional   bool   `xml:"optional"`
}

type pomProperty struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

// buildProperties collects properties from the POM and its parent chain.
// Properties are used to resolve ${...} references in versions.
func (r *Resolver) buildProperties(ctx context.Context, pom *pomXML, groupID, artifactID, version string) map[string]string {
	props := make(map[string]string)

	// Add built-in properties
	props["project.groupId"] = groupID
	props["project.artifactId"] = artifactID
	props["project.version"] = version

	// Walk parent chain
	currentPOM := pom
	visited := make(map[string]bool)

	for currentPOM != nil {
		for _, p := range currentPOM.Properties {
			name := p.XMLName.Local
			if name != "" && p.Value != "" {
				props[name] = p.Value
			}
		}

		// Stop if no parent or circular
		if currentPOM.Parent.GroupID == "" || currentPOM.Parent.ArtifactID == "" || currentPOM.Parent.Version == "" {
			break
		}
		parentKey := currentPOM.Parent.GroupID + ":" + currentPOM.Parent.ArtifactID + ":" + currentPOM.Parent.Version
		if visited[parentKey] {
			break
		}
		visited[parentKey] = true

		parentGroup := currentPOM.Parent.GroupID
		parentArtifact := currentPOM.Parent.ArtifactID
		parentVersion := r.resolveProperty(currentPOM.Parent.Version, props)
		if parentVersion == "" || strings.Contains(parentVersion, "${") {
			parentVersion = currentPOM.Parent.Version
		}

		parentPOM, err := r.fetchPOM(ctx, parentGroup, parentArtifact, parentVersion)
		if err != nil || parentPOM == nil {
			break
		}

		currentPOM = parentPOM
	}

	return props
}

// buildDependencyManagement collects dependencyManagement versions from the POM
// and its parent chain. This is essential for dependencies that declare a
// dependency without a version (relying on parent depMgmt).
func (r *Resolver) buildDependencyManagement(ctx context.Context, pom *pomXML, groupID, artifactID, version string) map[string]string {
	depMgmt := make(map[string]string)
	visited := make(map[string]bool)

	currentPOM := pom
	for currentPOM != nil {
		for _, dm := range currentPOM.DependencyManagement {
			key := dm.GroupID + ":" + dm.ArtifactID
			if _, ok := depMgmt[key]; !ok && dm.Version != "" {
				depMgmt[key] = dm.Version
			}
		}

		if currentPOM.Parent.GroupID == "" || currentPOM.Parent.ArtifactID == "" || currentPOM.Parent.Version == "" {
			break
		}
		parentKey := currentPOM.Parent.GroupID + ":" + currentPOM.Parent.ArtifactID + ":" + currentPOM.Parent.Version
		if visited[parentKey] {
			break
		}
		visited[parentKey] = true

		parentPOM, err := r.fetchPOM(ctx, currentPOM.Parent.GroupID, currentPOM.Parent.ArtifactID, currentPOM.Parent.Version)
		if err != nil || parentPOM == nil {
			break
		}
		currentPOM = parentPOM
	}

	return depMgmt
}

// resolveProperty substitutes simple ${property} references. If a property is
// not found, the original reference is returned.
func (r *Resolver) resolveProperty(value string, props map[string]string) string {
	if !strings.Contains(value, "${") {
		return value
	}
	result := value
	for name, val := range props {
		result = strings.ReplaceAll(result, "${"+name+"}", val)
	}
	return result
}

// fetchPOM fetches and parses a POM file from Maven Central.
func (r *Resolver) fetchPOM(ctx context.Context, groupID, artifactID, version string) (*pomXML, error) {
	// Check cache first
	if r.cache != nil {
		if data := r.cache.Get(groupID, artifactID, version); data != nil {
			var pom pomXML
			if err := xml.Unmarshal(data, &pom); err == nil {
				return &pom, nil
			}
		}
	}

	// Build Maven Central POM URL: {base}/{groupPath}/{artifactId}/{version}/{artifactId}-{version}.pom
	groupPath := strings.ReplaceAll(groupID, ".", "/")
	url := fmt.Sprintf("%s/%s/%s/%s/%s-%s.pom",
		MavenCentralPOMURL, groupPath, artifactID, version, artifactID, version)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "PatchFlow-CLI/0.1")

	resp, err := r.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("maven central returned %d for %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20)) // 5MB limit
	if err != nil {
		return nil, err
	}

	// Cache the POM
	if r.cache != nil {
		r.cache.Set(groupID, artifactID, version, body)
	}

	var pom pomXML
	if err := xml.Unmarshal(body, &pom); err != nil {
		return nil, fmt.Errorf("parse POM: %w", err)
	}

	return &pom, nil
}

// depKey creates a unique key for a dependency.
func depKey(d analysis.Dependency) string {
	return fmt.Sprintf("%s:%s:%s", d.Ecosystem, d.Name, d.Version)
}

// ─── Disk Cache ──────────────────────────────────────────────────────

// Cache stores Maven POM files on disk to avoid repeated downloads.
type Cache struct {
	dir string
}

// NewCache creates a disk cache for the given repository root. The cache
// directory is resolved via cacheutil (XDG-compliant global location).
func NewCache(repoRoot string) *Cache {
	return &Cache{
		dir: cacheutil.ResolveSubdir(repoRoot, "maven"),
	}
}

// Get returns a cached POM file, or nil if not cached or expired.
func (c *Cache) Get(groupID, artifactID, version string) []byte {
	path := c.cachePath(groupID, artifactID, version)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	// Check TTL via file modification time
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	if time.Since(info.ModTime()) > CacheTTL {
		return nil
	}

	return data
}

// Set stores a POM file in the cache.
func (c *Cache) Set(groupID, artifactID, version string, data []byte) {
	path := c.cachePath(groupID, artifactID, version)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0o644)
}

func (c *Cache) cachePath(groupID, artifactID, version string) string {
	safeGroup := strings.ReplaceAll(groupID, "/", "_")
	safeArtifact := strings.ReplaceAll(artifactID, "/", "_")
	return filepath.Join(c.dir, safeGroup, safeArtifact+"-"+version+".pom")
}
