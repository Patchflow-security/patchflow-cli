// Package manifest parses dependency manifest files and extracts package
// names and versions across multiple ecosystems (Go, npm, PyPI, Cargo, RubyGems, etc.).
package manifest

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/patchflow/patchflow-cli/internal/analysis"
)

// ManifestInfo represents a detected manifest file and its ecosystem.
type ManifestInfo struct {
	Path     string             `json:"path"`
	Ecosystem analysis.Ecosystem `json:"ecosystem"`
}

// KnownManifests maps manifest filenames to their ecosystem.
var KnownManifests = map[string]analysis.Ecosystem{
	"go.mod":            analysis.EcosystemGo,
	"package.json":      analysis.EcosystemNPM,
	"requirements.txt":  analysis.EcosystemPyPI,
	"pyproject.toml":    analysis.EcosystemPyPI,
	"setup.py":          analysis.EcosystemPyPI,
	"setup.cfg":         analysis.EcosystemPyPI,
	"Pipfile.lock":      analysis.EcosystemPyPI,
	"poetry.lock":       analysis.EcosystemPyPI,
	"uv.lock":           analysis.EcosystemPyPI,
	"Cargo.toml":        analysis.EcosystemCargo,
	"Gemfile":           analysis.EcosystemRubyGems,
	"Gemfile.lock":      analysis.EcosystemRubyGems,
	"composer.json":     analysis.EcosystemPackagist,
	"pom.xml":           analysis.EcosystemMaven,
	"build.gradle":      analysis.EcosystemMaven,
	"build.gradle.kts":  analysis.EcosystemMaven,
}

// SkipDirs are directories that should never be traversed.
var SkipDirs = map[string]bool{
	".git":         true,
	"vendor":       true,
	"node_modules": true,
	"dist":         true,
	"build":        true,
	"target":       true,
	".venv":        true,
	"venv":         true,
	"__pycache__":  true,
}

// Detect walks the filesystem from root and finds manifest files up to maxDepth
// subdirectories deep. Returns sorted results.
func Detect(root string, maxDepth int) ([]ManifestInfo, error) {
	if maxDepth < 0 {
		maxDepth = 0
	}

	var manifests []ManifestInfo

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable paths
		}

		rel, _ := filepath.Rel(root, path)
		if rel == "." {
			return nil
		}

		depth := strings.Count(rel, string(filepath.Separator))
		if d.IsDir() {
			if depth > maxDepth {
				return filepath.SkipDir
			}
			if SkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		name := d.Name()
		if eco, ok := KnownManifests[name]; ok {
			manifests = append(manifests, ManifestInfo{
				Path:     rel,
				Ecosystem: eco,
			})
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk %s: %w", root, err)
	}

	sort.Slice(manifests, func(i, j int) bool {
		return manifests[i].Path < manifests[j].Path
	})

	return manifests, nil
}

// Parse reads a manifest file and extracts dependencies.
// It dispatches to the appropriate parser based on the filename.
func Parse(path string) ([]analysis.Dependency, error) {
	name := filepath.Base(path)

	switch name {
	case "go.mod":
		return ParseGoMod(path)
	case "package.json":
		return ParsePackageJSON(path)
	case "requirements.txt":
		return ParseRequirementsTxt(path)
	case "pyproject.toml":
		return ParsePyProjectToml(path)
	case "setup.py":
		return ParseSetupPy(path)
	case "setup.cfg":
		return ParseSetupCfg(path)
	case "Pipfile.lock":
		return ParsePipfileLock(path)
	case "poetry.lock":
		return ParsePoetryLock(path)
	case "Cargo.toml":
		return ParseCargoToml(path)
	case "Gemfile":
		return ParseGemfile(path)
	case "Gemfile.lock":
		return ParseGemfileLock(path)
	case "composer.json":
		return ParseComposerJSON(path)
	case "pom.xml":
		return ParsePomXML(path)
	case "build.gradle", "build.gradle.kts":
		return ParseBuildGradle(path)
	default:
		return nil, nil
	}
}

// ParseAll parses all detected manifests in a repository root.
func ParseAll(root string, maxDepth int) ([]analysis.Dependency, []ManifestInfo, error) {
	manifests, err := Detect(root, maxDepth)
	if err != nil {
		return nil, nil, err
	}

	var allDeps []analysis.Dependency
	for _, m := range manifests {
		fullPath := filepath.Join(root, m.Path)
		deps, err := Parse(fullPath)
		if err != nil {
			continue // skip unparseable manifests
		}
		for i := range deps {
			deps[i].ManifestPath = m.Path
		}
		allDeps = append(allDeps, deps...)
	}

	return allDeps, manifests, nil
}

// --- Go: go.mod ---

var goModRequireRe = regexp.MustCompile(`^\s*(\S+)\s+(\S+)(?:\s+//\s*(indirect))?`)

// ParseGoMod parses a go.mod file and extracts direct (non-indirect) requires.
func ParseGoMod(path string) ([]analysis.Dependency, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var deps []analysis.Dependency
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	inRequireBlock := false
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Check for block require first: "require ("
		if trimmed == "require (" {
			inRequireBlock = true
			continue
		}
		// Single-line require: require foo v1.2.3
		if strings.HasPrefix(trimmed, "require ") && !strings.HasSuffix(trimmed, "(") {
			rest := strings.TrimPrefix(trimmed, "require ")
			if dep := parseGoModRequireLine(rest); dep != nil {
				deps = append(deps, *dep)
			}
			continue
		}
		if trimmed == ")" && inRequireBlock {
			inRequireBlock = false
			continue
		}
		if inRequireBlock {
			if dep := parseGoModRequireLine(trimmed); dep != nil {
				deps = append(deps, *dep)
			}
		}
	}

	return deps, scanner.Err()
}

func parseGoModRequireLine(line string) *analysis.Dependency {
	m := goModRequireRe.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	pkg := m[1]
	ver := m[2]
	indirect := strings.Contains(line, "// indirect")
	// Skip the Go toolchain and module self-reference
	if pkg == "" || strings.HasPrefix(pkg, "go ") || ver == "" {
		return nil
	}
	return &analysis.Dependency{
		Name:      pkg,
		Version:   ver,
		Ecosystem: analysis.EcosystemGo,
		IsDirect:  !indirect,
	}
}

// --- npm: package.json ---

type packageJSON struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// ParsePackageJSON parses a package.json file.
func ParsePackageJSON(path string) ([]analysis.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("invalid package.json: %w", err)
	}

	var deps []analysis.Dependency

	for name, version := range pkg.Dependencies {
		deps = append(deps, analysis.Dependency{
			Name:      name,
			Version:   cleanNPMVersion(version),
			Ecosystem: analysis.EcosystemNPM,
			IsDirect:  true,
			IsDev:     false,
		})
	}
	for name, version := range pkg.DevDependencies {
		deps = append(deps, analysis.Dependency{
			Name:      name,
			Version:   cleanNPMVersion(version),
			Ecosystem: analysis.EcosystemNPM,
			IsDirect:  true,
			IsDev:     true,
		})
	}

	sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })
	return deps, nil
}

// cleanNPMVersion strips semver range operators ( ^, ~, >=, etc.) to get a base version.
func cleanNPMVersion(v string) string {
	v = strings.TrimSpace(v)
	// Handle git/file/local specs — keep as-is for display but they won't query OSV
	if strings.HasPrefix(v, "git+") || strings.HasPrefix(v, "file:") || strings.HasPrefix(v, "link:") {
		return v
	}
	// Strip leading range operators
	v = strings.TrimLeft(v, "^~>=< ")
	// Handle wildcard
	if v == "*" || v == "" || v == "latest" {
		return ""
	}
	// Handle "x.y.z || a.b.c" — take the first
	if idx := strings.Index(v, " || "); idx > 0 {
		v = v[:idx]
	}
	return strings.TrimLeft(v, "v")
}

// --- Python: requirements.txt ---

var requirementsRe = regexp.MustCompile(`^([A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_.-]+\])?)\s*([=<>!~]=|=|<|>|~=)?\s*([0-9A-Za-z.*+!-]*)`)

// ParseRequirementsTxt parses a requirements.txt file.
func ParseRequirementsTxt(path string) ([]analysis.Dependency, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var deps []analysis.Dependency
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Strip inline comments
		if idx := strings.Index(line, " #"); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}
		// Strip environment markers
		if idx := strings.Index(line, ";"); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}

		m := requirementsRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := strings.ToLower(m[1])
		// Strip extras: package[extra] -> package
		if idx := strings.Index(name, "["); idx > 0 {
			name = name[:idx]
		}
		version := m[3]
		if version == "" || version == "*" {
			version = ""
		}

		deps = append(deps, analysis.Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: analysis.EcosystemPyPI,
			IsDirect:  true,
		})
	}

	return deps, scanner.Err()
}

// --- Python: pyproject.toml ---

var tomlDependencyRe = regexp.MustCompile(`^"?([A-Za-z0-9_.-]+)"?\s*=\s*"?(.+?)"?\s*$`)
var tomlArrayDepRe = regexp.MustCompile(`^"?([A-Za-z0-9_.-]+)"?\s*=\s*\[`)

// ParsePyProjectToml parses a pyproject.toml file for [project.dependencies] and
// [tool.poetry.dependencies] sections.
func ParsePyProjectToml(path string) ([]analysis.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var deps []analysis.Dependency
	lines := strings.Split(string(data), "\n")

	section := ""
	inArray := false

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Section headers
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line
			inArray = false
			continue
		}

		isDepSection := strings.Contains(section, "dependencies") ||
			section == "[project.dependencies]" ||
			section == "[tool.poetry.dependencies]" ||
			strings.HasPrefix(section, "[project.optional-dependencies")

		if !isDepSection {
			continue
		}

		// Skip python version constraint
		if strings.HasPrefix(line, "python") {
			continue
		}

		// Array-style: package = ["foo>=1.0", "bar>=2.0"]
		if tomlArrayDepRe.MatchString(line) && strings.HasSuffix(line, "[") {
			inArray = true
			continue
		}
		if inArray {
			if strings.HasPrefix(line, "]") {
				inArray = false
				continue
			}
			// Parse array element: "foo>=1.0"
			elem := strings.Trim(line, `",`)
			elem = strings.TrimSpace(elem)
			if dep := parsePythonVersionSpec(elem); dep != nil {
				deps = append(deps, *dep)
			}
			continue
		}

		// Key-value: package = ">=1.0.0" or package = "1.2.3"
		m := tomlDependencyRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := strings.ToLower(m[1])
		val := m[2]

		// Skip non-dependency keys
		if name == "python" || name == "build-backend" || name == "requires" {
			continue
		}

		dep := parsePythonVersionSpec(name + val)
		if dep == nil {
			dep = &analysis.Dependency{
				Name:      name,
				Version:   cleanPythonVersion(val),
				Ecosystem: analysis.EcosystemPyPI,
				IsDirect:  true,
			}
		}
		deps = append(deps, *dep)
	}

	return deps, nil
}

// --- Python: setup.py ---

// setupPyInstallRequiresRe matches install_requires = ["pkg>=1.0", ...]
var setupPyInstallRequiresRe = regexp.MustCompile(`(?:install_requires|requires)\s*=\s*\[(.*?)\]`)
var setupPySingleDepRe = regexp.MustCompile(`["']([^"']+)["']`)

// ParseSetupPy parses a setup.py file for install_requires.
// Since setup.py is Python code, we use regex to extract the install_requires list.
func ParseSetupPy(path string) ([]analysis.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	src := string(data)
	var deps []analysis.Dependency

	// Extract install_requires = [...] blocks
	matches := setupPyInstallRequiresRe.FindAllStringSubmatch(src, -1)
	for _, m := range matches {
		listContent := m[1]
		// Parse each "pkg>=1.0" entry
		depMatches := setupPySingleDepRe.FindAllStringSubmatch(listContent, -1)
		for _, dm := range depMatches {
			spec := dm[1]
			dep := parsePythonVersionSpec(spec)
			if dep == nil {
				// No version constraint — just the package name
				name := strings.TrimSpace(spec)
				name = strings.ToLower(name)
				if name != "" && name != "python" {
					deps = append(deps, analysis.Dependency{
						Name:      name,
						Version:   "",
						Ecosystem: analysis.EcosystemPyPI,
						IsDirect:  true,
					})
				}
			} else {
				deps = append(deps, *dep)
			}
		}
	}

	return deps, nil
}

// --- Python: setup.cfg ---

var setupCfgInstallRequiresRe = regexp.MustCompile(`(?m)^install_requires\s*=\s*(.*)$`)
var setupCfgOptionsRe = regexp.MustCompile(`(?m)^\[options\]`)

// ParseSetupCfg parses a setup.cfg file for install_requires.
func ParseSetupCfg(path string) ([]analysis.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	src := string(data)
	var deps []analysis.Dependency

	// Find [options] section
	optionsIdx := setupCfgOptionsRe.FindStringIndex(src)
	if optionsIdx == nil {
		return deps, nil
	}

	// Get the section content (from [options] to the next [section] or EOF)
	sectionStart := optionsIdx[1]
	nextSection := strings.Index(src[sectionStart:], "\n[")
	var section string
	if nextSection > 0 {
		section = src[sectionStart : sectionStart+nextSection]
	} else {
		section = src[sectionStart:]
	}

	// Parse install_requires (can span multiple lines with continuation)
	lines := strings.Split(section, "\n")
	var installRequires string
	inInstallRequires := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "install_requires") {
			// Could be inline or start of multi-line
			idx := strings.Index(trimmed, "=")
			if idx > 0 {
				val := strings.TrimSpace(trimmed[idx+1:])
				if val != "" {
					installRequires = val
				}
				inInstallRequires = val == "" || strings.HasSuffix(val, "\\")
			}
			continue
		}
		if inInstallRequires {
			if strings.HasPrefix(trimmed, "#") || trimmed == "" {
				continue
			}
			installRequires += " " + trimmed
			if !strings.HasSuffix(trimmed, "\\") {
				inInstallRequires = false
			}
		}
	}

	if installRequires != "" {
		// Parse space or newline separated requirements
		for _, spec := range strings.Fields(installRequires) {
			spec = strings.Trim(spec, ",\\")
			dep := parsePythonVersionSpec(spec)
			if dep == nil {
				name := strings.ToLower(strings.TrimSpace(spec))
				if name != "" && name != "python" {
					deps = append(deps, analysis.Dependency{
						Name:      name,
						Version:   "",
						Ecosystem: analysis.EcosystemPyPI,
						IsDirect:  true,
					})
				}
			} else {
				deps = append(deps, *dep)
			}
		}
	}

	return deps, nil
}

// --- Python: Pipfile.lock ---

// pipfileLockJSON represents the relevant parts of a Pipfile.lock.
type pipfileLockJSON struct {
	Default map[string]struct {
		Version string `json:"version"`
	} `json:"default"`
	Develop map[string]struct {
		Version string `json:"version"`
	} `json:"develop"`
}

// ParsePipfileLock parses a Pipfile.lock file (JSON format).
func ParsePipfileLock(path string) ([]analysis.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var lock pipfileLockJSON
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("invalid Pipfile.lock: %w", err)
	}

	var deps []analysis.Dependency
	for name, info := range lock.Default {
		deps = append(deps, analysis.Dependency{
			Name:      strings.ToLower(name),
			Version:   cleanPythonVersion(info.Version),
			Ecosystem: analysis.EcosystemPyPI,
			IsDirect:  true,
			IsDev:     false,
		})
	}
	for name, info := range lock.Develop {
		deps = append(deps, analysis.Dependency{
			Name:      strings.ToLower(name),
			Version:   cleanPythonVersion(info.Version),
			Ecosystem: analysis.EcosystemPyPI,
			IsDirect:  true,
			IsDev:     true,
		})
	}

	sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })
	return deps, nil
}

// --- Python: poetry.lock ---

// poetryLockJSON represents the relevant parts of a poetry.lock file.
type poetryLockJSON struct {
	Packages []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"package"`
}

// ParsePoetryLock parses a poetry.lock file (TOML/JSON format).
// poetry.lock v1 is TOML, but we try JSON first (poetry.lock v2).
func ParsePoetryLock(path string) ([]analysis.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Try JSON first (some tools output JSON locks)
	var lock poetryLockJSON
	if err := json.Unmarshal(data, &lock); err == nil && len(lock.Packages) > 0 {
		var deps []analysis.Dependency
		for _, pkg := range lock.Packages {
			deps = append(deps, analysis.Dependency{
				Name:      strings.ToLower(pkg.Name),
				Version:   cleanPythonVersion(pkg.Version),
				Ecosystem: analysis.EcosystemPyPI,
				IsDirect:  true,
			})
		}
		sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })
		return deps, nil
	}

	// Fall back to TOML regex parsing for [[package]] sections
	src := string(data)
	var deps []analysis.Dependency
	inPackage := false
	var name, version string

	pkgNameRe := regexp.MustCompile(`^name\s*=\s*"(.+)"`)
	pkgVerRe := regexp.MustCompile(`^version\s*=\s*"(.+)"`)

	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "[[package]]" {
			if name != "" && version != "" {
				deps = append(deps, analysis.Dependency{
					Name:      strings.ToLower(name),
					Version:   cleanPythonVersion(version),
					Ecosystem: analysis.EcosystemPyPI,
					IsDirect:  true,
				})
			}
			name = ""
			version = ""
			inPackage = true
			continue
		}
		if strings.HasPrefix(trimmed, "[") && trimmed != "[[package]]" {
			inPackage = false
			continue
		}
		if !inPackage {
			continue
		}
		if m := pkgNameRe.FindStringSubmatch(trimmed); m != nil {
			name = m[1]
		}
		if m := pkgVerRe.FindStringSubmatch(trimmed); m != nil {
			version = m[1]
		}
	}
	// Don't forget the last package
	if name != "" && version != "" {
		deps = append(deps, analysis.Dependency{
			Name:      strings.ToLower(name),
			Version:   cleanPythonVersion(version),
			Ecosystem: analysis.EcosystemPyPI,
			IsDirect:  true,
		})
	}

	sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })
	return deps, nil
}

// parsePythonVersionSpec parses a spec like "foo>=1.0.0" or "foo==1.2.3" into a Dependency.
func parsePythonVersionSpec(spec string) *analysis.Dependency {
	spec = strings.TrimSpace(spec)
	re := regexp.MustCompile(`^([A-Za-z0-9_.-]+)\s*[=<>!~]+\s*([0-9A-Za-z.*+!-]+)`)
	m := re.FindStringSubmatch(spec)
	if m == nil {
		return nil
	}
	return &analysis.Dependency{
		Name:      strings.ToLower(m[1]),
		Version:   m[2],
		Ecosystem: analysis.EcosystemPyPI,
		IsDirect:  true,
	}
}

func cleanPythonVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimLeft(v, "=<>!~ ")
	v = strings.TrimPrefix(v, "v")
	if v == "*" || v == "" {
		return ""
	}
	return v
}

// --- Rust: Cargo.toml ---

var cargoDepRe = regexp.MustCompile(`^([A-Za-z0-9_-]+)\s*=\s*"(.+?)"`)

// ParseCargoToml parses a Cargo.toml file for [dependencies] and [dev-dependencies].
func ParseCargoToml(path string) ([]analysis.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var deps []analysis.Dependency
	lines := strings.Split(string(data), "\n")
	section := ""

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line
			continue
		}

		isDep := section == "[dependencies]" || section == "[dev-dependencies]"
		if !isDep {
			continue
		}

		m := cargoDepRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ver := m[2]
		// Skip git/path/version specs that aren't semver
		if strings.HasPrefix(ver, "git") || strings.HasPrefix(ver, "path") {
			continue
		}
		deps = append(deps, analysis.Dependency{
			Name:      m[1],
			Version:   strings.TrimPrefix(ver, "v"),
			Ecosystem: analysis.EcosystemCargo,
			IsDirect:  true,
			IsDev:     section == "[dev-dependencies]",
		})
	}

	return deps, nil
}

// --- Ruby: Gemfile ---

var gemfileRe = regexp.MustCompile(`^\s*(?:gem|gem\s+["'](.+?)["']\s*,\s*["'](.+?)["'])`)

// ParseGemfile parses a Ruby Gemfile.
func ParseGemfile(path string) ([]analysis.Dependency, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var deps []analysis.Dependency
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "gem ") {
			continue
		}
		// gem "foo", "~> 1.0"
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		name := strings.Trim(parts[1], `"'`)
		version := ""
		if len(parts) >= 4 {
			version = strings.Trim(parts[3], `"'~>=< `)
		}
		deps = append(deps, analysis.Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: analysis.EcosystemRubyGems,
			IsDirect:  true,
		})
	}

	return deps, scanner.Err()
}

// ParseGemfileLock parses a Gemfile.lock for GEM specs.
func ParseGemfileLock(path string) ([]analysis.Dependency, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var deps []analysis.Dependency
	scanner := bufio.NewScanner(f)
	inSpecs := false

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "specs:") {
			inSpecs = true
			continue
		}
		if inSpecs && !strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "\t") {
			inSpecs = false
			continue
		}
		if !inSpecs {
			continue
		}

		// "    foo (1.2.3)"
		re := regexp.MustCompile(`^\s+([A-Za-z0-9_.-]+)\s+\(([^)]+)\)`)
		m := re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		deps = append(deps, analysis.Dependency{
			Name:      m[1],
			Version:   m[2],
			Ecosystem: analysis.EcosystemRubyGems,
			IsDirect:  false,
		})
	}

	return deps, scanner.Err()
}

// --- PHP: composer.json ---

type composerJSON struct {
	Require    map[string]string `json:"require"`
	RequireDev map[string]string `json:"require-dev"`
}

// ParseComposerJSON parses a composer.json file.
func ParseComposerJSON(path string) ([]analysis.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var c composerJSON
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("invalid composer.json: %w", err)
	}

	var deps []analysis.Dependency
	for name, version := range c.Require {
		if name == "php" || strings.HasPrefix(name, "ext-") {
			continue
		}
		deps = append(deps, analysis.Dependency{
			Name:      name,
			Version:   strings.TrimLeft(version, "^~>=< "),
			Ecosystem: analysis.EcosystemPackagist,
			IsDirect:  true,
		})
	}
	for name, version := range c.RequireDev {
		if name == "php" || strings.HasPrefix(name, "ext-") {
			continue
		}
		deps = append(deps, analysis.Dependency{
			Name:      name,
			Version:   strings.TrimLeft(version, "^~>=< "),
			Ecosystem: analysis.EcosystemPackagist,
			IsDirect:  true,
			IsDev:     true,
		})
	}

	sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })
	return deps, nil
}

// --- Java: pom.xml (basic) ---

var pomDependencyRe = regexp.MustCompile(`<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*(?:<version>([^<]+)</version>)?`)

// ParsePomXML parses a Maven pom.xml file for dependencies.
func ParsePomXML(path string) ([]analysis.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var deps []analysis.Dependency
	matches := pomDependencyRe.FindAllStringSubmatch(string(data), -1)
	for _, m := range matches {
		groupID := m[1]
		artifactID := m[2]
		version := m[3]
		if version == "" {
			version = "unknown"
		}
		// Skip test-scope detection is basic; we mark all as direct
		deps = append(deps, analysis.Dependency{
			Name:      groupID + ":" + artifactID,
			Version:   version,
			Ecosystem: analysis.EcosystemMaven,
			IsDirect:  true,
		})
	}

	return deps, nil
}

// --- Java: build.gradle (basic) ---

var gradleDepRe = regexp.MustCompile(`(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testCompileOnly|testRuntimeOnly)\s+['"]([^:]+):([^:]+):([^'"]+)['"]`)

// ParseBuildGradle parses a Gradle build file for dependencies.
func ParseBuildGradle(path string) ([]analysis.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var deps []analysis.Dependency
	matches := gradleDepRe.FindAllStringSubmatch(string(data), -1)
	for _, m := range matches {
		deps = append(deps, analysis.Dependency{
			Name:      m[1] + ":" + m[2],
			Version:   m[3],
			Ecosystem: analysis.EcosystemMaven,
			IsDirect:  true,
		})
	}

	return deps, nil
}
