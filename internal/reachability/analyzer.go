// Package reachability analyzes whether vulnerable dependencies are actually
// imported and used in the codebase. It parses import statements for Python, Go,
// and JavaScript/TypeScript, builds an import graph, and assigns reachability
// confidence levels to SCA findings.
package reachability

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/patchflow/patchflow-cli/internal/analysis"
)

// Analyzer runs reachability analysis on a repository.
type Analyzer struct {
	MaxDepth int
}

// NewAnalyzer creates a reachability analyzer with default settings.
func NewAnalyzer() *Analyzer {
	return &Analyzer{MaxDepth: 10}
}

// Result is the output of a reachability analysis run.
type Result struct {
	Findings []analysis.Finding `json:"findings"`
	Graph    *ImportGraph       `json:"-"`
	Updated  int                `json:"updated"`
}

// ImportGraph represents the codebase import graph.
type ImportGraph struct {
	// Imports maps a source file to the packages it imports.
	Imports map[string][]string `json:"imports"`
	// PackageFiles maps a package name to the files that import it.
	PackageFiles map[string][]string `json:"package_files"`
	// AllImportedPackages is the set of all imported package names.
	AllImportedPackages map[string]bool `json:"all_imported_packages"`
}

// Analyze runs reachability analysis and updates SCA findings with reachability metadata.
// It takes the SCA findings and the list of dependencies, then for each vulnerable
// dependency, checks whether it is imported in the codebase.
func (a *Analyzer) Analyze(ctx context.Context, root string, findings []analysis.Finding, deps []analysis.Dependency) (*Result, error) {
	started := time.Now()
	_ = started

	// Build the import graph by scanning source files
	graph, err := a.buildImportGraph(root)
	if err != nil {
		return nil, fmt.Errorf("reachability: failed to build import graph: %w", err)
	}

	// For each SCA finding, determine reachability
	updated := 0
	for i := range findings {
		if findings[i].Type != analysis.TypeSCA {
			continue
		}

		pkgName := findings[i].PackageName
		if pkgName == "" {
			continue
		}

		status, evidence := a.assessReachability(pkgName, findings[i].PackageVersion, graph, deps)

		// Only update if we found something better than unknown
		if status != analysis.ReachabilityUnknown {
			findings[i].Reachability = status
			findings[i].ReachabilityConfidence = reachabilityToConfidence(status)
			findings[i].ReachabilityEvidence = evidence
			updated++
		}
	}

	return &Result{
		Findings: findings,
		Graph:    graph,
		Updated:  updated,
	}, nil
}

// AssessPackage directly assesses the reachability of a single package.
// Used by the `patchflow reachability --package <name>` command.
func (a *Analyzer) AssessPackage(root string, pkgName string) (analysis.ReachabilityStatus, []string, error) {
	graph, err := a.buildImportGraph(root)
	if err != nil {
		return analysis.ReachabilityUnknown, nil, err
	}

	status, evidence := a.assessReachability(pkgName, "", graph, nil)
	return status, evidence, nil
}

// buildImportGraph scans source files and builds a map of imports.
func (a *Analyzer) buildImportGraph(root string) (*ImportGraph, error) {
	graph := &ImportGraph{
		Imports:             make(map[string][]string),
		PackageFiles:        make(map[string][]string),
		AllImportedPackages: make(map[string]bool),
	}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if isSkipDir(name) {
				return filepath.SkipDir
			}
			return nil
		}

		ext := filepath.Ext(path)
		switch ext {
		case ".py":
			imports := parsePythonImports(path)
			if len(imports) > 0 {
				rel, _ := filepath.Rel(root, path)
				graph.Imports[rel] = imports
				for _, imp := range imports {
					graph.AllImportedPackages[imp] = true
					graph.PackageFiles[imp] = append(graph.PackageFiles[imp], rel)
				}
			}
		case ".go":
			imports := parseGoImports(path)
			if len(imports) > 0 {
				rel, _ := filepath.Rel(root, path)
				graph.Imports[rel] = imports
				for _, imp := range imports {
					graph.AllImportedPackages[imp] = true
					graph.PackageFiles[imp] = append(graph.PackageFiles[imp], rel)
				}
			}
		case ".js", ".jsx", ".ts", ".tsx":
			imports := parseJSImports(path)
			if len(imports) > 0 {
				rel, _ := filepath.Rel(root, path)
				graph.Imports[rel] = imports
				for _, imp := range imports {
					graph.AllImportedPackages[imp] = true
					graph.PackageFiles[imp] = append(graph.PackageFiles[imp], rel)
				}
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	// Deduplicate package files
	for pkg := range graph.PackageFiles {
		graph.PackageFiles[pkg] = dedupStrings(graph.PackageFiles[pkg])
		sort.Strings(graph.PackageFiles[pkg])
	}

	return graph, nil
}

// assessReachability determines the reachability status for a package.
func (a *Analyzer) assessReachability(pkgName, version string, graph *ImportGraph, deps []analysis.Dependency) (analysis.ReachabilityStatus, []string) {
	var evidence []string

	// Check if the package or a known import alias is directly imported.
	for _, importName := range packageImportNames(pkgName) {
		if files, ok := graph.PackageFiles[importName]; ok && len(files) > 0 {
			if importName == pkgName {
				evidence = append(evidence, fmt.Sprintf("Directly imported in %d file(s):", len(files)))
			} else {
				evidence = append(evidence, fmt.Sprintf("Package %s imported as %s in %d file(s):", pkgName, importName, len(files)))
			}
			for _, f := range files {
				if len(evidence) > 10 {
					evidence = append(evidence, "  ... and more")
					break
				}
				evidence = append(evidence, "  - "+f)
			}
			return analysis.ReachabilityHigh, evidence
		}
	}

	normalizedPkgName := strings.ToLower(pkgName)
	if files, ok := graph.PackageFiles[normalizedPkgName]; ok && len(files) > 0 {
		evidence = append(evidence, fmt.Sprintf("Package %s imported as %s in %d file(s):", pkgName, normalizedPkgName, len(files)))
		for _, f := range files {
			if len(evidence) > 10 {
				evidence = append(evidence, "  ... and more")
				break
			}
			evidence = append(evidence, "  - "+f)
		}
		return analysis.ReachabilityHigh, evidence
	}

	// For Go packages, check if the module path prefix is imported
	// e.g. package "github.com/x/y" might be imported as "github.com/x/y/sub"
	if strings.Contains(pkgName, "/") {
		prefix := pkgName
		for imported := range graph.AllImportedPackages {
			if strings.HasPrefix(imported, prefix) || strings.HasPrefix(prefix, imported) {
				files := graph.PackageFiles[imported]
				evidence = append(evidence, fmt.Sprintf("Module path %s matches import %s in:", pkgName, imported))
				for _, f := range files {
					if len(evidence) > 10 {
						evidence = append(evidence, "  ... and more")
						break
					}
					evidence = append(evidence, "  - "+f)
				}
				return analysis.ReachabilityHigh, evidence
			}
		}
	}

	// For npm packages with scoped names, check unscoped
	if strings.HasPrefix(pkgName, "@") {
		parts := strings.Split(pkgName, "/")
		if len(parts) > 1 {
			shortName := parts[1]
			if files, ok := graph.PackageFiles[shortName]; ok && len(files) > 0 {
				evidence = append(evidence, fmt.Sprintf("Package %s imported as %s in:", pkgName, shortName))
				for _, f := range files {
					evidence = append(evidence, "  - "+f)
				}
				return analysis.ReachabilityMedium, evidence
			}
		}
	}

	// Check if it's a direct dependency (in deps list) but not imported
	isDirect := false
	if deps != nil {
		for _, dep := range deps {
			if dep.Name == pkgName && dep.IsDirect {
				isDirect = true
				break
			}
		}
	}

	if isDirect {
		evidence = append(evidence, fmt.Sprintf("Package %s is a direct dependency but no direct imports found.", pkgName))
		return analysis.ReachabilityMedium, evidence
	}

	// Not in the import graph at all
	evidence = append(evidence, fmt.Sprintf("Package %s not found in import graph.", pkgName))
	return analysis.ReachabilityNone, evidence
}

func packageImportNames(pkgName string) []string {
	normalized := strings.ToLower(strings.TrimSpace(pkgName))
	aliases := map[string][]string{
		"beautifulsoup4":  {"bs4"},
		"opencv-python":   {"cv2"},
		"pillow":          {"pil"},
		"psycopg2-binary": {"psycopg2"},
		"pyjwt":           {"jwt"},
		"pymysql":         {"pymysql"},
		"pypdf2":          {"pypdf2"},
		"python-dateutil": {"dateutil"},
		"python-dotenv":   {"dotenv"},
		"python-jose":     {"jose"},
		"pyyaml":          {"yaml"},
		"scikit-learn":    {"sklearn"},
	}

	names := []string{pkgName}
	if normalized != pkgName {
		names = append(names, normalized)
	}
	if strings.HasPrefix(normalized, "google-cloud-") {
		names = append(names, "google", "google.cloud")
	}
	if strings.HasPrefix(normalized, "azure-") {
		names = append(names, "azure")
	}
	names = append(names, aliases[normalized]...)
	return dedupStrings(names)
}

func reachabilityToConfidence(status analysis.ReachabilityStatus) analysis.Confidence {
	switch status {
	case analysis.ReachabilityHigh:
		return analysis.ConfidenceHigh
	case analysis.ReachabilityMedium:
		return analysis.ConfidenceMedium
	case analysis.ReachabilityLow:
		return analysis.ConfidenceLow
	case analysis.ReachabilityNone:
		return analysis.ConfidenceHigh // high confidence it's NOT reachable
	default:
		return analysis.ConfidenceLow
	}
}

// --- Python import parsing ---

var (
	pyImportRe     = regexp.MustCompile(`^\s*(?:import|from)\s+([A-Za-z0-9_.]+)`)
	pyFromImportRe = regexp.MustCompile(`^\s*from\s+([A-Za-z0-9_.]+)\s+import`)
)

// parsePythonImports extracts imported module names from a Python file.
func parsePythonImports(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var imports []string
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		// Skip comments and empty lines
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// from X import Y
		if m := pyFromImportRe.FindStringSubmatch(line); m != nil {
			pkg := strings.ToLower(m[1])
			// Take the top-level package name
			parts := strings.SplitN(pkg, ".", 2)
			topLevel := parts[0]
			if !seen[topLevel] {
				seen[topLevel] = true
				imports = append(imports, topLevel)
			}
			continue
		}

		// import X
		if m := pyImportRe.FindStringSubmatch(line); m != nil {
			pkg := strings.ToLower(m[1])
			// Handle "import X, Y, Z"
			for _, p := range strings.Split(pkg, ",") {
				p = strings.TrimSpace(p)
				parts := strings.SplitN(p, ".", 2)
				topLevel := parts[0]
				if topLevel != "" && !seen[topLevel] {
					seen[topLevel] = true
					imports = append(imports, topLevel)
				}
			}
		}
	}

	return imports
}

// --- Go import parsing ---

var (
	goImportRe      = regexp.MustCompile(`^\s*"([^"]+)"`)
	goImportBlockRe = regexp.MustCompile(`^\s*\(([^)]+)\)`)
)

// parseGoImports extracts imported package paths from a Go file.
func parseGoImports(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	content := string(data)
	var imports []string
	seen := make(map[string]bool)

	// Find import blocks: import ( ... )
	importBlockRe := regexp.MustCompile(`import\s*\(([^)]+)\)`)
	blockMatches := importBlockRe.FindAllStringSubmatch(content, -1)
	for _, m := range blockMatches {
		block := m[1]
		for _, line := range strings.Split(block, "\n") {
			line = strings.TrimSpace(line)
			// Skip alias and comments
			if strings.Contains(line, "//") {
				line = line[:strings.Index(line, "//")]
				line = strings.TrimSpace(line)
			}
			// Handle alias: name "path"
			if idx := strings.Index(line, `"`); idx >= 0 {
				end := strings.LastIndex(line, `"`)
				if end > idx {
					pkg := line[idx+1 : end]
					if !seen[pkg] {
						seen[pkg] = true
						imports = append(imports, pkg)
					}
				}
			}
		}
	}

	// Find single-line imports: import "path"
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "import ") {
			continue
		}
		rest := strings.TrimPrefix(trimmed, "import ")
		rest = strings.TrimSpace(rest)
		if strings.HasPrefix(rest, "(") {
			continue // handled above
		}
		// Extract quoted path
		if idx := strings.Index(rest, `"`); idx >= 0 {
			end := strings.LastIndex(rest, `"`)
			if end > idx {
				pkg := rest[idx+1 : end]
				if !seen[pkg] {
					seen[pkg] = true
					imports = append(imports, pkg)
				}
			}
		}
	}

	return imports
}

// --- JavaScript/TypeScript import parsing ---

var (
	jsImportFromRe    = regexp.MustCompile(`(?:import|export)\s+.*?\s+from\s+['"]([^'"]+)['"]`)
	jsRequireRe       = regexp.MustCompile(`require\(\s*['"]([^'"]+)['"]\s*\)`)
	jsDynamicImportRe = regexp.MustCompile(`import\(\s*['"]([^'"]+)['"]\s*\)`)
)

// parseJSImports extracts imported module names from a JS/TS file.
func parseJSImports(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var imports []string
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()

		// import ... from 'module'
		for _, m := range jsImportFromRe.FindAllStringSubmatch(line, -1) {
			pkg := normalizeJSPackage(m[1])
			if pkg != "" && !seen[pkg] {
				seen[pkg] = true
				imports = append(imports, pkg)
			}
		}

		// require('module')
		for _, m := range jsRequireRe.FindAllStringSubmatch(line, -1) {
			pkg := normalizeJSPackage(m[1])
			if pkg != "" && !seen[pkg] {
				seen[pkg] = true
				imports = append(imports, pkg)
			}
		}

		// dynamic import('module')
		for _, m := range jsDynamicImportRe.FindAllStringSubmatch(line, -1) {
			pkg := normalizeJSPackage(m[1])
			if pkg != "" && !seen[pkg] {
				seen[pkg] = true
				imports = append(imports, pkg)
			}
		}
	}

	return imports
}

// normalizeJSPackage converts a JS import path to a package name.
// "lodash/deep" → "lodash", "@scope/pkg/sub" → "@scope/pkg", "./local" → ""
func normalizeJSPackage(p string) string {
	if strings.HasPrefix(p, ".") || strings.HasPrefix(p, "/") {
		return "" // local import
	}

	// Scoped packages: @scope/name
	if strings.HasPrefix(p, "@") {
		parts := strings.SplitN(p, "/", 3)
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
		return p
	}

	// Regular packages: take the top-level name
	parts := strings.SplitN(p, "/", 2)
	return parts[0]
}

func isSkipDir(name string) bool {
	switch name {
	case ".git", "vendor", "node_modules", "dist", "build", "target",
		".venv", "venv", "__pycache__", ".next", ".nuxt", "coverage",
		".patchflow", ".idea", ".vscode":
		return true
	}
	return false
}

func dedupStrings(s []string) []string {
	seen := make(map[string]bool, len(s))
	result := make([]string, 0, len(s))
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}
