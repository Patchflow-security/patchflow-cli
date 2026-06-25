// Package gosast provides an embedded Go static analysis security scanner.
// It ports the most impactful rules from gosec (https://github.com/securego/gosec)
// using golang.org/x/tools/go/packages directly, without importing gosec's
// heavy transitive dependencies (AI SDKs, gRPC, OpenTelemetry).
//
// The rule implementations are derived from gosec v2.27.1 (Apache 2.0 licensed).
// See: https://github.com/securego/gosec/blob/v2.27.1/LICENSE
package gosast

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/tools/go/packages"

	"github.com/patchflow/patchflow-cli/internal/analysis"
)

// Severity levels for findings.
type Severity int

const (
	SeverityLow    Severity = 1
	SeverityMedium Severity = 2
	SeverityHigh   Severity = 3
)

// Confidence levels for findings.
type Confidence int

const (
	ConfidenceLow    Confidence = 1
	ConfidenceMedium Confidence = 2
	ConfidenceHigh   Confidence = 3
)

// Rule is the interface that all security rules implement.
type Rule interface {
	ID() string
	Match(node ast.Node, ctx *Context) (*Finding, error)
	Nodes() []ast.Node // AST node types this rule wants to inspect
}

// Finding is a raw security finding from a rule, before normalization.
type Finding struct {
	RuleID     string
	Title      string
	Severity   Severity
	Confidence Confidence
	File       string
	Line       int
	Col        int
	Code       string
}

// Context provides type information and file set to rules during AST traversal.
type Context struct {
	FileSet  *token.FileSet
	Info     *types.Info
	Pkg      *types.Package
	PkgFiles []*ast.File
	Root     *ast.File
	Imports  map[string][]string // import path -> imported names/aliases
}

// Analyzer runs all registered rules against Go source packages.
type Analyzer struct {
	rules       []Rule
	concurrency int
	logger      *log.Logger
}

// NewAnalyzer creates a new Go SAST analyzer with all built-in rules registered.
func NewAnalyzer() *Analyzer {
	a := &Analyzer{
		concurrency: runtime.NumCPU(),
		logger:      log.New(os.Stderr, "[gosast] ", log.LstdFlags),
	}
	a.registerDefaultRules()
	return a
}

// registerDefaultRules registers all built-in security rules.
func (a *Analyzer) registerDefaultRules() {
	a.rules = []Rule{
		// Injection
		newSQLStrConcat(),
		newSQLStrFormat(),
		newSubprocess(),

		// Crypto
		newWeakCryptoHash(),
		newWeakCryptoEncryption(),
		newWeakRand(),
		newDeprecatedCryptoHash(),
		newWeakKeyStrength(),

		// TLS
		newBadTLSConfig(),

		// Unsafe
		newUsingUnsafe(),

		// Filesystem
		newFilePermissions(),
		newMkdirPermissions(),
		newWritePermissions(),
		newOsCreatePerms(),
		newBadTempFile(),
		newReadFile(),
		newPathTraversal(),
		newDirectoryTraversal(),

		// Network
		newBindToAllInterfaces(),
		newSSRF(),
		newHTTPServeWithoutTimeouts(),
		newSlowloris(),

		// Hardcoded credentials
		newHardcodedCredentials(),

		// Blocklist imports
		newBlocklistedImports(),

		// Templates
		newTemplateCheck(),

		// SSH
		newSSHHostKey(),

		// Pprof
		newPprofCheck(),

		// Trojan Source
		newTrojanSource(),

		// Error handling
		newNoErrorCheck(),

		// Integer overflow
		newIntegerOverflow(),

		// Decompression bomb
		newDecompressionBomb(),

		// Implicit aliasing (pre-Go 1.22)
		newImplicitAliasing(),
	}
}

// Analyze runs all rules against Go packages in the given root directory.
func (a *Analyzer) Analyze(ctx context.Context, root string) ([]analysis.Finding, error) {
	startTime := time.Now()

	pkgs, err := a.loadPackages(root)
	if err != nil {
		return nil, fmt.Errorf("failed to load packages: %w", err)
	}

	if len(pkgs) == 0 {
		return nil, nil
	}

	var findings []analysis.Finding
	for _, pkg := range pkgs {
		if len(pkg.Errors) > 0 {
			for _, e := range pkg.Errors {
				a.logger.Printf("package error in %s: %v", pkg.PkgPath, e)
			}
			continue
		}
		if pkg.TypesInfo == nil || pkg.Syntax == nil {
			continue
		}

		pkgFindings := a.analyzePackage(pkg)
		findings = append(findings, pkgFindings...)
	}

	a.logger.Printf("analysis completed in %v: %d findings", time.Since(startTime), len(findings))
	return findings, nil
}

// loadPackages loads all Go packages in the root directory using the Go toolchain.
func (a *Analyzer) loadPackages(root string) ([]*packages.Package, error) {
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedTypes | packages.NeedTypesInfo |
			packages.NeedSyntax | packages.NeedModule,
		Dir:   root,
		Tests: false,
	}

	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, err
	}

	// Filter out packages with no syntax (e.g., cgo-only)
	var result []*packages.Package
	for _, p := range pkgs {
		if len(p.Syntax) > 0 {
			result = append(result, p)
		}
	}
	return result, nil
}

// analyzePackage runs all rules against a single Go package.
func (a *Analyzer) analyzePackage(pkg *packages.Package) []analysis.Finding {
	imports := buildImportMap(pkg)

	var findings []analysis.Finding
	for _, file := range pkg.Syntax {
		fileName := a.fileName(pkg, file)
		ctx := &Context{
			FileSet:  pkg.Fset,
			Info:     pkg.TypesInfo,
			Pkg:      pkg.Types,
			PkgFiles: pkg.Syntax,
			Root:     file,
			Imports:  imports,
		}

		for _, rule := range a.rules {
			ruleFindings := a.runRuleOnFile(rule, file, ctx, fileName)
			findings = append(findings, ruleFindings...)
		}
	}
	return findings
}

// runRuleOnFile walks the AST of a file and invokes the rule on matching nodes.
func (a *Analyzer) runRuleOnFile(rule Rule, file *ast.File, ctx *Context, fileName string) []analysis.Finding {
	nodeTypes := rule.Nodes()
	if len(nodeTypes) == 0 {
		return nil
	}

	// Build a set of node types this rule cares about
	typeSet := make(map[ast.Node]bool)
	for _, n := range nodeTypes {
		typeSet[n] = true
	}

	var findings []analysis.Finding
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		// Check if this node type matches any of the rule's registered types
		for registered := range typeSet {
			if sameNodeType(n, registered) {
				f, err := rule.Match(n, ctx)
				if err == nil && f != nil {
					findings = append(findings, toAnalysisFinding(f, fileName))
				}
				break
			}
		}
		return true
	})
	return findings
}

// sameNodeType checks if two AST nodes are of the same type.
func sameNodeType(a, b ast.Node) bool {
	return fmt.Sprintf("%T", a) == fmt.Sprintf("%T", b)
}

// fileName returns the file name for an AST file within a package.
func (a *Analyzer) fileName(pkg *packages.Package, file *ast.File) string {
	pos := pkg.Fset.Position(file.Pos())
	if pos.IsValid() {
		return pos.Filename
	}
	return ""
}

// buildImportMap builds a map of import path -> imported names/aliases.
func buildImportMap(pkg *packages.Package) map[string][]string {
	imports := make(map[string][]string)
	for _, file := range pkg.Syntax {
		for _, imp := range file.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			name := ""
			if imp.Name != nil {
				name = imp.Name.Name
			} else {
				// Use the last component of the path
				parts := strings.Split(path, "/")
				name = parts[len(parts)-1]
			}
			imports[path] = append(imports[path], name)
		}
	}
	return imports
}

// toAnalysisFinding converts a raw Finding to an analysis.Finding.
func toAnalysisFinding(f *Finding, fileName string) analysis.Finding {
	return analysis.Finding{
		ID:          fmt.Sprintf("gosast-%s-%s-%d", f.RuleID, filepath.Base(fileName), f.Line),
		Type:        analysis.TypeSAST,
		Analyzer:    "gosast-embedded",
		Severity:    toAnalysisSeverity(f.Severity),
		Confidence:  toAnalysisConfidence(f.Confidence),
		Title:       f.Title,
		Description: f.Title,
		FilePath:    fileName,
		LineStart:   f.Line,
		RuleID:      f.RuleID,
		Evidence:    f.Code,
		DetectedAt:  time.Now(),
	}
}

func toAnalysisSeverity(s Severity) analysis.Severity {
	switch s {
	case SeverityHigh:
		return analysis.SeverityHigh
	case SeverityMedium:
		return analysis.SeverityMedium
	case SeverityLow:
		return analysis.SeverityLow
	default:
		return analysis.SeverityInfo
	}
}

func toAnalysisConfidence(c Confidence) analysis.Confidence {
	switch c {
	case ConfidenceHigh:
		return analysis.ConfidenceHigh
	case ConfidenceMedium:
		return analysis.ConfidenceMedium
	case ConfidenceLow:
		return analysis.ConfidenceLow
	default:
		return analysis.ConfidenceLow
	}
}
