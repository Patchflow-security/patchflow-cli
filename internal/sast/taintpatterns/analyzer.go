// Package taintpatterns provides lightweight source-sink taint analysis for
// Python and JavaScript/TypeScript without requiring SSA form. It uses
// tree-sitter AST to identify taint sources (user input, request params,
// environment variables) and dangerous sinks (SQL queries, command execution,
// HTML output, file operations) within the same function scope.
//
// This catches injection vulnerabilities that simple regex pattern matching
// misses, such as:
//   - SQL injection: cursor.execute("SELECT * FROM users WHERE id=" + request.GET["id"])
//   - Command injection: os.system("ls " + input())
//   - XSS: res.send("<h1>" + req.query.name + "</h1>")
//   - Path traversal: open("/tmp/" + request.args.get("file"))
//
// The analysis is intra-procedural (within a single function) and tracks
// variable assignments from sources to sinks.
package taintpatterns

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
	"github.com/patchflow/patchflow-cli/internal/analysis"
	"github.com/patchflow/patchflow-cli/internal/ignore"
)

// Rule represents a taint pattern rule (source-sink pair).
type Rule struct {
	ID          string
	Title       string
	Description string
	Severity    analysis.Severity
	Confidence  analysis.Confidence
	Language    string // "python", "javascript", "typescript"
	CWEID       string // associated CWE ID (e.g., "CWE-89" for SQL injection)
	Sources     []SourcePattern
	Sinks       []SinkPattern
}

// SourcePattern defines where tainted data comes from.
type SourcePattern struct {
	FuncName     string // e.g., "request.GET", "req.query", "input"
	IsSubscript  bool   // involves subscript access (e.g., request.GET["key"])
}

// SinkPattern defines where tainted data should not flow.
type SinkPattern struct {
	FuncName string // e.g., "cursor.execute", "os.system", "res.send"
	ArgIndex int    // 0-based; -1 = any argument
}

// Analyzer performs lightweight taint analysis on Python and JS/TS files.
type Analyzer struct {
	rules         []Rule
	ignoreMatcher *ignore.Matcher
	mu            sync.Mutex
}

// NewAnalyzer creates a taint pattern analyzer with built-in rules.
func NewAnalyzer() *Analyzer {
	return &Analyzer{rules: builtInRules()}
}

// SetIgnoreMatcher sets the .gitignore matcher for filtering files.
func (a *Analyzer) SetIgnoreMatcher(m *ignore.Matcher) {
	a.ignoreMatcher = m
}

// Rules returns all registered taint pattern rules.
func (a *Analyzer) Rules() []Rule {
	return a.rules
}

// Analyze scans all Python and JS/TS files in the root directory.
func (a *Analyzer) Analyze(ctx context.Context, root string) ([]analysis.Finding, error) {
	var findings []analysis.Finding

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if isIgnoredDir(filepath.Base(path)) {
				return filepath.SkipDir
			}
			if a.ignoreMatcher != nil && !a.ignoreMatcher.IsEmpty() {
				if a.ignoreMatcher.Match(path, true) {
					return filepath.SkipDir
				}
			}
			return nil
		}

		if a.ignoreMatcher != nil && !a.ignoreMatcher.IsEmpty() {
			if a.ignoreMatcher.Match(path, false) {
				return nil
			}
		}
		if info.Size() > 2*1024*1024 {
			return nil
		}

		entry := grammars.DetectLanguage(path)
		if entry == nil {
			return nil
		}
		lang := entry.Name
		if lang != "python" && lang != "javascript" && lang != "typescript" {
			return nil
		}
		if !a.hasRulesForLanguage(lang) {
			return nil
		}

		fileFindings, err := a.scanFile(path, root, entry, lang)
		if err != nil {
			return nil
		}
		findings = append(findings, fileFindings...)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("taintpatterns: walk failed: %w", err)
	}
	return findings, nil
}

// ScanFilePublic scans a single file (for use by the parallel file collector).
func (a *Analyzer) ScanFilePublic(absPath, root string, entry *grammars.LangEntry) ([]analysis.Finding, error) {
	if entry == nil {
		return nil, nil
	}
	lang := entry.Name
	if lang != "python" && lang != "javascript" && lang != "typescript" {
		return nil, nil
	}
	if !a.hasRulesForLanguage(lang) {
		return nil, nil
	}
	return a.scanFile(absPath, root, entry, lang)
}

func (a *Analyzer) hasRulesForLanguage(lang string) bool {
	for _, r := range a.rules {
		if r.Language == lang {
			return true
		}
	}
	return false
}

func isIgnoredDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", "dist", "build", "__pycache__",
		".next", ".nuxt", "target", ".gradle", ".idea", ".vscode",
		"bin", "obj", ".cache", ".pytest_cache", ".mypy_cache",
		".ruff_cache", "coverage", ".turbo", ".svelte-kit":
		return true
	}
	return false
}

// scanFile parses a file with tree-sitter and runs taint analysis.
func (a *Analyzer) scanFile(absPath, root string, entry *grammars.LangEntry, lang string) ([]analysis.Finding, error) {
	src, err := os.ReadFile(absPath)
	if err != nil {
		return nil, err
	}

	parser := gotreesitter.NewParser(entry.Language())
	if parser == nil {
		return nil, nil
	}
	tree, err := parser.Parse(src)
	if err != nil || tree == nil {
		return nil, nil
	}
	defer tree.Release()

	bt := gotreesitter.Bind(tree)
	rootNode := bt.RootNode()

	var findings []analysis.Finding
	a.analyzeNode(rootNode, bt, lang, absPath, root, src, &findings)
	return findings, nil
}

// analyzeNode recursively walks the AST looking for function definitions,
// then analyzes each function for source-sink flows.
func (a *Analyzer) analyzeNode(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang, absPath, root string, src []byte, findings *[]analysis.Finding) {
	if node == nil {
		return
	}

	nt := bt.NodeType(node)
	if isFunctionDef(nt, lang) {
		a.analyzeFunction(node, bt, lang, absPath, root, src, findings)
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		a.analyzeNode(node.Child(i), bt, lang, absPath, root, src, findings)
	}
}

func isFunctionDef(nodeType, lang string) bool {
	switch lang {
	case "python":
		return nodeType == "function_definition"
	case "javascript", "typescript":
		return nodeType == "function_declaration" || nodeType == "method_definition" ||
			nodeType == "arrow_function" || nodeType == "function_expression"
	}
	return false
}

// analyzeFunction performs intra-procedural taint analysis on a single function.
func (a *Analyzer) analyzeFunction(fnNode *gotreesitter.Node, bt *gotreesitter.BoundTree, lang, absPath, root string, src []byte, findings *[]analysis.Finding) {
	taintedVars := make(map[string]bool)
	a.walkFunctionBody(fnNode, bt, lang, absPath, root, src, taintedVars, findings)
}

// walkFunctionBody walks the function body collecting taint assignments and
// checking sink calls.
func (a *Analyzer) walkFunctionBody(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang, absPath, root string, src []byte, taintedVars map[string]bool, findings *[]analysis.Finding) {
	if node == nil {
		return
	}

	nt := bt.NodeType(node)

	// Check for assignments: var = <taint_source>
	// Python: assignment, JS/TS: lexical_declaration (const/let), variable_declaration (var), assignment_expression
	if nt == "assignment" || nt == "assignment_expression" || nt == "variable_declarator" ||
		nt == "lexical_declaration" || nt == "variable_declaration" {
		a.checkAssignment(node, bt, lang, src, taintedVars)
	}

	// Check for sink calls: sink(tainted_var)
	// Python: "call", JS/TS: "call_expression"
	if nt == "call" || nt == "call_expression" {
		a.checkSinkCall(node, bt, lang, absPath, root, src, taintedVars, findings)
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		a.walkFunctionBody(node.Child(i), bt, lang, absPath, root, src, taintedVars, findings)
	}
}

// checkAssignment checks if an assignment sources from a taint source.
func (a *Analyzer) checkAssignment(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string, src []byte, taintedVars map[string]bool) {
	nt := bt.NodeType(node)

	// lexical_declaration / variable_declaration wrap variable_declarator children
	if nt == "lexical_declaration" || nt == "variable_declaration" {
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child == nil {
				continue
			}
			childType := bt.NodeType(child)
			if childType == "variable_declarator" {
				a.checkAssignment(child, bt, lang, src, taintedVars)
			}
		}
		return
	}

	var lhsNode, rhsNode *gotreesitter.Node
	if nt == "assignment" {
		lhsNode = bt.ChildByField(node, "left")
		rhsNode = bt.ChildByField(node, "right")
	} else if nt == "variable_declarator" {
		lhsNode = bt.ChildByField(node, "name")
		rhsNode = bt.ChildByField(node, "value")
	} else if nt == "assignment_expression" {
		lhsNode = bt.ChildByField(node, "left")
		rhsNode = bt.ChildByField(node, "right")
	}

	if lhsNode == nil || rhsNode == nil {
		return
	}

	varName := bt.NodeText(lhsNode)
	if varName == "" {
		return
	}

	for _, rule := range a.rules {
		if rule.Language != lang {
			continue
		}
		for _, source := range rule.Sources {
			if matchesSource(rhsNode, bt, src, source) {
				taintedVars[varName] = true
				return
			}
		}
	}

	if referencesTaintedVar(rhsNode, bt, taintedVars) {
		taintedVars[varName] = true
	}
}

// checkSinkCall checks if a call to a sink function uses tainted arguments.
func (a *Analyzer) checkSinkCall(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang, absPath, root string, src []byte, taintedVars map[string]bool, findings *[]analysis.Finding) {
	funcNode := bt.ChildByField(node, "function")
	if funcNode == nil {
		return
	}

	funcName := bt.NodeText(funcNode)
	if funcName == "" {
		return
	}

	argsNode := bt.ChildByField(node, "arguments")
	if argsNode == nil {
		return
	}

	for _, rule := range a.rules {
		if rule.Language != lang {
			continue
		}
		for _, sink := range rule.Sinks {
			if !sinkMatches(funcName, sink.FuncName) {
				continue
			}

			argIdx := 0
			for i := 0; i < int(argsNode.ChildCount()); i++ {
				arg := argsNode.Child(i)
				if arg == nil || isPunctuation(bt.NodeType(arg)) {
					continue
				}

				if sink.ArgIndex >= 0 && argIdx != sink.ArgIndex {
					argIdx++
					continue
				}

				argText := bt.NodeText(arg)
				if isArgTainted(arg, bt, taintedVars) {
					f := a.makeFinding(rule, node, bt, absPath, root, funcName, argText)
					*findings = append(*findings, f)
					break
				}
				argIdx++
			}
		}
	}
}

func isPunctuation(nodeType string) bool {
	return nodeType == "(" || nodeType == ")" || nodeType == "," ||
		nodeType == "[" || nodeType == "]" || nodeType == "{" || nodeType == "}"
}

// matchesSource checks if a node represents a taint source.
func matchesSource(node *gotreesitter.Node, bt *gotreesitter.BoundTree, src []byte, source SourcePattern) bool {
	text := bt.NodeText(node)
	if source.IsSubscript {
		return strings.Contains(text, source.FuncName)
	}
	if strings.HasPrefix(text, source.FuncName) || text == source.FuncName {
		return true
	}
	return strings.Contains(text, source.FuncName+"(")
}

// referencesTaintedVar checks if a node references any tainted variable.
func referencesTaintedVar(node *gotreesitter.Node, bt *gotreesitter.BoundTree, taintedVars map[string]bool) bool {
	if node == nil {
		return false
	}
	if bt.NodeType(node) == "identifier" {
		if taintedVars[bt.NodeText(node)] {
			return true
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		if referencesTaintedVar(node.Child(i), bt, taintedVars) {
			return true
		}
	}
	return false
}

// isArgTainted checks if a call argument contains tainted data.
func isArgTainted(arg *gotreesitter.Node, bt *gotreesitter.BoundTree, taintedVars map[string]bool) bool {
	if arg == nil {
		return false
	}
	if bt.NodeType(arg) == "identifier" {
		return taintedVars[bt.NodeText(arg)]
	}
	return referencesTaintedVar(arg, bt, taintedVars)
}

// sinkMatches checks if a function name matches a sink pattern.
func sinkMatches(funcName, sinkPattern string) bool {
	if funcName == sinkPattern {
		return true
	}
	if strings.HasSuffix(funcName, "."+sinkPattern) {
		return true
	}
	if strings.HasPrefix(funcName, sinkPattern) {
		return true
	}
	return false
}

// makeFinding creates a Finding from a taint rule match.
func (a *Analyzer) makeFinding(rule Rule, node *gotreesitter.Node, bt *gotreesitter.BoundTree, absPath, root, sinkFunc, argText string) analysis.Finding {
	startPoint := node.StartPoint()
	lineStart := int(startPoint.Row) + 1
	lineEnd := int(node.EndPoint().Row) + 1

	relPath, err := filepath.Rel(root, absPath)
	if err != nil {
		relPath = absPath
	}

	evidence := strings.TrimSpace(argText)
	if len(evidence) > 100 {
		evidence = evidence[:97] + "..."
	}

	return analysis.Finding{
		ID:             fmt.Sprintf("taint-pattern-%s-%s-%d", rule.ID, filepath.Base(relPath), lineStart),
		Type:           analysis.TypeSAST,
		Analyzer:       "taint-patterns",
		Severity:       rule.Severity,
		Confidence:     rule.Confidence,
		Title:          rule.Title,
		Description:    rule.Description,
		FilePath:       relPath,
		LineStart:      lineStart,
		LineEnd:        lineEnd,
		RuleID:         rule.ID,
		CWEID:          rule.CWEID,
		Evidence:       evidence,
		Recommendation: fmt.Sprintf("Ensure user input flowing into %s is sanitized/validated.", sinkFunc),
		DetectedAt:     time.Now(),
	}
}
