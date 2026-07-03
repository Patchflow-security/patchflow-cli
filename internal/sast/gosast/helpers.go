// Helpers ported from gosec v2.27.1 (Apache 2.0 licensed).
// Source: https://github.com/securego/gosec/blob/v2.27.1/helpers.go

package gosast

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strconv"
	"strings"
)

// CallList is used to check for usage of specific packages and functions.
type CallList map[string]map[string]bool

// NewCallList creates a new empty CallList.
func NewCallList() CallList {
	return make(CallList)
}

// AddAll adds several calls to the call list at once.
func (c CallList) AddAll(selector string, idents ...string) CallList {
	for _, ident := range idents {
		c.Add(selector, ident)
	}
	return c
}

// Add adds a selector and call to the call list.
func (c CallList) Add(selector, ident string) CallList {
	if _, ok := c[selector]; !ok {
		c[selector] = make(map[string]bool)
	}
	c[selector][ident] = true
	return c
}

// Contains returns true if the package and function are members of this call list.
func (c CallList) Contains(selector, ident string) bool {
	if idents, ok := c[selector]; ok {
		return idents[ident]
	}
	return false
}

// ContainsPointer returns true if a pointer to the selector type or the type
// itself is a member of this call list.
func (c CallList) ContainsPointer(selector, ident string) bool {
	if strings.HasPrefix(selector, "*") {
		if c.Contains(selector, ident) {
			return true
		}
		s := strings.TrimPrefix(selector, "*")
		return c.Contains(s, ident)
	}
	return false
}

// ContainsPkgCallExpr resolves the call expression name and type, then looks up
// the package path for that type. Finally, it determines if the call exists
// within the call list.
func (c CallList) ContainsPkgCallExpr(n ast.Node, ctx *Context) *ast.CallExpr {
	selector, ident, err := GetCallInfo(n, ctx)
	if err != nil {
		return nil
	}

	// Selector can have two forms:
	// 1. A short name if a module function is called (expr.Name).
	// 2. A full name if a structure function is called (TypeOf(expr)).
	if !strings.ContainsRune(selector, '.') {
		path, ok := GetImportPath(selector, ctx)
		if !ok {
			return nil
		}
		selector = path
	}

	// Strip vendor path prefix if present
	if idx := strings.Index(selector, "vendor/"); idx >= 0 {
		selector = selector[idx+len("vendor/"):]
	}

	if !c.Contains(selector, ident) {
		return nil
	}

	return n.(*ast.CallExpr)
}

// ContainsCallExpr resolves the call expression name and type, then determines
// if the call exists within the call list.
func (c CallList) ContainsCallExpr(n ast.Node, ctx *Context) *ast.CallExpr {
	selector, ident, err := GetCallInfo(n, ctx)
	if err != nil {
		return nil
	}
	if !c.Contains(selector, ident) && !c.ContainsPointer(selector, ident) {
		return nil
	}
	return n.(*ast.CallExpr)
}

// GetCallInfo returns the package or type and name associated with a call expression.
func GetCallInfo(n ast.Node, ctx *Context) (string, string, error) {
	switch node := n.(type) {
	case *ast.CallExpr:
		switch fn := node.Fun.(type) {
		case *ast.SelectorExpr:
			switch expr := fn.X.(type) {
			case *ast.Ident:
				if expr.Obj != nil && expr.Obj.Kind == ast.Var {
					t := ctx.Info.TypeOf(expr)
					if t != nil {
						return t.String(), fn.Sel.Name, nil
					}
					return "undefined", fn.Sel.Name, fmt.Errorf("missing type info")
				}
				return expr.Name, fn.Sel.Name, nil
			case *ast.SelectorExpr:
				if expr.Sel != nil {
					t := ctx.Info.TypeOf(expr.Sel)
					if t != nil {
						return t.String(), fn.Sel.Name, nil
					}
					return "undefined", fn.Sel.Name, fmt.Errorf("missing type info")
				}
			}
		case *ast.Ident:
			if ctx.Pkg != nil {
				return ctx.Pkg.Name(), fn.Name, nil
			}
			return "", fn.Name, nil
		}
	}
	return "", "", fmt.Errorf("unable to determine call info")
}

// GetImportPath resolves the full import path of an identifier based on
// the imports in the current context (including aliases).
func GetImportPath(name string, ctx *Context) (string, bool) {
	for path, names := range ctx.Imports {
		for _, n := range names {
			if n == name {
				return path, true
			}
		}
	}
	return "", false
}

// GetString reads and returns a string value from an ast.BasicLit.
func GetString(n ast.Node) (string, error) {
	if node, ok := n.(*ast.BasicLit); ok && node.Kind == token.STRING {
		return strconv.Unquote(node.Value)
	}
	return "", fmt.Errorf("unexpected AST node type: %T", n)
}

// GetStringRecursive recursively walks down a tree of *ast.BinaryExpr,
// concatenating string results.
func GetStringRecursive(n ast.Node) (string, error) {
	if node, ok := n.(*ast.BasicLit); ok && node.Kind == token.STRING {
		return strconv.Unquote(node.Value)
	}
	if expr, ok := n.(*ast.BinaryExpr); ok {
		x, err := GetStringRecursive(expr.X)
		if err != nil {
			return "", err
		}
		y, err := GetStringRecursive(expr.Y)
		if err != nil {
			return "", err
		}
		return x + y, nil
	}
	return "", nil
}

// GetInt reads and returns an integer value from an ast.BasicLit.
func GetInt(n ast.Node) (int64, error) {
	if node, ok := n.(*ast.BasicLit); ok && node.Kind == token.INT {
		return strconv.ParseInt(node.Value, 0, 64)
	}
	return 0, fmt.Errorf("unexpected AST node type: %T", n)
}

// GetBinaryExprOperands returns all operands of a binary expression.
func GetBinaryExprOperands(be *ast.BinaryExpr) []ast.Node {
	var result []ast.Node
	var traverse func(be *ast.BinaryExpr)
	traverse = func(be *ast.BinaryExpr) {
		if lhs, ok := be.X.(*ast.BinaryExpr); ok {
			traverse(lhs)
		} else {
			result = append(result, be.X)
		}
		if rhs, ok := be.Y.(*ast.BinaryExpr); ok {
			traverse(rhs)
		} else {
			result = append(result, be.Y)
		}
	}
	traverse(be)
	return result
}

// TryResolve attempts to resolve all values in a subtree to known constants.
func TryResolve(n ast.Node, ctx *Context) bool {
	switch node := n.(type) {
	case *ast.BasicLit:
		return true
	case *ast.CompositeLit:
		if len(node.Elts) == 0 {
			return false
		}
		for _, arg := range node.Elts {
			if !TryResolve(arg, ctx) {
				return false
			}
		}
		return true
	case *ast.Ident:
		if node.Obj == nil || node.Obj.Kind != ast.Var {
			return true
		}
		if decl, ok := node.Obj.Decl.(ast.Node); ok {
			return TryResolve(decl, ctx)
		}
		return false
	case *ast.ValueSpec:
		if len(node.Values) == 0 {
			return false
		}
		for _, value := range node.Values {
			if !TryResolve(value, ctx) {
				return false
			}
		}
		return true
	case *ast.AssignStmt:
		if len(node.Rhs) == 0 {
			return false
		}
		for _, arg := range node.Rhs {
			if !TryResolve(arg, ctx) {
				return false
			}
		}
		return true
	case *ast.CallExpr:
		return false // Can't resolve call results
	case *ast.BinaryExpr:
		return TryResolve(node.X, ctx) && TryResolve(node.Y, ctx)
	case *ast.KeyValueExpr:
		return TryResolve(node.Key, ctx) && TryResolve(node.Value, ctx)
	case *ast.IndexExpr:
		return TryResolve(node.X, ctx)
	case *ast.SliceExpr:
		return TryResolve(node.X, ctx)
	}
	return false
}

// GetIdentStringValues returns the string values of an Ident if they can be resolved.
func GetIdentStringValues(ident *ast.Ident) []string {
	var values []string
	if ident.Obj == nil {
		return values
	}
	switch decl := ident.Obj.Decl.(type) {
	case *ast.ValueSpec:
		for _, v := range decl.Values {
			if val, err := GetString(v); err == nil {
				values = append(values, val)
			}
		}
	case *ast.AssignStmt:
		for _, v := range decl.Rhs {
			if val, err := GetString(v); err == nil {
				values = append(values, val)
			}
		}
	}
	return values
}

// MatchCallByPackage ensures that the specified package is imported,
// adjusts the name for any aliases, and checks if the call matches.
func MatchCallByPackage(n ast.Node, ctx *Context, pkg string, names ...string) (*ast.CallExpr, bool) {
	importedNames, found := ctx.Imports[pkg]
	if !found {
		return nil, false
	}

	callExpr, ok := n.(*ast.CallExpr)
	if !ok {
		return nil, false
	}

	packageName, callName, err := GetCallInfo(callExpr, ctx)
	if err != nil {
		return nil, false
	}

	for _, in := range importedNames {
		if packageName != in {
			continue
		}
		for _, name := range names {
			if callName == name {
				return callExpr, true
			}
		}
	}
	return nil, false
}

// getNodeLocation returns the filename and line number of an ast.Node.
func getNodeLocation(n ast.Node, ctx *Context) (string, int, int) {
	fobj := ctx.FileSet.File(n.Pos())
	if fobj == nil {
		return "", 0, 0
	}
	return fobj.Name(), fobj.Line(n.Pos()), fobj.Position(n.Pos()).Column
}

// makeFinding creates a Finding from a rule match.
func makeFinding(ruleID, title string, sev Severity, conf Confidence, cwe string, n ast.Node, ctx *Context) *Finding {
	file, line, col := getNodeLocation(n, ctx)
	return &Finding{
		RuleID:     ruleID,
		Title:      title,
		Severity:   sev,
		Confidence: conf,
		CWEID:      cwe,
		File:       file,
		Line:       line,
		Col:        col,
	}
}

// resolveTypeOf returns the type string of an expression, or empty string.
func resolveTypeOf(expr ast.Expr, ctx *Context) string {
	if ctx.Info == nil {
		return ""
	}
	t := ctx.Info.TypeOf(expr)
	if t == nil {
		return ""
	}
	return t.String()
}

// isOsPerm checks if the node is os.ModePerm.
func isOsPerm(n ast.Node) bool {
	if node, ok := n.(*ast.SelectorExpr); ok {
		if identX, ok := node.X.(*ast.Ident); ok {
			if identX.Name == "os" && node.Sel != nil && node.Sel.Name == "ModePerm" {
				return true
			}
		}
	}
	return false
}

// modeIsSubset checks if subset is a subset of superset.
func modeIsSubset(subset, superset int64) bool {
	return (subset | superset) == superset
}

// ContainingFile returns the *ast.File containing the given object.
func ContainingFile(obj types.Object, ctx *Context) *ast.File {
	if ctx.FileSet == nil || obj == nil {
		return nil
	}
	posFile := ctx.FileSet.File(obj.Pos())
	if posFile == nil {
		return nil
	}
	for _, f := range ctx.PkgFiles {
		if fileInfo := ctx.FileSet.File(f.Pos()); fileInfo != nil && fileInfo.Name() == posFile.Name() {
			return f
		}
	}
	return nil
}
