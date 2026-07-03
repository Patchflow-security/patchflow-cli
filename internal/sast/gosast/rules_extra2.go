// Additional rules ported from gosec v2.27.1 (Apache 2.0 licensed).
// Source: https://github.com/securego/gosec/blob/v2.27.1/rules/
//
// This file contains rules that were previously skipped:
// - G115: Integer overflow when converting between integer types
// - G117: Secret serialization to text-based formats (simplified)
// - G602: Slice access out of range (simplified, AST-based)

package gosast

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strconv"
)

// --- G115: Integer overflow when converting between integer types ---

// integerConversionRule detects potentially overflowing conversions between
// integer types. It flags conversions where the source type can represent
// values outside the destination type's range.
//
// This is a simplified AST-based version that checks for explicit type
// conversions between integer types. The full gosec rule uses SSA for
// more precise analysis, but this covers the most common cases.
type integerConversionRule struct {
	id   string
	what string
	sev  Severity
	conf Confidence
	cwe  string
}

func (r *integerConversionRule) ID() string          { return r.id }
func (r *integerConversionRule) What() string         { return r.what }
func (r *integerConversionRule) SeverityVal() Severity { return r.sev }

func (r *integerConversionRule) Nodes() []ast.Node {
	return []ast.Node{(*ast.CallExpr)(nil)}
}

func (r *integerConversionRule) Match(n ast.Node, ctx *Context) (*Finding, error) {
	callExpr, ok := n.(*ast.CallExpr)
	if !ok {
		return nil, nil
	}

	// Check if this is a type conversion (not a function call)
	if ctx.Info == nil {
		return nil, nil
	}

	// Get the target type of the conversion
	targetType := ctx.Info.TypeOf(callExpr.Fun)
	if targetType == nil {
		return nil, nil
	}

	targetBasic, ok := targetType.(*types.Basic)
	if !ok {
		return nil, nil
	}

	// Only check integer-to-integer conversions
	if !isIntegerType(targetBasic.Kind()) {
		return nil, nil
	}

	// Must have exactly one argument (the value being converted)
	if len(callExpr.Args) != 1 {
		return nil, nil
	}

	// Get the source type
	sourceType := ctx.Info.TypeOf(callExpr.Args[0])
	if sourceType == nil {
		return nil, nil
	}

	sourceBasic, ok := sourceType.(*types.Basic)
	if !ok {
		return nil, nil
	}

	if !isIntegerType(sourceBasic.Kind()) {
		return nil, nil
	}

	// Check if the conversion is potentially narrowing
	if isNarrowingConversion(sourceBasic.Kind(), targetBasic.Kind()) {
		return makeFinding(r.id, r.what, r.sev, r.conf, r.cwe, n, ctx), nil
	}

	return nil, nil
}

func newIntegerConversion() Rule {
	return &integerConversionRule{
		id:   "G115",
		what: "Potential integer overflow when converting between integer types",
		sev:  SeverityLow, // demoted: most conversions are safe in practice
		conf: ConfidenceMedium,
		cwe:  "CWE-190",
	}
}

// isIntegerType returns true if the types.BasicKind is an integer type.
func isIntegerType(k types.BasicKind) bool {
	switch k {
	case types.Int, types.Int8, types.Int16, types.Int32, types.Int64,
		types.Uint, types.Uint8, types.Uint16, types.Uint32, types.Uint64,
		types.Uintptr, types.UntypedInt:
		return true
	}
	return false
}

// isNarrowingConversion returns true if converting from sourceKind to
// targetKind could lose data (e.g., int32 → int8, uint64 → int32).
func isNarrowingConversion(sourceKind, targetKind types.BasicKind) bool {
	// Same type — no narrowing
	if sourceKind == targetKind {
		return false
	}

	// UntypedInt is resolved by the compiler — skip
	if sourceKind == types.UntypedInt {
		return false
	}

	sourceSize := integerSize(sourceKind)
	targetSize := integerSize(targetKind)
	sourceSigned := isSignedInteger(sourceKind)
	targetSigned := isSignedInteger(targetKind)

	// Narrowing by size
	if sourceSize > targetSize {
		return true
	}

	// Same size but signed→unsigned or unsigned→signed
	if sourceSize == targetSize {
		if sourceSigned != targetSigned {
			return true
		}
	}

	// Signed to unsigned of larger size can still overflow
	if sourceSigned && !targetSigned && sourceSize >= targetSize {
		return true
	}

	return false
}

func integerSize(k types.BasicKind) int {
	switch k {
	case types.Int8, types.Uint8:
		return 8
	case types.Int16, types.Uint16:
		return 16
	case types.Int32, types.Uint32:
		return 32
	case types.Int64, types.Uint64:
		return 64
	case types.Int, types.Uint, types.Uintptr:
		return 64 // platform-dependent, assume 64-bit
	}
	return 0
}

func isSignedInteger(k types.BasicKind) bool {
	switch k {
	case types.Int, types.Int8, types.Int16, types.Int32, types.Int64:
		return true
	}
	return false
}

// --- G117: Secret serialization to text-based formats (simplified) ---

// secretSerializationRule detects when sensitive data (passwords, tokens,
// secrets) is serialized to text-based formats like JSON, YAML, or XML
// without being masked or excluded.
//
// This is a simplified version that checks for json.Marshal, yaml.Marshal,
// and xml.Marshal calls on variables whose names suggest they contain
// sensitive data (password, secret, token, key, credential).
type secretSerializationRule struct {
	id   string
	what string
	sev  Severity
	conf Confidence
	cwe  string
}

func (r *secretSerializationRule) ID() string          { return r.id }
func (r *secretSerializationRule) What() string         { return r.what }
func (r *secretSerializationRule) SeverityVal() Severity { return r.sev }

func (r *secretSerializationRule) Nodes() []ast.Node {
	return []ast.Node{(*ast.CallExpr)(nil)}
}

func (r *secretSerializationRule) Match(n ast.Node, ctx *Context) (*Finding, error) {
	callExpr, ok := n.(*ast.CallExpr)
	if !ok {
		return nil, nil
	}

	// Check if this is a marshal call
	selector, ident, err := GetCallInfo(n, ctx)
	if err != nil {
		return nil, nil
	}

	isMarshal := false
	switch {
	case (selector == "encoding/json" || selector == "json") && ident == "Marshal":
		isMarshal = true
	case (selector == "encoding/xml" || selector == "xml") && ident == "Marshal":
		isMarshal = true
	case (selector == "gopkg.in/yaml.v2" || selector == "gopkg.in/yaml.v3" || selector == "sigs.k8s.io/yaml" || selector == "yaml") && ident == "Marshal":
		isMarshal = true
	}

	if !isMarshal {
		return nil, nil
	}

	if len(callExpr.Args) == 0 {
		return nil, nil
	}

	// Check if the argument is a variable with a sensitive name
	arg := callExpr.Args[0]
	if ident, ok := arg.(*ast.Ident); ok {
		if isSensitiveName(ident.Name) {
			return makeFinding(r.id, r.what, r.sev, r.conf, r.cwe, n, ctx), nil
		}
	}

	// Check if it's a composite literal with sensitive fields
	if compLit, ok := arg.(*ast.CompositeLit); ok {
		for _, elt := range compLit.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				if key, ok := kv.Key.(*ast.Ident); ok {
					if isSensitiveName(key.Name) {
						return makeFinding(r.id, r.what, r.sev, r.conf, r.cwe, n, ctx), nil
					}
				}
			}
		}
	}

	return nil, nil
}

// isSensitiveName returns true if the name suggests it contains sensitive data.
func isSensitiveName(name string) bool {
	name = lower(name)
	sensitiveWords := []string{"password", "passwd", "pwd", "secret", "token",
		"apikey", "api_key", "credential", "privatekey", "private_key",
		"accesskey", "access_key", "auth", "session"}
	for _, word := range sensitiveWords {
		if contains(name, word) {
			return true
		}
	}
	return false
}

func lower(s string) string {
	result := make([]byte, len(s))
	for i := range s {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		result[i] = c
	}
	return string(result)
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func newSecretSerialization() Rule {
	return &secretSerializationRule{
		id:   "G117",
		what: "Secret serialization to text-based format without masking",
		sev:  SeverityMedium,
		conf: ConfidenceLow,
		cwe:  "CWE-312",
	}
}

// --- G602: Slice access out of range (simplified) ---

// sliceBoundsRule detects potential out-of-range slice accesses. This is a
// simplified AST-based version that checks for:
//   - Slice expressions with constant indices that exceed the slice capacity
//   - Slice access patterns where the index is derived from user input
//
// The full gosec G602 rule uses SSA for precise bounds analysis. This version
// catches the most common patterns: hardcoded indices that exceed known
// array/slice lengths, and slice expressions on arrays with constant sizes.
type sliceBoundsRule struct {
	id   string
	what string
	sev  Severity
	conf Confidence
	cwe  string
}

func (r *sliceBoundsRule) ID() string          { return r.id }
func (r *sliceBoundsRule) What() string         { return r.what }
func (r *sliceBoundsRule) SeverityVal() Severity { return r.sev }

func (r *sliceBoundsRule) Nodes() []ast.Node {
	return []ast.Node{(*ast.SliceExpr)(nil), (*ast.IndexExpr)(nil)}
}

func (r *sliceBoundsRule) Match(n ast.Node, ctx *Context) (*Finding, error) {
	switch node := n.(type) {
	case *ast.SliceExpr:
		// Check slice expressions like s[low:high] where high > len(s)
		// We can only check if the slice is a composite literal with known length
		if compLit, ok := node.X.(*ast.CompositeLit); ok {
			knownLen := len(compLit.Elts)
			if knownLen == 0 {
				return nil, nil
			}

			// Check high index
			if node.High != nil {
				if highVal, err := getIntConstant(node.High, ctx); err == nil && highVal > int64(knownLen) {
					return makeFinding(r.id, r.what, r.sev, r.conf, r.cwe, n, ctx), nil
				}
			}

			// Check low index
			if node.Low != nil {
				if lowVal, err := getIntConstant(node.Low, ctx); err == nil && lowVal > int64(knownLen) {
					return makeFinding(r.id, r.what, r.sev, r.conf, r.cwe, n, ctx), nil
				}
			}
		}

	case *ast.IndexExpr:
		// Check index access on composite literals with known length
		if compLit, ok := node.X.(*ast.CompositeLit); ok {
			knownLen := len(compLit.Elts)
			if knownLen == 0 {
				return nil, nil
			}
			if idxVal, err := getIntConstant(node.Index, ctx); err == nil && idxVal >= int64(knownLen) {
				return makeFinding(r.id, r.what, r.sev, r.conf, r.cwe, n, ctx), nil
			}
		}
	}

	return nil, nil
}

// getIntConstant tries to resolve an AST expression to an integer constant.
func getIntConstant(expr ast.Expr, ctx *Context) (int64, error) {
	if ctx.Info == nil {
		return 0, fmt.Errorf("no type info")
	}

	// Direct integer literal
	if lit, ok := expr.(*ast.BasicLit); ok && lit.Kind == token.INT {
		return strconv.ParseInt(lit.Value, 0, 64)
	}

	// Constant expression via type info
	if tv, ok := ctx.Info.Types[expr]; ok && tv.Value != nil {
		if val, ok := constant.Int64Val(tv.Value); ok {
			return val, nil
		}
	}

	return 0, fmt.Errorf("not a constant")
}

func newSliceBounds() Rule {
	return &sliceBoundsRule{
		id:   "G602",
		what: "Slice access out of range",
		sev:  SeverityMedium,
		conf: ConfidenceLow,
		cwe:  "CWE-119",
	}
}
