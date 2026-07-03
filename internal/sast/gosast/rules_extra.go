// Additional rules ported from gosec v2.27.1 (Apache 2.0 licensed).
// Source: https://github.com/securego/gosec/blob/v2.27.1/rules/
//
// This file contains the second batch of ported rules:
// - G104: Unchecked errors
// - G109: Integer overflow (strconv.Atoi → int32/int16)
// - G110: Decompression bomb (io.Copy with compressed reader)
// - G111: Directory traversal (http.Dir("/"))
// - G112: Slowloris (missing ReadHeaderTimeout)
// - G307: os.Create default permissions
// - G402: Bad TLS connection settings
// - G403: Weak RSA key (< 2048 bits)
// - G406: Deprecated MD4/RIPEMD160
// - G601: Implicit memory aliasing in range loops (pre-Go 1.22)

package gosast

import (
	"crypto/tls"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"strings"
)

// --- G104: Errors unhandled ---

type noErrorCheckRule struct {
	id        string
	what      string
	sev       Severity
	conf      Confidence
	cwe       string
	whitelist CallList
}

func (r *noErrorCheckRule) ID() string          { return r.id }
func (r *noErrorCheckRule) What() string         { return r.what }
func (r *noErrorCheckRule) SeverityVal() Severity { return r.sev }

func (r *noErrorCheckRule) Nodes() []ast.Node {
	return []ast.Node{(*ast.AssignStmt)(nil), (*ast.ExprStmt)(nil)}
}

func (r *noErrorCheckRule) Match(n ast.Node, ctx *Context) (*Finding, error) {
	switch stmt := n.(type) {
	case *ast.AssignStmt:
		for _, expr := range stmt.Rhs {
			if callExpr, ok := expr.(*ast.CallExpr); ok && r.whitelist.ContainsCallExpr(expr, ctx) == nil {
				pos := returnsError(callExpr, ctx)
				if pos < 0 || pos >= len(stmt.Lhs) {
					continue
				}
				if id, ok := stmt.Lhs[pos].(*ast.Ident); ok && id.Name == "_" {
					return makeFinding(r.id, r.what, r.sev, r.conf, r.cwe, n, ctx), nil
				}
			}
		}
	case *ast.ExprStmt:
		if callExpr, ok := stmt.X.(*ast.CallExpr); ok && r.whitelist.ContainsCallExpr(stmt.X, ctx) == nil {
			pos := returnsError(callExpr, ctx)
			if pos >= 0 {
				return makeFinding(r.id, r.what, r.sev, r.conf, r.cwe, n, ctx), nil
			}
		}
	}
	return nil, nil
}

// returnsError checks if a call expression returns an error and returns its position.
func returnsError(callExpr *ast.CallExpr, ctx *Context) int {
	if ctx.Info == nil {
		return -1
	}
	if tv := ctx.Info.TypeOf(callExpr); tv != nil {
		switch t := tv.(type) {
		case *types.Tuple:
			for pos := 0; pos < t.Len(); pos++ {
				variable := t.At(pos)
				if variable != nil && variable.Type().String() == "error" {
					return pos
				}
			}
		case *types.Named:
			if t.String() == "error" {
				return 0
			}
		}
	}
	return -1
}

func newNoErrorCheck() Rule {
	whitelist := NewCallList()
	whitelist.AddAll("bytes.Buffer", "Write", "WriteByte", "WriteRune", "WriteString")
	whitelist.AddAll("fmt", "Print", "Printf", "Println", "Fprint", "Fprintf", "Fprintln")
	whitelist.AddAll("strings.Builder", "Write", "WriteByte", "WriteRune", "WriteString")
	whitelist.Add("io.PipeWriter", "CloseWithError")
	whitelist.Add("hash.Hash", "Write")
	whitelist.Add("os", "Unsetenv")
	whitelist.Add("rand", "Read")

	return &noErrorCheckRule{
		id:        "G104",
		what:      "Errors unhandled",
		sev:       SeverityInfo, // audit-only: unchecked errors are too noisy for default scan
		conf:      ConfidenceHigh,
		cwe:       "CWE-755",
		whitelist: whitelist,
	}
}

// --- G109: Integer overflow from strconv.Atoi → int32/int16 ---

type integerOverflowRule struct {
	id        string
	what      string
	sev       Severity
	conf      Confidence
	cwe       string
	calls     CallList
	atoiVars  map[*types.Var]struct{}
}

func (r *integerOverflowRule) ID() string          { return r.id }
func (r *integerOverflowRule) What() string         { return r.what }
func (r *integerOverflowRule) SeverityVal() Severity { return r.sev }

func (r *integerOverflowRule) Nodes() []ast.Node {
	return []ast.Node{(*ast.AssignStmt)(nil), (*ast.CallExpr)(nil)}
}

func (r *integerOverflowRule) Match(n ast.Node, ctx *Context) (*Finding, error) {
	if r.atoiVars == nil {
		r.atoiVars = make(map[*types.Var]struct{})
	}

	switch node := n.(type) {
	case *ast.AssignStmt:
		for _, expr := range node.Rhs {
			if callExpr, ok := expr.(*ast.CallExpr); ok && r.calls.ContainsPkgCallExpr(callExpr, ctx) != nil {
				if len(node.Lhs) > 0 {
					if idt, ok := node.Lhs[0].(*ast.Ident); ok && idt.Name != "_" {
						if ctx.Info != nil {
							if obj := ctx.Info.ObjectOf(idt); obj != nil {
								if v, ok := obj.(*types.Var); ok {
									r.atoiVars[v] = struct{}{}
								}
							}
						}
					}
				}
			}
		}
	case *ast.CallExpr:
		if fun, ok := node.Fun.(*ast.Ident); ok {
			if fun.Name == "int32" || fun.Name == "int16" {
				if len(node.Args) > 0 {
					if idt, ok := node.Args[0].(*ast.Ident); ok {
						if ctx.Info != nil {
							if obj := ctx.Info.ObjectOf(idt); obj != nil {
								if v, ok := obj.(*types.Var); ok {
									if _, tracked := r.atoiVars[v]; tracked {
										return makeFinding(r.id, r.what, r.sev, r.conf, r.cwe, n, ctx), nil
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return nil, nil
}

func newIntegerOverflow() Rule {
	r := &integerOverflowRule{
		id:   "G109",
		what: "Potential integer overflow from strconv.Atoi result conversion to int16/32",
		sev:  SeverityHigh,
		conf: ConfidenceMedium,
		cwe:  "CWE-190",
		calls: NewCallList(),
	}
	r.calls.Add("strconv", "Atoi")
	return r
}

// --- G110: Decompression bomb ---

type decompressionBombRule struct {
	id          string
	what        string
	sev         Severity
	conf        Confidence
	cwe         string
	readerCalls CallList
	copyCalls   CallList
	readerVars  map[*types.Var]struct{}
}

func (r *decompressionBombRule) ID() string          { return r.id }
func (r *decompressionBombRule) What() string         { return r.what }
func (r *decompressionBombRule) SeverityVal() Severity { return r.sev }

func (r *decompressionBombRule) Nodes() []ast.Node {
	return []ast.Node{(*ast.AssignStmt)(nil), (*ast.CallExpr)(nil)}
}

func (r *decompressionBombRule) Match(n ast.Node, ctx *Context) (*Finding, error) {
	if r.readerVars == nil {
		r.readerVars = make(map[*types.Var]struct{})
	}

	switch node := n.(type) {
	case *ast.AssignStmt:
		for i, expr := range node.Rhs {
			if callExpr, ok := expr.(*ast.CallExpr); ok {
				if containsReaderCall(callExpr, ctx, r.readerCalls) {
					if i < len(node.Lhs) {
						if idt, ok := node.Lhs[i].(*ast.Ident); ok && idt.Name != "_" {
							if ctx.Info != nil {
								if obj := ctx.Info.ObjectOf(idt); obj != nil {
									if v, ok := obj.(*types.Var); ok {
										r.readerVars[v] = struct{}{}
									}
								}
							}
						}
					}
				}
			}
		}
	case *ast.CallExpr:
		if r.copyCalls.ContainsPkgCallExpr(node, ctx) != nil {
			if len(node.Args) > 1 {
				if idt, ok := node.Args[1].(*ast.Ident); ok {
					if ctx.Info != nil {
						if obj := ctx.Info.ObjectOf(idt); obj != nil {
							if v, ok := obj.(*types.Var); ok {
								if _, tracked := r.readerVars[v]; tracked {
									return makeFinding(r.id, r.what, r.sev, r.conf, r.cwe, n, ctx), nil
								}
							}
						}
					}
				}
			}
		}
	}
	return nil, nil
}

func containsReaderCall(node ast.Node, ctx *Context, list CallList) bool {
	if list.ContainsPkgCallExpr(node, ctx) != nil {
		return true
	}
	s, idt, _ := GetCallInfo(node, ctx)
	return list.Contains(s, idt)
}

func newDecompressionBomb() Rule {
	r := &decompressionBombRule{
		id:          "G110",
		what:        "Potential DoS vulnerability via decompression bomb",
		sev:         SeverityMedium,
		conf:        ConfidenceMedium,
		cwe:         "CWE-409",
		readerCalls: NewCallList(),
		copyCalls:   NewCallList(),
	}
	r.readerCalls.Add("compress/gzip", "NewReader")
	r.readerCalls.AddAll("compress/zlib", "NewReader", "NewReaderDict")
	r.readerCalls.Add("compress/bzip2", "NewReader")
	r.readerCalls.AddAll("compress/flate", "NewReader", "NewReaderDict")
	r.readerCalls.Add("compress/lzw", "NewReader")
	r.readerCalls.Add("archive/tar", "NewReader")
	r.readerCalls.Add("archive/zip", "NewReader")
	r.readerCalls.Add("*archive/zip.File", "Open")
	r.copyCalls.AddAll("io", "Copy", "CopyBuffer")
	return r
}

// --- G111: Directory traversal (http.Dir("/")) ---

type directoryTraversalRule struct {
	id      string
	what    string
	sev     Severity
	conf    Confidence
	cwe     string
	pattern *regexp.Regexp
}

func (r *directoryTraversalRule) ID() string          { return r.id }
func (r *directoryTraversalRule) What() string         { return r.what }
func (r *directoryTraversalRule) SeverityVal() Severity { return r.sev }

func (r *directoryTraversalRule) Nodes() []ast.Node { return []ast.Node{(*ast.CallExpr)(nil)} }

func (r *directoryTraversalRule) Match(n ast.Node, ctx *Context) (*Finding, error) {
	callExpr, ok := n.(*ast.CallExpr)
	if !ok {
		return nil, nil
	}
	for _, arg := range callExpr.Args {
		if basiclit, ok1 := arg.(*ast.BasicLit); ok1 {
			if fun, ok2 := callExpr.Fun.(*ast.SelectorExpr); ok2 {
				if x, ok3 := fun.X.(*ast.Ident); ok3 {
					str := x.Name + "." + fun.Sel.Name + "(" + basiclit.Value + ")"
					if r.pattern.MatchString(str) {
						return makeFinding(r.id, r.what, r.sev, r.conf, r.cwe, n, ctx), nil
					}
				}
			}
		}
	}
	return nil, nil
}

func newDirectoryTraversal() Rule {
	return &directoryTraversalRule{
		id:      "G111",
		what:    "Potential directory traversal",
		sev:     SeverityMedium,
		conf:    ConfidenceMedium,
		cwe:     "CWE-22",
		pattern: regexp.MustCompile(`http\.Dir\("\/"\)|http\.Dir\('\/'\)`),
	}
}

// --- G112: Slowloris (missing ReadHeaderTimeout) ---

type slowlorisRule struct {
	id   string
	what string
	sev  Severity
	conf Confidence
	cwe  string
}

func (r *slowlorisRule) ID() string          { return r.id }
func (r *slowlorisRule) What() string         { return r.what }
func (r *slowlorisRule) SeverityVal() Severity { return r.sev }

func (r *slowlorisRule) Nodes() []ast.Node { return []ast.Node{(*ast.CompositeLit)(nil)} }

func (r *slowlorisRule) Match(n ast.Node, ctx *Context) (*Finding, error) {
	complit, ok := n.(*ast.CompositeLit)
	if !ok || complit.Type == nil {
		return nil, nil
	}
	if ctx.Info == nil {
		return nil, nil
	}
	actualType := ctx.Info.TypeOf(complit.Type)
	if actualType == nil || actualType.String() != "net/http.Server" {
		return nil, nil
	}
	if !containsReadHeaderTimeout(complit) {
		return makeFinding(r.id, r.what, r.sev, r.conf, r.cwe, n, ctx), nil
	}
	return nil, nil
}

func containsReadHeaderTimeout(node *ast.CompositeLit) bool {
	if node == nil {
		return false
	}
	for _, elt := range node.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if ident, ok := kv.Key.(*ast.Ident); ok {
				if ident.Name == "ReadHeaderTimeout" || ident.Name == "ReadTimeout" {
					return true
				}
			}
		}
	}
	return false
}

func newSlowloris() Rule {
	return &slowlorisRule{
		id:   "G112",
		what: "Potential Slowloris Attack because ReadHeaderTimeout is not configured in the http.Server",
		sev:  SeverityMedium,
		conf: ConfidenceLow,
		cwe:  "CWE-770",
	}
}

// --- G307: os.Create default permissions ---

type osCreatePermsRule struct {
	id          string
	what        string
	sev         Severity
	conf        Confidence
	cwe         string
	mode        int64
	pkgs        []string
	calls       []string
}

const defaultOsCreateMode = 0o666

func (r *osCreatePermsRule) ID() string          { return r.id }
func (r *osCreatePermsRule) What() string         { return r.what }
func (r *osCreatePermsRule) SeverityVal() Severity { return r.sev }

func (r *osCreatePermsRule) Nodes() []ast.Node { return []ast.Node{(*ast.CallExpr)(nil)} }

func (r *osCreatePermsRule) Match(n ast.Node, ctx *Context) (*Finding, error) {
	for _, pkg := range r.pkgs {
		if _, matched := MatchCallByPackage(n, ctx, pkg, r.calls...); matched {
			if !modeIsSubset(defaultOsCreateMode, r.mode) {
				return makeFinding(r.id, r.what, r.sev, r.conf, r.cwe, n, ctx), nil
			}
		}
	}
	return nil, nil
}

func newOsCreatePerms() Rule {
	mode := int64(0o666)
	return &osCreatePermsRule{
		id:    "G307",
		what:  fmt.Sprintf("Expect file permissions to be %#o or less but os.Create used with default permissions %#o", mode, defaultOsCreateMode),
		sev:   SeverityMedium,
		conf:  ConfidenceHigh,
		cwe:   "CWE-276",
		mode:  mode,
		pkgs:  []string{"os"},
		calls: []string{"Create"},
	}
}

// --- G402: Bad TLS connection settings ---

type insecureConfigTLSRule struct {
	id              string
	what            string
	sev             Severity
	conf            Confidence
	cwe             string
	requiredType    string
	minVersion      int64
	maxVersion      int64
	goodCiphers     []string
	actualMinVersion int64
	actualMaxVersion int64
	minVersionSet   bool
	maxVersionSet   bool
}

var tlsVersionMap = map[string]int64{
	"VersionTLS10": int64(tls.VersionTLS10),
	"VersionTLS11": int64(tls.VersionTLS11),
	"VersionTLS12": int64(tls.VersionTLS12),
	"VersionTLS13": int64(tls.VersionTLS13),
}

func (t *insecureConfigTLSRule) ID() string          { return t.id }
func (t *insecureConfigTLSRule) What() string         { return t.what }
func (t *insecureConfigTLSRule) SeverityVal() Severity { return t.sev }

func (t *insecureConfigTLSRule) Nodes() []ast.Node {
	return []ast.Node{(*ast.CompositeLit)(nil), (*ast.AssignStmt)(nil)}
}

func (t *insecureConfigTLSRule) Match(n ast.Node, ctx *Context) (*Finding, error) {
	if complit, ok := n.(*ast.CompositeLit); ok && complit.Type != nil {
		if ctx.Info == nil {
			return nil, nil
		}
		actualType := ctx.Info.TypeOf(complit.Type)
		if actualType != nil && actualType.String() == t.requiredType {
			defer t.resetVersion()
			for _, elt := range complit.Elts {
				if f := t.processTLSConf(elt, ctx); f != nil {
					return f, nil
				}
			}
			if f := t.checkVersion(n, ctx); f != nil {
				return f, nil
			}
		}
		return nil, nil
	}

	if assign, ok := n.(*ast.AssignStmt); ok && len(assign.Lhs) > 0 {
		if selector, ok := assign.Lhs[0].(*ast.SelectorExpr); ok {
			if ctx.Info != nil {
				actualType := ctx.Info.TypeOf(selector.X)
				if actualType != nil && strings.HasSuffix(actualType.String(), t.requiredType) {
					return t.processTLSConfVal(selector.Sel, assign.Rhs[0], ctx), nil
				}
			}
		}
	}
	return nil, nil
}

func (t *insecureConfigTLSRule) processTLSConf(n ast.Node, ctx *Context) *Finding {
	if kve, ok := n.(*ast.KeyValueExpr); ok {
		return t.processTLSConfVal(kve.Key, kve.Value, ctx)
	}
	if assign, ok := n.(*ast.AssignStmt); ok {
		if len(assign.Lhs) < 1 || len(assign.Rhs) < 1 {
			return nil
		}
		if selector, ok := assign.Lhs[0].(*ast.SelectorExpr); ok {
			return t.processTLSConfVal(selector.Sel, assign.Rhs[0], ctx)
		}
	}
	return nil
}

func (t *insecureConfigTLSRule) processTLSConfVal(key, value ast.Expr, ctx *Context) *Finding {
	if ident, ok := key.(*ast.Ident); ok {
		switch ident.Name {
		case "InsecureSkipVerify":
			val, known := t.resolveBoolConst(value, ctx)
			if known && val {
				return makeFinding(t.id, "TLS InsecureSkipVerify set to true.", SeverityHigh, ConfidenceHigh, t.cwe, value, ctx)
			}
			if !known {
				return makeFinding(t.id, "TLS InsecureSkipVerify may be set to true.", SeverityHigh, ConfidenceLow, t.cwe, value, ctx)
			}
		case "MinVersion":
			t.minVersionSet = true
			t.actualMinVersion = t.resolveTLSVersion(value, ctx)
		case "MaxVersion":
			t.maxVersionSet = true
			t.actualMaxVersion = t.resolveTLSVersion(value, ctx)
		case "CipherSuites":
			return t.processTLSCipherSuites(value, ctx)
		}
	}
	return nil
}

func (t *insecureConfigTLSRule) processTLSCipherSuites(n ast.Node, ctx *Context) *Finding {
	if ciphers, ok := n.(*ast.CompositeLit); ok {
		for _, elt := range ciphers.Elts {
			if ident, ok := elt.(*ast.SelectorExpr); ok {
				cipherName := ident.Sel.Name
				if !containsStr(t.goodCiphers, cipherName) {
					msg := fmt.Sprintf("TLS Bad Cipher Suite: %s", cipherName)
					return makeFinding(t.id, msg, SeverityHigh, ConfidenceHigh, t.cwe, ident, ctx)
				}
			}
		}
	}
	return nil
}

func (t *insecureConfigTLSRule) resolveTLSVersion(expr ast.Expr, ctx *Context) int64 {
	if val, err := GetInt(expr); err == nil {
		return val
	}
	if se, ok := expr.(*ast.SelectorExpr); ok {
		if x, ok := se.X.(*ast.Ident); ok {
			if _, ok := GetImportPath(x.Name, ctx); ok {
				return tlsVersionMap[se.Sel.Name]
			}
		}
	}
	return 0
}

func (t *insecureConfigTLSRule) resolveBoolConst(expr ast.Expr, _ *Context) (bool, bool) {
	if id, ok := expr.(*ast.Ident); ok {
		if id.Name == "true" {
			return true, true
		}
		if id.Name == "false" {
			return false, true
		}
	}
	if u, ok := expr.(*ast.UnaryExpr); ok && u.Op == token.NOT {
		if op, ok := u.X.(*ast.Ident); ok {
			if op.Name == "true" {
				return false, true
			}
			if op.Name == "false" {
				return true, true
			}
		}
	}
	return false, false
}

func (t *insecureConfigTLSRule) checkVersion(n ast.Node, ctx *Context) *Finding {
	if t.minVersionSet && t.actualMinVersion < t.minVersion {
		if t.actualMinVersion == 0 {
			return nil // safe default on Go 1.18+
		}
		return makeFinding(t.id, "TLS MinVersion too low.", SeverityHigh, ConfidenceHigh, t.cwe, n, ctx)
	}
	if t.maxVersionSet && t.actualMaxVersion != 0 && t.actualMaxVersion < t.maxVersion {
		return makeFinding(t.id, "TLS MaxVersion too low.", SeverityHigh, ConfidenceHigh, t.cwe, n, ctx)
	}
	return nil
}

func (t *insecureConfigTLSRule) resetVersion() {
	t.actualMinVersion = 0
	t.actualMaxVersion = 0
	t.minVersionSet = false
	t.maxVersionSet = false
}

func newBadTLSConfig() Rule {
	return &insecureConfigTLSRule{
		id:           "G402",
		what:         "TLS settings should be properly configured",
		sev:          SeverityMedium,
		conf:         ConfidenceHigh,
		cwe:          "CWE-295",
		requiredType: "crypto/tls.Config",
		minVersion:   int64(tls.VersionTLS12),
		maxVersion:   int64(tls.VersionTLS13),
		goodCiphers: []string{
			"TLS_AES_128_GCM_SHA256",
			"TLS_AES_256_GCM_SHA384",
			"TLS_CHACHA20_POLY1305_SHA256",
			"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
			"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		},
	}
}

// --- G403: Weak RSA key strength ---

type weakKeyStrengthRule struct {
	callListRule
	bits int64
}

func (w *weakKeyStrengthRule) Match(n ast.Node, ctx *Context) (*Finding, error) {
	callExpr := w.calls.ContainsPkgCallExpr(n, ctx)
	if callExpr == nil {
		return nil, nil
	}
	if len(callExpr.Args) < 2 {
		return nil, nil
	}
	if bits, err := GetInt(callExpr.Args[1]); err == nil && bits < w.bits {
		return makeFinding(w.id, w.what, w.sev, w.conf, w.cwe, n, ctx), nil
	}
	return nil, nil
}

func newWeakKeyStrength() Rule {
	bits := int64(2048)
	r := &weakKeyStrengthRule{
		callListRule: newCallListRule("G403", fmt.Sprintf("RSA keys should be at least %d bits", bits), SeverityMedium, ConfidenceHigh, "CWE-327"),
		bits:         bits,
	}
	r.Add("crypto/rsa", "GenerateKey")
	return r
}

// --- G406: Deprecated MD4/RIPEMD160 ---

func newDeprecatedCryptoHash() Rule {
	r := newCallListRule("G406", "Use of deprecated cryptographic primitive", SeverityMedium, ConfidenceHigh, "CWE-327")
	r.AddAll("golang.org/x/crypto/md4", "New", "Sum")
	r.AddAll("golang.org/x/crypto/ripemd160", "New", "Sum")
	return &r
}

// --- G601: Implicit memory aliasing in range loops (pre-Go 1.22) ---

type implicitAliasingRule struct {
	id             string
	what           string
	sev            Severity
	conf           Confidence
	cwe            string
	aliases        map[*types.Var]struct{}
	rightBrace     token.Pos
	acceptableAlias []*ast.UnaryExpr
}

func (r *implicitAliasingRule) ID() string          { return r.id }
func (r *implicitAliasingRule) What() string         { return r.what }
func (r *implicitAliasingRule) SeverityVal() Severity { return r.sev }

func (r *implicitAliasingRule) Nodes() []ast.Node {
	return []ast.Node{(*ast.RangeStmt)(nil), (*ast.UnaryExpr)(nil), (*ast.ReturnStmt)(nil)}
}

func (r *implicitAliasingRule) Match(n ast.Node, ctx *Context) (*Finding, error) {
	// This rule is not needed for Go 1.22+ where range loop variables have per-iteration scope.
	// We check the Go version at runtime; if we can't determine it, we run the rule.
	if goVersionGE122() {
		return nil, nil
	}

	switch node := n.(type) {
	case *ast.RangeStmt:
		if valueIdent, ok := node.Value.(*ast.Ident); ok {
			if ctx.Info != nil {
				if obj := ctx.Info.ObjectOf(valueIdent); obj != nil {
					if v, ok := obj.(*types.Var); ok {
						if r.aliases == nil {
							r.aliases = make(map[*types.Var]struct{})
						}
						r.aliases[v] = struct{}{}
						if node.Body != nil && r.rightBrace < node.Body.Rbrace {
							r.rightBrace = node.Body.Rbrace
						}
					}
				}
			}
		}

	case *ast.UnaryExpr:
		if node.Pos() > r.rightBrace {
			r.aliases = make(map[*types.Var]struct{})
			r.acceptableAlias = make([]*ast.UnaryExpr, 0)
		}
		if len(r.aliases) == 0 {
			return nil, nil
		}
		if containsUnaryExpr(r.acceptableAlias, node) {
			return nil, nil
		}
		if node.Op == token.AND {
			if identExpr, hasSelector := getIdentExpr(node.X); identExpr != nil {
				if ctx.Info != nil {
					if obj := ctx.Info.ObjectOf(identExpr); obj != nil {
						if v, ok := obj.(*types.Var); ok {
							if _, aliased := r.aliases[v]; aliased {
								_, isPointer := ctx.Info.TypeOf(identExpr).(*types.Pointer)
								if !hasSelector || !isPointer {
									return makeFinding(r.id, r.what, r.sev, r.conf, r.cwe, n, ctx), nil
								}
							}
						}
					}
				}
			}
		}

	case *ast.ReturnStmt:
		for _, res := range node.Results {
			if unary, ok := res.(*ast.UnaryExpr); ok && unary.Op == token.AND {
				r.acceptableAlias = append(r.acceptableAlias, unary)
			}
		}
	}
	return nil, nil
}

func containsUnaryExpr(exprs []*ast.UnaryExpr, expr *ast.UnaryExpr) bool {
	for _, e := range exprs {
		if e == expr {
			return true
		}
	}
	return false
}

func getIdentExpr(expr ast.Expr) (*ast.Ident, bool) {
	return doGetIdentExpr(expr, false)
}

func doGetIdentExpr(expr ast.Expr, hasSelector bool) (*ast.Ident, bool) {
	switch node := expr.(type) {
	case *ast.Ident:
		return node, hasSelector
	case *ast.SelectorExpr:
		return doGetIdentExpr(node.X, true)
	case *ast.UnaryExpr:
		return doGetIdentExpr(node.X, hasSelector)
	default:
		return nil, false
	}
}

func newImplicitAliasing() Rule {
	return &implicitAliasingRule{
		id:             "G601",
		what:           "Implicit memory aliasing in for loop.",
		sev:            SeverityMedium,
		conf:           ConfidenceMedium,
		cwe:            "CWE-123",
		aliases:        make(map[*types.Var]struct{}),
		rightBrace:     token.NoPos,
		acceptableAlias: make([]*ast.UnaryExpr, 0),
	}
}

// containsStr checks if a string is in a slice.
func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// goVersionGE122 checks if the Go version is >= 1.22.
// Since we can't reliably determine the project's Go version at analysis time
// without parsing go.mod, we default to false (run the rule).
// The rule itself checks for the loop variable pattern that was fixed in 1.22.
func goVersionGE122() bool {
	// Conservative: return false to always run the rule.
	// Users on Go 1.22+ can suppress with //patchflow:ignore G601
	return false
}
