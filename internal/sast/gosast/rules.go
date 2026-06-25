// Rules ported from gosec v2.27.1 (Apache 2.0 licensed).
// Source: https://github.com/securego/gosec/blob/v2.27.1/rules/
//
// These rules cover the most impactful security checks:
// - Injection (SQL, command execution)
// - Crypto (weak hashes, weak encryption, weak random)
// - Unsafe pointer usage
// - Filesystem (permissions, path traversal, temp files)
// - Network (bind to all interfaces, SSRF, HTTP timeouts)
// - Hardcoded credentials
// - Blocklisted imports
// - Template XSS
// - SSH host key
// - Pprof exposure
// - Trojan Source (bidirectional Unicode)

package gosast

import (
	"fmt"
	"go/ast"
	"go/token"
	"regexp"
	"strconv"
)

// --- Base rule types ---

// callListRule is a base for rules that check a CallList and issue on match.
type callListRule struct {
	id    string
	what  string
	sev   Severity
	conf  Confidence
	calls CallList
}

func newCallListRule(id, what string, sev Severity, conf Confidence) callListRule {
	return callListRule{
		id:    id,
		what:  what,
		sev:   sev,
		conf:  conf,
		calls: NewCallList(),
	}
}

func (r *callListRule) Add(selector, ident string) *callListRule {
	r.calls.Add(selector, ident)
	return r
}

func (r *callListRule) AddAll(selector string, idents ...string) *callListRule {
	r.calls.AddAll(selector, idents...)
	return r
}

func (r *callListRule) ID() string { return r.id }

func (r *callListRule) Nodes() []ast.Node { return []ast.Node{(*ast.CallExpr)(nil)} }

func (r *callListRule) Match(n ast.Node, ctx *Context) (*Finding, error) {
	if r.calls.ContainsPkgCallExpr(n, ctx) != nil {
		return makeFinding(r.id, r.what, r.sev, r.conf, n, ctx), nil
	}
	return nil, nil
}

// --- G201: SQL query construction using format string ---

type sqlStrFormat struct {
	callListRule
	patterns []*regexp.Regexp
}

var (
	sqlRegexp       = regexp.MustCompile(`(?i)(SELECT|DELETE|INSERT|UPDATE|INTO|FROM|WHERE)( |\n|\r|\t)`)
	sqlFormatRegexp = regexp.MustCompile(`%[^bdoxXfFp]`)
)

func (r *sqlStrFormat) Match(n ast.Node, ctx *Context) (*Finding, error) {
	callExpr, ok := n.(*ast.CallExpr)
	if !ok {
		return nil, nil
	}

	// Check if this is a fmt.Sprintf call
	if r.calls.ContainsPkgCallExpr(n, ctx) == nil {
		return nil, nil
	}

	// Check if the result is used in a SQL context (database/sql methods)
	// For simplicity, check if the first arg looks like SQL
	if len(callExpr.Args) == 0 {
		return nil, nil
	}

	for _, arg := range callExpr.Args {
		if str, err := GetStringRecursive(arg); err == nil && r.matchPatterns(str) {
			return makeFinding(r.id, r.what, r.sev, r.conf, n, ctx), nil
		}
	}
	return nil, nil
}

func (s *sqlStrFormat) matchPatterns(str string) bool {
	return sqlRegexp.MatchString(str) && sqlFormatRegexp.MatchString(str)
}

func newSQLStrFormat() Rule {
	r := &sqlStrFormat{
		callListRule: newCallListRule("G201", "SQL query construction using format string", SeverityMedium, ConfidenceHigh),
	}
	r.AddAll("fmt", "Sprintf", "Printf")
	return r
}

// --- G202: SQL query construction using string concatenation ---

type sqlStrConcat struct {
	callListRule
}

func (r *sqlStrConcat) Match(n ast.Node, ctx *Context) (*Finding, error) {
	switch stmt := n.(type) {
	case *ast.AssignStmt:
		for _, expr := range stmt.Rhs {
			if call, ok := expr.(*ast.CallExpr); ok {
				if r.checkQuery(call, ctx) {
					return makeFinding(r.id, r.what, r.sev, r.conf, stmt, ctx), nil
				}
			}
		}
	case *ast.ExprStmt:
		if call, ok := stmt.X.(*ast.CallExpr); ok {
			if r.checkQuery(call, ctx) {
				return makeFinding(r.id, r.what, r.sev, r.conf, stmt, ctx), nil
			}
		}
	}
	return nil, nil
}

func (r *sqlStrConcat) checkQuery(call *ast.CallExpr, ctx *Context) bool {
	// Check if this is a database/sql call
	if r.calls.ContainsCallExpr(call, ctx) == nil {
		return false
	}

	if len(call.Args) == 0 {
		return false
	}

	// Check the first argument (query string) for concatenation
	query := call.Args[0]
	if be, ok := query.(*ast.BinaryExpr); ok {
		operands := GetBinaryExprOperands(be)
		if len(operands) >= 2 {
			if start, ok := operands[0].(*ast.BasicLit); ok {
				if str, err := GetString(start); err == nil && sqlRegexp.MatchString(str) {
					// Check if any other operand is not resolvable (i.e., tainted)
					for _, op := range operands[1:] {
						if !TryResolve(op, ctx) {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func (r *sqlStrConcat) Nodes() []ast.Node {
	return []ast.Node{(*ast.AssignStmt)(nil), (*ast.ExprStmt)(nil)}
}

func newSQLStrConcat() Rule {
	r := &sqlStrConcat{
		callListRule: newCallListRule("G202", "SQL query construction using string concatenation", SeverityMedium, ConfidenceHigh),
	}
	r.AddAll("*database/sql.DB", "Exec", "Query", "QueryRow", "Prepare")
	r.AddAll("*database/sql.DB", "ExecContext", "QueryContext", "QueryRowContext", "PrepareContext")
	r.AddAll("*database/sql.Tx", "Exec", "Query", "QueryRow", "Prepare")
	r.AddAll("*database/sql.Tx", "ExecContext", "QueryContext", "QueryRowContext", "PrepareContext")
	r.AddAll("*database/sql.Conn", "ExecContext", "QueryContext", "QueryRowContext", "PrepareContext")
	return r
}

// --- G204: Subprocess launched with variable ---

type subprocessRule struct {
	callListRule
}

func (r *subprocessRule) Match(n ast.Node, ctx *Context) (*Finding, error) {
	node := r.calls.ContainsPkgCallExpr(n, ctx)
	if node == nil {
		return nil, nil
	}

	for _, arg := range node.Args {
		if !TryResolve(arg, ctx) {
			return makeFinding(r.id, "Subprocess launched with variable", SeverityMedium, ConfidenceHigh, n, ctx), nil
		}
	}
	return nil, nil
}

func newSubprocess() Rule {
	r := &subprocessRule{
		callListRule: newCallListRule("G204", "Subprocess launched with variable", SeverityMedium, ConfidenceHigh),
	}
	r.Add("os/exec", "Command")
	r.Add("os/exec", "CommandContext")
	r.Add("syscall", "Exec")
	r.Add("syscall", "ForkExec")
	r.Add("syscall", "StartProcess")
	r.Add("golang.org/x/sys/execabs", "Command")
	r.Add("golang.org/x/sys/execabs", "CommandContext")
	return r
}

// --- G103: Use of unsafe block ---

func newUsingUnsafe() Rule {
	r := newCallListRule("G103", "Use of unsafe calls should be audited", SeverityLow, ConfidenceHigh)
	r.AddAll("unsafe", "Pointer", "String", "StringData", "Slice", "SliceData")
	return &r
}

// --- G301: Poor file permissions used when creating a directory ---

type filePermissionsRule struct {
	id    string
	what  string
	sev   Severity
	conf  Confidence
	mode  int64
	pkgs  []string
	calls []string
}

func (r *filePermissionsRule) ID() string { return r.id }

func (r *filePermissionsRule) Nodes() []ast.Node { return []ast.Node{(*ast.CallExpr)(nil)} }

func (r *filePermissionsRule) Match(n ast.Node, ctx *Context) (*Finding, error) {
	for _, pkg := range r.pkgs {
		if callExpr, matched := MatchCallByPackage(n, ctx, pkg, r.calls...); matched {
			if len(callExpr.Args) == 0 {
				continue
			}
			modeArg := callExpr.Args[len(callExpr.Args)-1]
			if mode, err := GetInt(modeArg); err == nil && !modeIsSubset(mode, r.mode) || isOsPerm(modeArg) {
				return makeFinding(r.id, r.what, r.sev, r.conf, n, ctx), nil
			}
		}
	}
	return nil, nil
}

func newMkdirPermissions() Rule {
	return &filePermissionsRule{
		id:    "G301",
		what:  "Expect directory permissions to be 0750 or less",
		sev:   SeverityMedium,
		conf:  ConfidenceHigh,
		mode:  0o750,
		pkgs:  []string{"os"},
		calls: []string{"Mkdir", "MkdirAll"},
	}
}

// --- G302: Poor file permissions used when creating file or using chmod ---

func newFilePermissions() Rule {
	return &filePermissionsRule{
		id:    "G302",
		what:  "Expect file permissions to be 0600 or less",
		sev:   SeverityMedium,
		conf:  ConfidenceHigh,
		mode:  0o600,
		pkgs:  []string{"os"},
		calls: []string{"OpenFile", "Chmod"},
	}
}

// --- G306: Poor file permissions used when writing to a file ---

func newWritePermissions() Rule {
	return &filePermissionsRule{
		id:    "G306",
		what:  "Expect WriteFile permissions to be 0600 or less",
		sev:   SeverityMedium,
		conf:  ConfidenceHigh,
		mode:  0o600,
		pkgs:  []string{"io/ioutil", "os"},
		calls: []string{"WriteFile"},
	}
}

// --- G303: Creating tempfile using a predictable path ---

type badTempFileRule struct {
	callListRule
}

func (r *badTempFileRule) Match(n ast.Node, ctx *Context) (*Finding, error) {
	callExpr := r.calls.ContainsPkgCallExpr(n, ctx)
	if callExpr == nil {
		return nil, nil
	}
	if len(callExpr.Args) > 0 {
		if str, err := GetString(callExpr.Args[0]); err == nil && str != "" {
			return makeFinding(r.id, r.what, r.sev, r.conf, n, ctx), nil
		}
	}
	return nil, nil
}

func newBadTempFile() Rule {
	r := &badTempFileRule{
		callListRule: newCallListRule("G303", "Creating tempfile using a predictable path", SeverityMedium, ConfidenceHigh),
	}
	r.AddAll("os", "Create", "CreateTemp")
	r.AddAll("io/ioutil", "TempFile")
	return r
}

// --- G304: File path provided as taint input ---

type readFileRule struct {
	callListRule
}

func (r *readFileRule) Match(n ast.Node, ctx *Context) (*Finding, error) {
	callExpr := r.calls.ContainsPkgCallExpr(n, ctx)
	if callExpr == nil {
		return nil, nil
	}
	if len(callExpr.Args) > 0 {
		if !TryResolve(callExpr.Args[0], ctx) {
			return makeFinding(r.id, r.what, r.sev, r.conf, n, ctx), nil
		}
	}
	return nil, nil
}

func newReadFile() Rule {
	r := &readFileRule{
		callListRule: newCallListRule("G304", "File path provided as taint input", SeverityMedium, ConfidenceHigh),
	}
	r.AddAll("os", "Open", "OpenFile", "ReadFile")
	r.AddAll("io/ioutil", "ReadFile")
	return r
}

// --- G305: File path traversal when extracting zip archive ---

func newPathTraversal() Rule {
	r := newCallListRule("G305", "File path traversal when extracting zip archive", SeverityMedium, ConfidenceHigh)
	r.AddAll("archive/zip", "OpenReader", "NewReader")
	r.AddAll("archive/tar", "OpenReader", "NewReader")
	return &r
}

// --- G401: Detect the usage of MD5 or SHA1 ---

func newWeakCryptoHash() Rule {
	r := newCallListRule("G401", "Use of weak cryptographic primitive", SeverityMedium, ConfidenceHigh)
	r.AddAll("crypto/md5", "New", "Sum")
	r.AddAll("crypto/sha1", "New", "Sum")
	return &r
}

// --- G405: Detect the usage of DES or RC4 ---

func newWeakCryptoEncryption() Rule {
	r := newCallListRule("G405", "Use of weak cryptographic primitive", SeverityMedium, ConfidenceHigh)
	r.AddAll("crypto/des", "NewCipher", "NewTripleDESCipher")
	r.Add("crypto/rc4", "NewCipher")
	return &r
}

// --- G404: Insecure random number source ---

func newWeakRand() Rule {
	r := newCallListRule("G404", "Use of weak random number generator (math/rand instead of crypto/rand)", SeverityHigh, ConfidenceMedium)
	r.AddAll("math/rand", "New", "Read", "Float32", "Float64", "Int", "Int31", "Int31n",
		"Int63", "Int63n", "Intn", "NormFloat64", "Uint32", "Uint64")
	r.AddAll("math/rand/v2", "New", "Float32", "Float64", "Int", "Int32", "Int32N",
		"Int64", "Int64N", "IntN", "N", "NormFloat64", "Uint32", "Uint32N", "Uint64", "Uint64N", "UintN")
	return &r
}

// --- G102: Bind to all network interfaces ---

type bindToAllInterfacesRule struct {
	callListRule
	pattern *regexp.Regexp
}

func (r *bindToAllInterfacesRule) Match(n ast.Node, ctx *Context) (*Finding, error) {
	callExpr := r.calls.ContainsPkgCallExpr(n, ctx)
	if callExpr == nil {
		return nil, nil
	}
	if len(callExpr.Args) > 1 {
		arg := callExpr.Args[1]
		if bl, ok := arg.(*ast.BasicLit); ok {
			if val, err := GetString(bl); err == nil && r.pattern.MatchString(val) {
				return makeFinding(r.id, r.what, r.sev, r.conf, n, ctx), nil
			}
		} else if ident, ok := arg.(*ast.Ident); ok {
			for _, val := range GetIdentStringValues(ident) {
				if r.pattern.MatchString(val) {
					return makeFinding(r.id, r.what, r.sev, r.conf, n, ctx), nil
				}
			}
		}
	}
	return nil, nil
}

func newBindToAllInterfaces() Rule {
	r := &bindToAllInterfacesRule{
		callListRule: newCallListRule("G102", "Binds to all network interfaces", SeverityMedium, ConfidenceHigh),
		pattern:      regexp.MustCompile(`^(0\.0\.0\.0|:).*$`),
	}
	r.Add("net", "Listen")
	r.Add("crypto/tls", "Listen")
	return r
}

// --- G107: URL provided to HTTP request as taint input ---

type ssrfRule struct {
	callListRule
}

func (r *ssrfRule) Match(n ast.Node, ctx *Context) (*Finding, error) {
	callExpr := r.calls.ContainsPkgCallExpr(n, ctx)
	if callExpr == nil {
		return nil, nil
	}
	if len(callExpr.Args) > 0 {
		if !TryResolve(callExpr.Args[0], ctx) {
			return makeFinding(r.id, r.what, r.sev, r.conf, n, ctx), nil
		}
	}
	return nil, nil
}

func newSSRF() Rule {
	r := &ssrfRule{
		callListRule: newCallListRule("G107", "URL provided to HTTP request as taint input", SeverityMedium, ConfidenceHigh),
	}
	r.AddAll("net/http", "Get", "Post", "Head", "Get", "PostForm")
	return r
}

// --- G114: Use of net/http serve function without timeouts ---

func newHTTPServeWithoutTimeouts() Rule {
	r := newCallListRule("G114", "Use of net/http serve function that has no support for setting timeouts", SeverityMedium, ConfidenceHigh)
	r.AddAll("net/http", "Serve", "ServeTLS", "ListenAndServe", "ListenAndServeTLS")
	return &r
}

// --- G101: Hardcoded credentials ---

type hardcodedCredentialsRule struct {
	id           string
	what         string
	sev          Severity
	conf         Confidence
	pattern      *regexp.Regexp
}

var credentialPattern = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|apikey|api_key|private_key|access_key|client_secret)`)

func (r *hardcodedCredentialsRule) ID() string { return r.id }

func (r *hardcodedCredentialsRule) Nodes() []ast.Node {
	return []ast.Node{(*ast.AssignStmt)(nil), (*ast.ValueSpec)(nil)}
}

func (r *hardcodedCredentialsRule) Match(n ast.Node, ctx *Context) (*Finding, error) {
	switch node := n.(type) {
	case *ast.AssignStmt:
		for _, lhs := range node.Lhs {
			if ident, ok := lhs.(*ast.Ident); ok {
				if credentialPattern.MatchString(ident.Name) {
					for _, rhs := range node.Rhs {
						if val, err := GetString(rhs); err == nil && val != "" && len(val) > 3 {
							return makeFinding(r.id, fmt.Sprintf("%s: hardcoded credential in variable '%s'", r.what, ident.Name), r.sev, r.conf, n, ctx), nil
						}
					}
				}
			}
		}
	case *ast.ValueSpec:
		for _, ident := range node.Names {
			if credentialPattern.MatchString(ident.Name) {
				for _, val := range node.Values {
					if str, err := GetString(val); err == nil && str != "" && len(str) > 3 {
						return makeFinding(r.id, fmt.Sprintf("%s: hardcoded credential in variable '%s'", r.what, ident.Name), r.sev, r.conf, n, ctx), nil
					}
				}
			}
		}
	}
	return nil, nil
}

func newHardcodedCredentials() Rule {
	return &hardcodedCredentialsRule{
		id:      "G101",
		what:    "Hardcoded credentials",
		sev:     SeverityHigh,
		conf:    ConfidenceHigh,
		pattern: credentialPattern,
	}
}

// --- G501-G507: Blocklisted imports ---

type blocklistedImportsRule struct {
	id        string
	what      string
	sev       Severity
	conf      Confidence
	blocklist map[string]string // import path -> description
}

func (r *blocklistedImportsRule) ID() string { return r.id }

func (r *blocklistedImportsRule) Nodes() []ast.Node { return []ast.Node{(*ast.ImportSpec)(nil)} }

func (r *blocklistedImportsRule) Match(n ast.Node, ctx *Context) (*Finding, error) {
	imp, ok := n.(*ast.ImportSpec)
	if !ok {
		return nil, nil
	}
	path, err := strconv.Unquote(imp.Path.Value)
	if err != nil {
		return nil, nil
	}
	if desc, found := r.blocklist[path]; found {
		return makeFinding(r.id, fmt.Sprintf("%s: %s", r.what, desc), r.sev, r.conf, n, ctx), nil
	}
	return nil, nil
}

func newBlocklistedImports() Rule {
	return &blocklistedImportsRule{
		id:   "G501",
		what: "Import blocklist: weak crypto",
		sev:  SeverityMedium,
		conf: ConfidenceHigh,
		blocklist: map[string]string{
			"crypto/md5":                      "crypto/md5 is weak",
			"crypto/des":                      "crypto/des is weak",
			"crypto/rc4":                      "crypto/rc4 is weak",
			"crypto/sha1":                     "crypto/sha1 is weak",
			"net/http/cgi":                    "net/http/cgi has security risks",
			"golang.org/x/crypto/md4":         "md4 is deprecated and weak",
			"golang.org/x/crypto/ripemd160":   "ripemd160 is deprecated and weak",
		},
	}
}

// --- G203: Use of unescaped data in HTML templates ---

type templateCheckRule struct {
	callListRule
}

func (r *templateCheckRule) Match(n ast.Node, ctx *Context) (*Finding, error) {
	callExpr := r.calls.ContainsPkgCallExpr(n, ctx)
	if callExpr == nil {
		return nil, nil
	}
	// Check if any argument is a template.HTML type (which bypasses escaping)
	for _, arg := range callExpr.Args {
		typeStr := resolveTypeOf(arg, ctx)
		if typeStr == "template.HTML" || typeStr == "template.JS" || typeStr == "template.URL" {
			return makeFinding(r.id, r.what, r.sev, r.conf, n, ctx), nil
		}
	}
	return nil, nil
}

func newTemplateCheck() Rule {
	r := &templateCheckRule{
		callListRule: newCallListRule("G203", "Use of unescaped data in HTML templates", SeverityMedium, ConfidenceHigh),
	}
	r.AddAll("html/template", "HTML", "JS", "URL", "HTMLAttr")
	return r
}

// --- G106: SSH InsecureIgnoreHostKey ---

func newSSHHostKey() Rule {
	r := newCallListRule("G106", "Use of ssh.InsecureIgnoreHostKey function", SeverityMedium, ConfidenceHigh)
	r.Add("golang.org/x/crypto/ssh", "InsecureIgnoreHostKey")
	return &r
}

// --- G108: Profiling endpoint automatically exposed ---

func newPprofCheck() Rule {
	r := newCallListRule("G108", "Profiling endpoint is automatically exposed", SeverityMedium, ConfidenceHigh)
	r.Add("net/http/pprof", "Index")
	return &r
}

// --- G116: Trojan Source (bidirectional Unicode) ---

type trojanSourceRule struct {
	id     string
	what   string
	sev    Severity
	conf   Confidence
	bidiRe *regexp.Regexp
}

var bidiUnicodeRe = regexp.MustCompile(`[\x{202A}-\x{202E}\x{2066}-\x{2069}\x{200E}\x{200F}\x{061C}]`)

func (r *trojanSourceRule) ID() string { return r.id }

func (r *trojanSourceRule) Nodes() []ast.Node { return []ast.Node{(*ast.BasicLit)(nil)} }

func (r *trojanSourceRule) Match(n ast.Node, ctx *Context) (*Finding, error) {
	lit, ok := n.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return nil, nil
	}
	str, err := strconv.Unquote(lit.Value)
	if err != nil {
		return nil, nil
	}
	if r.bidiRe.MatchString(str) {
		return makeFinding(r.id, r.what, r.sev, r.conf, n, ctx), nil
	}
	return nil, nil
}

func newTrojanSource() Rule {
	return &trojanSourceRule{
		id:      "G116",
		what:    "Potential Trojan Source attack: bidirectional Unicode characters detected",
		sev:     SeverityMedium,
		conf:    ConfidenceHigh,
		bidiRe:  bidiUnicodeRe,
	}
}
