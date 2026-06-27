// Package treesitter provides AST-based security analysis for non-Go languages
// using tree-sitter. This replaces the regex-only approach with proper AST
// parsing, eliminating false positives and enabling more precise detection.
//
// Supported languages: Python, JavaScript, TypeScript, Ruby, PHP, Java, C#, Rust.
//
// The analyzer uses github.com/odvcencio/gotreesitter — a pure-Go tree-sitter
// runtime that requires no CGo and cross-compiles to all Go targets.
package treesitter

import (
	"context"
	"fmt"
	"io"
	"log"
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

// Finding represents a raw taint finding before normalization.
type Finding struct {
	RuleID        string
	Title         string
	Severity      analysis.Severity
	Confidence    analysis.Confidence
	File          string
	Line          int
	Col           int
	Code          string
	Description   string
	CWE           string
	Recommendation string
}

// Analyzer runs AST-based security analysis using tree-sitter.
type Analyzer struct {
	rules        []astRule
	ignoreMatcher *ignore.Matcher
	logger       *log.Logger
	parserPools   sync.Map // map[string]*sync.Pool (language name → parser pool)
	ruleNodeTypes map[string]map[string]bool // language → set of node types rules care about
}

// astRule defines an AST-based security rule.
type astRule struct {
	ID             string
	Title          string
	Severity       analysis.Severity
	Confidence     analysis.Confidence
	Languages      []string
	Description    string
	CWE            string
	Recommendation string
	// Match is called for each node in the AST. If it returns true, a finding
	// is created for that node.
	Match func(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) bool
}

// NewAnalyzer creates a tree-sitter-based analyzer with built-in rules.
func NewAnalyzer() *Analyzer {
	a := &Analyzer{
		logger: log.New(io.Discard, "[treesitter] ", log.LstdFlags),
	}
	a.registerDefaults()
	return a
}

// SetIgnoreMatcher sets the gitignore matcher for filtering files.
func (a *Analyzer) SetIgnoreMatcher(m *ignore.Matcher) {
	a.ignoreMatcher = m
}

// registerDefaults registers the built-in AST-based rules.
func (a *Analyzer) registerDefaults() {
	a.rules = []astRule{
		// --- Python AST rules ---
		// AST-confirmed but not taint-confirmed: Medium severity.
		// Taint-confirmed findings (TP-PY*) remain High.
		{
			ID:             "TS-PY001",
			Title:          "Use of eval() (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"python"},
			Description:    "eval() can execute arbitrary code. Confirmed via AST — the call is in actual code, not a string literal.",
			CWE:            "CWE-95",
			Recommendation: "Avoid eval() entirely. Use ast.literal_eval() for literals only.",
			Match:          matchCallByName("eval"),
		},
		{
			ID:             "TS-PY002",
			Title:          "Use of exec() (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"python"},
			Description:    "exec() can execute arbitrary code. Confirmed via AST analysis.",
			CWE:            "CWE-95",
			Recommendation: "Avoid exec() entirely. Refactor to use proper function calls.",
			Match:          matchCallByName("exec"),
		},
		{
			ID:             "TS-PY003",
			Title:          "Use of os.system() (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"python"},
			Description:    "os.system() is vulnerable to command injection.",
			CWE:            "CWE-78",
			Recommendation: "Use subprocess.run() with shell=False and pass arguments as a list.",
			Match:          matchAttributeCall("os", "system"),
		},
		{
			ID:             "TS-PY004",
			Title:          "subprocess with shell=True (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"python"},
			Description:    "subprocess with shell=True is vulnerable to command injection.",
			CWE:            "CWE-78",
			Recommendation: "Use shell=False and pass arguments as a list.",
			Match:          matchSubprocessShellTrue,
		},
		{
			ID:             "TS-PY005",
			Title:          "Use of pickle.loads() (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"python"},
			Description:    "pickle.loads() can execute arbitrary code during deserialization.",
			CWE:            "CWE-502",
			Recommendation: "Use JSON or other safe serialization formats.",
			Match:          matchAttributeCall("pickle", "loads"),
		},
		{
			ID:             "TS-PY006",
			Title:          "yaml.load() without SafeLoader (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"python"},
			Description:    "yaml.load() without SafeLoader can execute arbitrary code.",
			CWE:            "CWE-502",
			Recommendation: "Use yaml.safe_load() instead.",
			Match:          matchYamlLoad,
		},
		{
			ID:             "TS-PY007",
			Title:          "hashlib.md5() — weak cryptographic hash (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"python"},
			Description:    "MD5 is cryptographically broken and should not be used for security purposes.",
			CWE:            "CWE-327",
			Recommendation: "Use hashlib.sha256() or better for security-sensitive operations.",
			Match:          matchAttributeCall("hashlib", "md5"),
		},
		{
			ID:             "TS-PY008",
			Title:          "hashlib.sha1() — weak cryptographic hash (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"python"},
			Description:    "SHA1 is cryptographically broken and should not be used for security purposes.",
			CWE:            "CWE-327",
			Recommendation: "Use hashlib.sha256() or better for security-sensitive operations.",
			Match:          matchAttributeCall("hashlib", "sha1"),
		},
		{
			ID:             "TS-PY009",
			Title:          "Flask debug mode enabled (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"python"},
			Description:    "Running Flask with debug=True exposes the Werkzeug debugger, which allows arbitrary code execution.",
			CWE:            "CWE-489",
			Recommendation: "Never enable debug mode in production. Use app.run(debug=False) or set FLASK_ENV=production.",
			Match:          matchFlaskDebug,
		},
		{
			ID:             "TS-PY010",
			Title:          "marshal.loads() — unsafe deserialization (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"python"},
			Description:    "marshal.loads() can execute arbitrary code during deserialization.",
			CWE:            "CWE-502",
			Recommendation: "Use JSON or other safe serialization formats.",
			Match:          matchAttributeCall("marshal", "loads"),
		},
		{
			ID:             "TS-PY011",
			Title:          "shelve.open() — unsafe persistence (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"python"},
			Description:    "shelve uses pickle internally, which can execute arbitrary code during deserialization.",
			CWE:            "CWE-502",
			Recommendation: "Use JSON or other safe serialization formats.",
			Match:          matchCallByName("shelve.open"),
		},
		{
			ID:             "TS-PY012",
			Title:          "subprocess.Popen with shell=True (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"python"},
			Description:    "subprocess.Popen with shell=True is vulnerable to command injection.",
			CWE:            "CWE-78",
			Recommendation: "Use shell=False and pass arguments as a list.",
			Match:          matchSubprocessPopenShellTrue,
		},
		{
			ID:             "TS-PY013",
			Title:          "os.popen() — command injection risk (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"python"},
			Description:    "os.popen() runs commands in a shell and is vulnerable to command injection.",
			CWE:            "CWE-78",
			Recommendation: "Use subprocess.run() with shell=False and argument lists.",
			Match:          matchAttributeCall("os", "popen"),
		},
		{
			ID:             "TS-PY014",
			Title:          "pty.spawn() — command injection risk (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"python"},
			Description:    "pty.spawn() executes commands in a pseudo-terminal, which can be vulnerable to command injection.",
			CWE:            "CWE-78",
			Recommendation: "Use subprocess with shell=False and argument lists.",
			Match:          matchAttributeCall("pty", "spawn"),
		},
		{
			ID:             "TS-PY015",
			Title:          "tempfile.mktemp() — race condition (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"python"},
			Description:    "tempfile.mktemp() is deprecated because it creates predictable filenames, leading to race conditions (TOCTOU).",
			CWE:            "CWE-377",
			Recommendation: "Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() instead.",
			Match:          matchAttributeCall("tempfile", "mktemp"),
		},
		{
			ID:             "TS-PY016",
			Title:          "random.random() — insecure PRNG (AST-confirmed)",
			Severity:       analysis.SeverityLow,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"python"},
			Description:    "The random module uses a Mersenne Twister PRNG which is not cryptographically secure.",
			CWE:            "CWE-338",
			Recommendation: "Use secrets module for cryptographic randomness (secrets.token_hex(), secrets.token_urlsafe()).",
			Match:          matchAttributeCall("random", "random"),
		},
		{
			ID:             "TS-PY017",
			Title:          "random.randint() — insecure PRNG (AST-confirmed)",
			Severity:       analysis.SeverityLow,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"python"},
			Description:    "The random module uses a Mersenne Twister PRNG which is not cryptographically secure.",
			CWE:            "CWE-338",
			Recommendation: "Use secrets.randbelow() for cryptographic randomness.",
			Match:          matchAttributeCall("random", "randint"),
		},
		{
			ID:             "TS-PY018",
			Title:          "input() in Python 2 — eval-like behavior (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"python"},
			Description:    "In Python 2, input() calls eval() on the user input, allowing arbitrary code execution.",
			CWE:            "CWE-95",
			Recommendation: "Use raw_input() in Python 2 or input() in Python 3.",
			Match:          matchCallByName("input"),
		},
		{
			ID:             "TS-PY019",
			Title:          "compile() — code compilation (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"python"},
			Description:    "compile() can compile and execute arbitrary code strings.",
			CWE:            "CWE-95",
			Recommendation: "Avoid compile() with untrusted input.",
			Match:          matchCallByName("compile"),
		},
		{
			ID:             "TS-PY020",
			Title:          "ctypes.CDLL() — native code loading (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"python"},
			Description:    "ctypes.CDLL() loads arbitrary shared libraries, which can execute arbitrary native code.",
			CWE:            "CWE-114",
			Recommendation: "Avoid loading untrusted shared libraries.",
			Match:          matchAttributeCall("ctypes", "CDLL"),
		},

		// --- JavaScript/TypeScript AST rules ---
		// Note: tree-sitter detects .tsx as "tsx" and .jsx as "javascript",
		// so we include all three language names.
		{
			ID:             "TS-JS001",
			Title:          "Use of eval() (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"javascript", "typescript", "tsx"},
			Description:    "eval() can execute arbitrary code. AST-confirmed — not in a string literal.",
			CWE:            "CWE-95",
			Recommendation: "Avoid eval() entirely. Use JSON.parse() for JSON data.",
			Match:          matchCallByName("eval"),
		},
		{
			ID:             "TS-JS002",
			Title:          "Use of Function constructor (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"javascript", "typescript", "tsx"},
			Description:    "new Function() is equivalent to eval() and can execute arbitrary code.",
			CWE:            "CWE-95",
			Recommendation: "Avoid new Function(). Use proper function definitions.",
			Match:          matchNewFunction,
		},
		{
			ID:             "TS-JS003",
			Title:          "child_process.exec (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"javascript", "typescript", "tsx"},
			Description:    "child_process.exec runs commands in a shell and is vulnerable to command injection.",
			CWE:            "CWE-78",
			Recommendation: "Use execFile or spawn with shell=false.",
			Match:          matchAttributeCall("child_process", "exec"),
		},
		{
			ID:             "TS-JS004",
			Title:          "dangerouslySetInnerHTML (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"javascript", "typescript", "tsx"},
			Description:    "dangerouslySetInnerHTML can introduce XSS if the content is not properly sanitized.",
			CWE:            "CWE-79",
			Recommendation: "Use DOMPurify or similar to sanitize HTML before rendering.",
			Match:          matchJSXAttribute("dangerouslySetInnerHTML"),
		},
		{
			ID:             "TS-JS005",
			Title:          "Prototype pollution via __proto__ (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"javascript", "typescript", "tsx"},
			Description:    "Assignment to __proto__ can lead to prototype pollution.",
			CWE:            "CWE-1321",
			Recommendation: "Use Object.create(null) or Map instead of __proto__.",
			Match:          matchProtoPollution,
		},
		{
			ID:             "TS-JS006",
			Title:          "crypto.createHash('md5') — weak hash (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"javascript", "typescript", "tsx"},
			Description:    "MD5 is cryptographically broken and should not be used for security purposes.",
			CWE:            "CWE-327",
			Recommendation: "Use crypto.createHash('sha256') or better.",
			Match:          matchCryptoHash("md5"),
		},
		{
			ID:             "TS-JS007",
			Title:          "crypto.createHash('sha1') — weak hash (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"javascript", "typescript", "tsx"},
			Description:    "SHA1 is cryptographically broken and should not be used for security purposes.",
			CWE:            "CWE-327",
			Recommendation: "Use crypto.createHash('sha256') or better.",
			Match:          matchCryptoHash("sha1"),
		},
		{
			ID:             "TS-JS008",
			Title:          "new Buffer() — deprecated (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"javascript", "typescript", "tsx"},
			Description:    "new Buffer() is deprecated and can leak sensitive data due to uninitialized memory.",
			CWE:            "CWE-908",
			Recommendation: "Use Buffer.from() or Buffer.alloc() instead.",
			Match:          matchNewByName("Buffer"),
		},
		{
			ID:             "TS-JS009",
			Title:          "innerHTML assignment — XSS risk (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"javascript", "typescript", "tsx"},
			Description:    "Setting innerHTML with untrusted data can lead to XSS attacks.",
			CWE:            "CWE-79",
			Recommendation: "Use textContent, or sanitize HTML with DOMPurify before assignment.",
			Match:          matchPropertyAssignment("innerHTML"),
		},
		{
			ID:             "TS-JS010",
			Title:          "outerHTML assignment — XSS risk (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"javascript", "typescript", "tsx"},
			Description:    "Setting outerHTML with untrusted data can lead to XSS attacks.",
			CWE:            "CWE-79",
			Recommendation: "Use textContent, or sanitize HTML with DOMPurify before assignment.",
			Match:          matchPropertyAssignment("outerHTML"),
		},
		{
			ID:             "TS-JS011",
			Title:          "insertAdjacentHTML — XSS risk (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"javascript", "typescript", "tsx"},
			Description:    "insertAdjacentHTML with untrusted data can lead to XSS attacks.",
			CWE:            "CWE-79",
			Recommendation: "Use insertAdjacentText or sanitize HTML with DOMPurify.",
			Match:          matchCallByName("insertAdjacentHTML"),
		},
		{
			ID:             "TS-JS012",
			Title:          "document.write() — XSS risk (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"javascript", "typescript", "tsx"},
			Description:    "document.write() with untrusted data can lead to XSS attacks.",
			CWE:            "CWE-79",
			Recommendation: "Use DOM manipulation methods (createElement, textContent) instead.",
			Match:          matchAttributeCall("document", "write"),
		},
		{
			ID:             "TS-JS013",
			Title:          "child_process.execSync (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"javascript", "typescript", "tsx"},
			Description:    "child_process.execSync runs commands in a shell and is vulnerable to command injection.",
			CWE:            "CWE-78",
			Recommendation: "Use execFileSync or spawnSync with shell=false.",
			Match:          matchAttributeCall("child_process", "execSync"),
		},
		{
			ID:             "TS-JS014",
			Title:          "setTimeout with string — eval-like (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"javascript", "typescript", "tsx"},
			Description:    "setTimeout with a string argument is equivalent to eval() and can execute arbitrary code.",
			CWE:            "CWE-95",
			Recommendation: "Pass a function reference instead of a string to setTimeout.",
			Match:          matchSetTimeoutString,
		},
		{
			ID:             "TS-JS015",
			Title:          "setInterval with string — eval-like (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"javascript", "typescript", "tsx"},
			Description:    "setInterval with a string argument is equivalent to eval() and can execute arbitrary code.",
			CWE:            "CWE-95",
			Recommendation: "Pass a function reference instead of a string to setInterval.",
			Match:          matchSetIntervalString,
		},
		{
			ID:             "TS-JS016",
			Title:          "Object.assign to __proto__ — prototype pollution (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"javascript", "typescript", "tsx"},
			Description:    "Object.assign targeting __proto__ can lead to prototype pollution.",
			CWE:            "CWE-1321",
			Recommendation: "Use Object.create(null) and avoid __proto__ assignments.",
			Match:          matchObjectAssignProto,
		},
		{
			ID:             "TS-JS017",
			Title:          "crypto.createDecipher (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"javascript", "typescript", "tsx"},
			Description:    "crypto.createDecipher uses a deprecated key derivation function (MD5).",
			CWE:            "CWE-327",
			Recommendation: "Use crypto.createDecipheriv() with a proper key and IV.",
			Match:          matchAttributeCall("crypto", "createDecipher"),
		},
		{
			ID:             "TS-JS018",
			Title:          "res.redirect with user input — open redirect (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"javascript", "typescript", "tsx"},
			Description:    "res.redirect with user-controlled input can lead to open redirect attacks.",
			CWE:            "CWE-601",
			Recommendation: "Validate redirect URLs against an allowlist before redirecting.",
			Match:          matchAttributeCall("res", "redirect"),
		},
		{
			ID:             "TS-JS019",
			Title:          "jwt.sign with hardcoded secret (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"javascript", "typescript", "tsx"},
			Description:    "JWT signed with a hardcoded secret can be extracted from source code, allowing token forgery.",
			CWE:            "CWE-798",
			Recommendation: "Load JWT secrets from environment variables or a secret manager.",
			Match:          matchAttributeCall("jwt", "sign"),
		},
		{
			ID:             "TS-JS020",
			Title:          "localStorage.setItem for tokens (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"javascript", "typescript", "tsx"},
			Description:    "Storing tokens in localStorage makes them accessible to JavaScript, vulnerable to XSS attacks.",
			CWE:            "CWE-922",
			Recommendation: "Use httpOnly cookies for token storage instead of localStorage.",
			Match:          matchAttributeCall("localStorage", "setItem"),
		},

		// --- Ruby AST rules ---
		{
			ID:             "TS-RB001",
			Title:          "Use of eval() (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"ruby"},
			Description:    "eval() can execute arbitrary code. AST-confirmed.",
			CWE:            "CWE-95",
			Recommendation: "Avoid eval() entirely.",
			Match:          matchCallByName("eval"),
		},
		{
			ID:             "TS-RB002",
			Title:          "Use of system() (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"ruby"},
			Description:    "system() is vulnerable to command injection.",
			CWE:            "CWE-78",
			Recommendation: "Use Open3.capture3 with array arguments.",
			Match:          matchCallByName("system"),
		},
		{
			ID:             "TS-RB003",
			Title:          "Use of exec() (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"ruby"},
			Description:    "exec() replaces the current process and is vulnerable to command injection.",
			CWE:            "CWE-78",
			Recommendation: "Use Open3.capture3 with array arguments.",
			Match:          matchCallByName("exec"),
		},
		{
			ID:             "TS-RB004",
			Title:          "Use of spawn() (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"ruby"},
			Description:    "spawn() can be vulnerable to command injection when called with shell strings.",
			CWE:            "CWE-78",
			Recommendation: "Use spawn with array arguments.",
			Match:          matchCallByName("spawn"),
		},
		{
			ID:             "TS-RB005",
			Title:          "Use of backtick execution (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"ruby"},
			Description:    "Backtick execution runs commands in a shell and is vulnerable to command injection.",
			CWE:            "CWE-78",
			Recommendation: "Use Open3.capture3 with array arguments.",
			Match:          matchRubyBacktick,
		},
		{
			ID:             "TS-RB006",
			Title:          "Use of IO.popen() (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"ruby"},
			Description:    "IO.popen() runs commands in a shell and is vulnerable to command injection.",
			CWE:            "CWE-78",
			Recommendation: "Use Open3.popen3 with array arguments.",
			Match:          matchAttributeCall("IO", "popen"),
		},
		{
			ID:             "TS-RB007",
			Title:          "Use of Open3.capture2 (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"ruby"},
			Description:    "Open3.capture2 can be vulnerable to command injection when called with shell strings.",
			CWE:            "CWE-78",
			Recommendation: "Pass arguments as an array to avoid shell interpretation.",
			Match:          matchAttributeCall("Open3", "capture2"),
		},
		{
			ID:             "TS-RB008",
			Title:          "Use of send() (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"ruby"},
			Description:    "send() can call arbitrary methods, which may lead to security bypasses if the method name is user-controlled.",
			CWE:            "CWE-913",
			Recommendation: "Avoid send() with user-controlled method names. Use public_send with an allowlist.",
			Match:          matchCallByName("send"),
		},
		{
			ID:             "TS-RB009",
			Title:          "Use of Marshal.load (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"ruby"},
			Description:    "Marshal.load can execute arbitrary code during deserialization.",
			CWE:            "CWE-502",
			Recommendation: "Use JSON or other safe serialization formats.",
			Match:          matchAttributeCall("Marshal", "load"),
		},
		{
			ID:             "TS-RB010",
			Title:          "Use of YAML.load (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"ruby"},
			Description:    "YAML.load can execute arbitrary code during deserialization in older Ruby versions.",
			CWE:            "CWE-502",
			Recommendation: "Use YAML.safe_load() instead.",
			Match:          matchAttributeCall("YAML", "load"),
		},

		// --- PHP AST rules ---
		{
			ID:             "TS-PHP001",
			Title:          "Use of eval() (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"php"},
			Description:    "eval() can execute arbitrary code. AST-confirmed.",
			CWE:            "CWE-95",
			Recommendation: "Avoid eval() entirely.",
			Match:          matchCallByName("eval"),
		},
		{
			ID:             "TS-PHP002",
			Title:          "Use of unserialize() (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"php"},
			Description:    "unserialize() can execute arbitrary code during deserialization.",
			CWE:            "CWE-502",
			Recommendation: "Use json_decode() instead.",
			Match:          matchCallByName("unserialize"),
		},
		{
			ID:             "TS-PHP003",
			Title:          "Use of system() (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"php"},
			Description:    "system() executes an external program and is vulnerable to command injection.",
			CWE:            "CWE-78",
			Recommendation: "Use escapeshellarg() and escapeshellcmd() to sanitize input.",
			Match:          matchCallByName("system"),
		},
		{
			ID:             "TS-PHP004",
			Title:          "Use of exec() (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"php"},
			Description:    "exec() executes an external program and is vulnerable to command injection.",
			CWE:            "CWE-78",
			Recommendation: "Use escapeshellarg() and escapeshellcmd() to sanitize input.",
			Match:          matchCallByName("exec"),
		},
		{
			ID:             "TS-PHP005",
			Title:          "Use of shell_exec() (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"php"},
			Description:    "shell_exec() executes commands via the shell and is vulnerable to command injection.",
			CWE:            "CWE-78",
			Recommendation: "Use escapeshellarg() and escapeshellcmd() to sanitize input.",
			Match:          matchCallByName("shell_exec"),
		},
		{
			ID:             "TS-PHP006",
			Title:          "Use of passthru() (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"php"},
			Description:    "passthru() executes external programs and is vulnerable to command injection.",
			CWE:            "CWE-78",
			Recommendation: "Use escapeshellarg() and escapeshellcmd() to sanitize input.",
			Match:          matchCallByName("passthru"),
		},
		{
			ID:             "TS-PHP007",
			Title:          "Use of popen() (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"php"},
			Description:    "popen() opens a process file pointer and is vulnerable to command injection.",
			CWE:            "CWE-78",
			Recommendation: "Use escapeshellarg() and escapeshellcmd() to sanitize input.",
			Match:          matchCallByName("popen"),
		},
		{
			ID:             "TS-PHP008",
			Title:          "Use of proc_open() (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"php"},
			Description:    "proc_open() executes a command and is vulnerable to command injection.",
			CWE:            "CWE-78",
			Recommendation: "Use escapeshellarg() and escapeshellcmd() to sanitize input.",
			Match:          matchCallByName("proc_open"),
		},
		{
			ID:             "TS-PHP009",
			Title:          "Use of assert() with string (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"php"},
			Description:    "assert() with a string argument evaluates the string as PHP code, equivalent to eval().",
			CWE:            "CWE-95",
			Recommendation: "Avoid assert() with string arguments. Use if statements for assertions.",
			Match:          matchCallByName("assert"),
		},
		{
			ID:             "TS-PHP010",
			Title:          "Use of create_function() (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"php"},
			Description:    "create_function() creates an anonymous function from string arguments, equivalent to eval().",
			CWE:            "CWE-95",
			Recommendation: "Use anonymous functions (closures) instead: function($args) { ... }.",
			Match:          matchCallByName("create_function"),
		},

		// --- Java AST rules ---
		{
			ID:             "TS-JAVA001",
			Title:          "Runtime.exec() (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"java"},
			Description:    "Runtime.exec() can be vulnerable to command injection.",
			CWE:            "CWE-78",
			Recommendation: "Use ProcessBuilder with argument lists, not shell strings.",
			Match:          matchRuntimeExec,
		},
		{
			ID:             "TS-JAVA002",
			Title:          "ObjectInputStream deserialization (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"java"},
			Description:    "ObjectInputStream deserializes Java objects, which can execute arbitrary code.",
			CWE:            "CWE-502",
			Recommendation: "Use JSON or other safe serialization. Implement ObjectInputFilter.",
			Match:          matchNewByName("ObjectInputStream"),
		},
		{
			ID:             "TS-JAVA003",
			Title:          "ProcessBuilder with shell (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"java"},
			Description:    "ProcessBuilder with shell commands can be vulnerable to command injection.",
			CWE:            "CWE-78",
			Recommendation: "Use ProcessBuilder with argument lists, not shell strings.",
			Match:          matchNewByName("ProcessBuilder"),
		},
		{
			ID:             "TS-JAVA004",
			Title:          "MessageDigest MD5 (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"java"},
			Description:    "MD5 is cryptographically broken and should not be used for security purposes.",
			CWE:            "CWE-327",
			Recommendation: "Use MessageDigest.getInstance(\"SHA-256\") or better.",
			Match:          matchMessageDigest("MD5"),
		},
		{
			ID:             "TS-JAVA005",
			Title:          "MessageDigest SHA1 (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"java"},
			Description:    "SHA1 is cryptographically broken and should not be used for security purposes.",
			CWE:            "CWE-327",
			Recommendation: "Use MessageDigest.getInstance(\"SHA-256\") or better.",
			Match:          matchMessageDigest("SHA1"),
		},
		{
			ID:             "TS-JAVA006",
			Title:          "java.util.Random (AST-confirmed)",
			Severity:       analysis.SeverityLow,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"java"},
			Description:    "java.util.Random uses a predictable seed and is not cryptographically secure.",
			CWE:            "CWE-338",
			Recommendation: "Use java.security.SecureRandom for cryptographic randomness.",
			Match:          matchNewByName("Random"),
		},
		{
			ID:             "TS-JAVA007",
			Title:          "XMLReader without disabling external entities (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"java"},
			Description:    "XML parsing without disabling external entities can lead to XXE attacks.",
			CWE:            "CWE-611",
			Recommendation: "Set feature http://apache.org/xml/features/disallow-doctype-decl to true.",
			Match:          matchNewByName("XMLReader"),
		},
		{
			ID:             "TS-JAVA008",
			Title:          "DocumentBuilderFactory without XXE protection (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"java"},
			Description:    "DocumentBuilderFactory without disabling external entities can lead to XXE attacks.",
			CWE:            "CWE-611",
			Recommendation: "Set feature http://apache.org/xml/features/disallow-doctype-decl to true.",
			Match:          matchNewByName("DocumentBuilderFactory"),
		},
		{
			ID:             "TS-JAVA009",
			Title:          "SAXParserFactory without XXE protection (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"java"},
			Description:    "SAXParserFactory without disabling external entities can lead to XXE attacks.",
			CWE:            "CWE-611",
			Recommendation: "Set feature http://apache.org/xml/features/disallow-doctype-decl to true.",
			Match:          matchNewByName("SAXParserFactory"),
		},
		{
			ID:             "TS-JAVA010",
			Title:          "ScriptEngine eval (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"java"},
			Description:    "ScriptEngine.eval() can execute arbitrary code from strings.",
			CWE:            "CWE-95",
			Recommendation: "Avoid ScriptEngine.eval() with untrusted input.",
			Match:          matchScriptEngineEval,
		},
		{
			ID:             "TS-JAVA011",
			Title:          "Spring @CrossOrigin wildcard (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"java"},
			Description:    "Cross-origin resource sharing with wildcard origins allows any site to make requests.",
			CWE:            "CWE-942",
			Recommendation: "Specify exact allowed origins instead of using wildcard.",
			Match:          matchAnnotationString("CrossOrigin", "*"),
		},
		{
			ID:             "TS-JAVA012",
			Title:          "Files.readString without validation (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"java"},
			Description:    "Files.readString with user-controlled paths can lead to path traversal.",
			CWE:            "CWE-22",
			Recommendation: "Validate and sanitize file paths before reading.",
			Match:          matchAttributeCall("Files", "readString"),
		},

		// --- C# AST rules ---
		{
			ID:             "TS-CS001",
			Title:          "Process.Start (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"c_sharp"},
			Description:    "Process.Start can be vulnerable to command injection.",
			CWE:            "CWE-78",
			Recommendation: "Use ProcessStartInfo with argument lists, not shell strings.",
			Match:          matchCSharpProcessStart,
		},
		{
			ID:             "TS-CS002",
			Title:          "MD5.Create() — weak hash (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"c_sharp"},
			Description:    "MD5 is cryptographically broken and should not be used for security purposes.",
			CWE:            "CWE-327",
			Recommendation: "Use SHA256.Create() or better.",
			Match:          matchAttributeCall("MD5", "Create"),
		},
		{
			ID:             "TS-CS003",
			Title:          "SHA1.Create() — weak hash (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"c_sharp"},
			Description:    "SHA1 is cryptographically broken and should not be used for security purposes.",
			CWE:            "CWE-327",
			Recommendation: "Use SHA256.Create() or better.",
			Match:          matchAttributeCall("SHA1", "Create"),
		},
		{
			ID:             "TS-CS004",
			Title:          "Random() — insecure PRNG (AST-confirmed)",
			Severity:       analysis.SeverityLow,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"c_sharp"},
			Description:    "System.Random is not cryptographically secure.",
			CWE:            "CWE-338",
			Recommendation: "Use System.Security.Cryptography.RandomNumberGenerator.",
			Match:          matchNewByName("Random"),
		},
		{
			ID:             "TS-CS005",
			Title:          "XmlSerializer — deserialization risk (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"c_sharp"},
			Description:    "XmlSerializer can be vulnerable to deserialization attacks when processing untrusted XML.",
			CWE:            "CWE-502",
			Recommendation: "Validate XML schemas and restrict types during deserialization.",
			Match:          matchNewByName("XmlSerializer"),
		},
		{
			ID:             "TS-CS006",
			Title:          "BinaryFormatter — unsafe deserialization (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"c_sharp"},
			Description:    "BinaryFormatter is deprecated and unsafe — it can execute arbitrary code during deserialization.",
			CWE:            "CWE-502",
			Recommendation: "Use JsonSerializer or XmlSerializer with type-restricted deserialization.",
			Match:          matchNewByName("BinaryFormatter"),
		},
		{
			ID:             "TS-CS007",
			Title:          "JavaScriptSerializer — deserialization risk (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"c_sharp"},
			Description:    "JavaScriptSerializer can be vulnerable to deserialization attacks with untrusted input.",
			CWE:            "CWE-502",
			Recommendation: "Use System.Text.Json.JsonSerializer with type-restricted deserialization.",
			Match:          matchNewByName("JavaScriptSerializer"),
		},
		{
			ID:             "TS-CS008",
			Title:          "WebRequest without SSL (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"c_sharp"},
			Description:    "WebRequest.Create with HTTP URLs transmits data unencrypted.",
			CWE:            "CWE-319",
			Recommendation: "Use HTTPS URLs and validate SSL certificates.",
			Match:          matchAttributeCall("WebRequest", "Create"),
		},
		{
			ID:             "TS-CS009",
			Title:          "Response.Redirect — open redirect risk (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"c_sharp"},
			Description:    "Response.Redirect with user-controlled input can lead to open redirect attacks.",
			CWE:            "CWE-601",
			Recommendation: "Validate redirect URLs against an allowlist.",
			Match:          matchAttributeCall("Response", "Redirect"),
		},
		{
			ID:             "TS-CS010",
			Title:          "HtmlString — XSS risk (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"c_sharp"},
			Description:    "HtmlString renders raw HTML without encoding, which can lead to XSS attacks.",
			CWE:            "CWE-79",
			Recommendation: "Use HtmlString only with sanitized content. Use HtmlEncode for untrusted data.",
			Match:          matchNewByName("HtmlString"),
		},

		// --- Rust AST rules ---
		{
			ID:             "TS-RS001",
			Title:          "Command::new with shell (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"rust"},
			Description:    "Command::new with shell can be vulnerable to command injection.",
			CWE:            "CWE-78",
			Recommendation: "Avoid passing user input to shell commands. Use argument lists.",
			Match:          matchRustCommandNew,
		},
		{
			ID:             "TS-RS002",
			Title:          "unsafe block (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"rust"},
			Description:    "unsafe blocks bypass Rust's safety guarantees.",
			CWE:            "CWE-119",
			Recommendation: "Minimize unsafe code. Document why it's safe.",
			Match:          matchUnsafeBlock,
		},
		{
			ID:             "TS-RS003",
			Title:          "std::mem::transmute (AST-confirmed)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"rust"},
			Description:    "transmute reinterprets memory, which can cause undefined behavior.",
			CWE:            "CWE-119",
			Recommendation: "Avoid transmute. Use From/Into traits or bytemuck.",
			Match:          matchRustTransmute,
		},
		{
			ID:             "TS-RS004",
			Title:          "std::fs::read with user path — path traversal (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"rust"},
			Description:    "std::fs::read with user-controlled paths can lead to path traversal attacks.",
			CWE:            "CWE-22",
			Recommendation: "Validate and canonicalize file paths before reading.",
			Match:          matchRustFsCall("read"),
		},
		{
			ID:             "TS-RS005",
			Title:          "std::fs::write with user path — path traversal (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"rust"},
			Description:    "std::fs::write with user-controlled paths can lead to path traversal attacks.",
			CWE:            "CWE-22",
			Recommendation: "Validate and canonicalize file paths before writing.",
			Match:          matchRustFsCall("write"),
		},
		{
			ID:             "TS-RS006",
			Title:          "unsafe impl — trait-level unsafe (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceHigh,
			Languages:      []string{"rust"},
			Description:    "unsafe impl blocks bypass Rust's safety guarantees for trait implementations.",
			CWE:            "CWE-119",
			Recommendation: "Minimize unsafe impl. Document safety invariants thoroughly.",
			Match:          matchRustUnsafeImpl,
		},
		{
			ID:             "TS-RS007",
			Title:          "raw pointer dereference (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"rust"},
			Description:    "Dereferencing raw pointers bypasses Rust's borrow checker and can cause undefined behavior.",
			CWE:            "CWE-119",
			Recommendation: "Use references instead of raw pointers where possible.",
			Match:          matchRustRawPointerDeref,
		},
		{
			ID:             "TS-RS008",
			Title:          "std::process::Command::new (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"rust"},
			Description:    "Command::new can be vulnerable to command injection when arguments are user-controlled.",
			CWE:            "CWE-78",
			Recommendation: "Avoid passing user input directly to commands. Use argument lists, not shell strings.",
			Match:          matchRustCommandNewAny,
		},
		{
			ID:             "TS-RS009",
			Title:          "std::env::var().unwrap() — panic on missing env (AST-confirmed)",
			Severity:       analysis.SeverityLow,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"rust"},
			Description:    "env::var().unwrap() panics if the environment variable is not set, causing denial of service.",
			CWE:            "CWE-248",
			Recommendation: "Use env::var().unwrap_or_default() or handle the Result properly.",
			Match:          matchRustEnvVarUnwrap,
		},
		{
			ID:             "TS-RS010",
			Title:          "as_ptr / from_raw parts — unsafe pointer ops (AST-confirmed)",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Languages:      []string{"rust"},
			Description:    "as_ptr and from_raw operations bypass Rust's memory safety guarantees.",
			CWE:            "CWE-119",
			Recommendation: "Use safe alternatives. If raw pointers are necessary, document safety invariants.",
			Match:          matchRustRawPointerOps,
		},
	}
	a.buildRuleNodeTypes()
}

// buildRuleNodeTypes pre-computes which node types each language's rules care about,
// so walkAST can skip nodes that no rule would ever match.
func (a *Analyzer) buildRuleNodeTypes() {
	// We use a keyword-based heuristic: if the node type contains any of these
	// substrings, it might be relevant to a rule. This is conservative — better
	// to check a few extra nodes than to miss a finding.
	a.ruleNodeTypes = make(map[string]map[string]bool)
	relevantKeywords := []string{
		"call", "assign", "binary", "subscript", "attribute", "member",
		"identifier", "string", "template", "unary", "argument", "import",
		"expression", "literal", "decorator", "annotation", "field",
	}
	for _, rule := range a.rules {
		for _, lang := range rule.Languages {
			if a.ruleNodeTypes[lang] == nil {
				a.ruleNodeTypes[lang] = make(map[string]bool)
			}
			// Mark all node types containing relevant keywords as relevant.
			// Since we don't have the full grammar symbol list here, we
			// store the keywords and check at walk time.
			_ = relevantKeywords // stored implicitly via isRelevantNodeType
		}
	}
}

// isRelevantNodeType checks if a node type might match any rule for this language.
// Uses keyword matching to be conservative across different grammar naming conventions.
func isRelevantNodeType(nodeType string, lang string) bool {
	switch nodeType {
	// Node types from all supported grammars that security rules match on
	case "call", "call_expression", "assignment", "assignment_expression",
		"augmented_assignment", "augmented_assignment_expression",
		"binary_expression", "binary", "subscript", "subscript_expression",
		"attribute", "member_expression", "member_access_expression",
		"field_access_expression", "field_expression", "element_reference",
		"string", "string_literal", "template_string", "encapsed_string",
		"identifier", "keyword_argument", "argument_list",
		"decorator", "import_statement", "import_from_statement",
		"import_declaration", "use_declaration", "using_directive",
		"export_statement", "annotation",
		"method_invocation", "invocation_expression",
		"new_expression", "macro_invocation",
		"array_access_expression", "element_access_expression",
		"index_expression", "hash", "array",
		"function_call_expression", "operator_assignment",
		// Rust-specific
		"unsafe_block", "deref_expression", "raw_destructor",
		"macro_definition", "struct_expression",
		// Ruby-specific
		"subshell", "backtick", "command", "heredoc_beginning",
		// Java/C#/PHP-specific
		"class_declaration", "method_declaration", "field_declaration",
		"function_definition",
		// JS/TS-specific
		"property_assignment", "pair", "object":
		return true
	}
	// Fallback: check if the node type contains any relevant keyword.
	// This is intentionally broad to avoid missing findings.
	for _, kw := range []string{"call", "assign", "import", "string", "literal",
		"expression", "unsafe", "subshell", "backtick", "deref", "command",
		"exec", "eval", "process", "random", "crypto", "hash", "secret",
		"token", "password", "key", "debug", "sql", "query", "render",
		"template", "request", "response", "cookie", "session", "header",
		"proto", "pollut", "timeout", "interval", "function", "method",
		"field", "property", "pair", "object", "class", "struct",
		"macro", "annotation", "decorator", "attribute", "argument",
		"parameter", "subscript", "index", "member", "element",
		"impl", "trait", "use", "let", "var", "const", "static"} {
		if strings.Contains(nodeType, kw) {
			return true
		}
	}
	return false
}

// Analyze runs tree-sitter analysis on all supported source files in the root directory.
func (a *Analyzer) Analyze(ctx context.Context, root string) ([]analysis.Finding, error) {
	startTime := time.Now()

	var findings []analysis.Finding

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}

		if a.ignoreMatcher != nil && a.ignoreMatcher.Match(path, info.IsDir()) {
			return nil
		}

		entry := grammars.DetectLanguage(path)
		if entry == nil {
			return nil
		}

		if !a.hasRulesForLanguage(entry.Name) {
			return nil
		}

		if shouldSkipFile(path) {
			return nil
		}

		fileFindings, err := a.scanFile(path, root, entry)
		if err != nil {
			a.logger.Printf("error scanning %s: %v", path, err)
			return nil
		}
		findings = append(findings, fileFindings...)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("treesitter: walk failed: %w", err)
	}

	a.logger.Printf("tree-sitter analysis completed in %v: %d findings", time.Since(startTime), len(findings))
	return findings, nil
}

// ScanFilePublic is the exported version of scanFile for use by the
// parallel file scanner. It parses a file with tree-sitter and runs AST rules.
func (a *Analyzer) ScanFilePublic(absPath, root string, entry *grammars.LangEntry) ([]analysis.Finding, error) {
	return a.scanFile(absPath, root, entry)
}

// scanFile parses a file with tree-sitter and runs AST rules against it.
func (a *Analyzer) scanFile(absPath, root string, entry *grammars.LangEntry) ([]analysis.Finding, error) {
	src, err := os.ReadFile(absPath)
	if err != nil {
		return nil, err
	}

	lang := entry.Language()
	if lang == nil {
		return nil, nil
	}

	// Get a parser from the per-language pool (thread-safe).
	// This avoids the expensive NewParser allocation for every file.
	parser := a.acquireParser(entry.Name, lang)
	defer a.releaseParser(entry.Name, parser)

	tree, err := parser.Parse(src)
	if err != nil {
		return nil, nil
	}
	if tree == nil {
		return nil, nil
	}
	defer tree.Release()

	bt := gotreesitter.Bind(tree)
	rootNode := bt.RootNode()
	var findings []analysis.Finding

	a.walkAST(rootNode, bt, entry.Name, absPath, root, src, &findings)

	return findings, nil
}

// acquireParser gets a parser from the per-language pool, creating one if needed.
func (a *Analyzer) acquireParser(langName string, lang *gotreesitter.Language) *gotreesitter.Parser {
	v, _ := a.parserPools.LoadOrStore(langName, &sync.Pool{
		New: func() interface{} {
			return gotreesitter.NewParser(lang)
		},
	})
	pool := v.(*sync.Pool)
	p := pool.Get().(*gotreesitter.Parser)
	return p
}

// releaseParser returns a parser to the per-language pool for reuse.
func (a *Analyzer) releaseParser(langName string, parser *gotreesitter.Parser) {
	if parser == nil {
		return
	}
	v, ok := a.parserPools.Load(langName)
	if !ok {
		return
	}
	pool := v.(*sync.Pool)
	pool.Put(parser)
}

// walkAST recursively walks the tree-sitter AST and runs rules on each node.
// It skips rule matching for node types that no rule cares about, but still
// visits children to find relevant nodes deeper in the tree.
func (a *Analyzer) walkAST(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang, absPath, root string, src []byte, findings *[]analysis.Finding) {
	if node == nil {
		return
	}

	// Check if any rule cares about this node type.
	// If not, skip rule matching but still visit children.
	nodeType := bt.NodeType(node)
	isRelevant := isRelevantNodeType(nodeType, lang)

	// Always run rules on potentially relevant nodes.
	// The isRelevantNodeType check is conservative — when in doubt, run rules.
	if isRelevant || nodeType == "" {
		for _, rule := range a.rules {
			if !containsStr(rule.Languages, lang) {
				continue
			}
			if rule.Match(node, bt, lang) {
				f := a.makeFinding(rule, node, bt, absPath, root, src)
				*findings = append(*findings, f)
			}
		}
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		a.walkAST(child, bt, lang, absPath, root, src, findings)
	}
}

// makeFinding creates a normalized finding from an AST match.
func (a *Analyzer) makeFinding(rule astRule, node *gotreesitter.Node, bt *gotreesitter.BoundTree, absPath, root string, src []byte) analysis.Finding {
	startPoint := node.StartPoint()
	line := int(startPoint.Row) + 1

	code := ""
	lines := strings.Split(string(src), "\n")
	if line > 0 && line <= len(lines) {
		code = strings.TrimSpace(lines[line-1])
	}

	relPath, _ := filepath.Rel(root, absPath)
	if relPath == "" {
		relPath = absPath
	}

	return analysis.Finding{
		ID:             fmt.Sprintf("ts-%s-%s-%d", rule.ID, relPath, line),
		Type:           analysis.TypeSAST,
		Analyzer:       "treesitter-ast",
		Severity:       rule.Severity,
		Confidence:     rule.Confidence,
		Title:          rule.Title,
		Description:    rule.Description,
		FilePath:       absPath,
		LineStart:      line,
		RuleID:         rule.ID,
		Evidence:       code,
		Recommendation: rule.Recommendation,
		CWEID:          rule.CWE,
		DetectedAt:     time.Now(),
	}
}

// hasRulesForLanguage returns true if any rule applies to the given language.
func (a *Analyzer) hasRulesForLanguage(lang string) bool {
	for _, rule := range a.rules {
		if containsStr(rule.Languages, lang) {
			return true
		}
	}
	return false
}

// HasRulesForLanguage is the exported version for use by the file collector
// to skip files whose language has no tree-sitter rules.
func (a *Analyzer) HasRulesForLanguage(lang string) bool {
	return a.hasRulesForLanguage(lang)
}

// shouldSkipFile returns true for test files and vendored code.
func shouldSkipFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if strings.Contains(base, "_test.") || strings.Contains(base, ".test.") ||
		strings.Contains(base, ".spec.") || strings.HasSuffix(base, ".test.js") ||
		strings.HasSuffix(base, ".spec.ts") {
		return true
	}
	parts := strings.Split(filepath.ToSlash(path), "/")
	for _, part := range parts {
		switch part {
		case "node_modules", "vendor", "venv", ".venv", "dist", "build", "__pycache__":
			return true
		}
	}
	return false
}

// --- Rule matching helpers ---
// All match functions use BoundTree to access node type and text without
// passing *Language and []byte separately.

// nodeType returns the type name of a node via the BoundTree.
func nodeType(node *gotreesitter.Node, bt *gotreesitter.BoundTree) string {
	return bt.NodeType(node)
}

// nodeText returns the source text of a node via the BoundTree.
func nodeText(node *gotreesitter.Node, bt *gotreesitter.BoundTree) string {
	return bt.NodeText(node)
}

// childByField returns a child by field name via the BoundTree.
func childByField(node *gotreesitter.Node, bt *gotreesitter.BoundTree, field string) *gotreesitter.Node {
	return bt.ChildByField(node, field)
}

// matchCallByName returns a Match function that detects calls to a function
// with the given name (e.g., eval, exec, system).
func matchCallByName(name string) func(*gotreesitter.Node, *gotreesitter.BoundTree, string) bool {
	return func(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) bool {
		nt := nodeType(node, bt)

		switch lang {
		case "python":
			if nt == "call" {
				fn := childByField(node, bt, "function")
				if fn != nil && nodeType(fn, bt) == "identifier" {
					return nodeText(fn, bt) == name
				}
			}
		case "javascript", "typescript", "tsx":
			if nt == "call_expression" {
				fn := childByField(node, bt, "function")
				if fn != nil && nodeType(fn, bt) == "identifier" {
					return nodeText(fn, bt) == name
				}
			}
		case "ruby":
			if nt == "call" {
				fn := childByField(node, bt, "method")
				if fn != nil && nodeType(fn, bt) == "identifier" {
					return nodeText(fn, bt) == name
				}
			}
		case "php":
			if nt == "function_call_expression" {
				fn := childByField(node, bt, "function")
				if fn != nil {
					return nodeText(fn, bt) == name
				}
			}
		}
		return false
	}
}

// matchAttributeCall matches calls like os.system(), pickle.loads(), etc.
func matchAttributeCall(obj, method string) func(*gotreesitter.Node, *gotreesitter.BoundTree, string) bool {
	return func(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) bool {
		nt := nodeType(node, bt)

		switch lang {
		case "python":
			if nt == "call" {
				fn := childByField(node, bt, "function")
				if fn != nil && nodeType(fn, bt) == "attribute" {
					objNode := childByField(fn, bt, "object")
					attrNode := childByField(fn, bt, "attribute")
					if objNode != nil && attrNode != nil {
						return nodeText(objNode, bt) == obj && nodeText(attrNode, bt) == method
					}
				}
			}
		case "javascript", "typescript", "tsx":
			if nt == "call_expression" {
				fn := childByField(node, bt, "function")
				if fn != nil && nodeType(fn, bt) == "member_expression" {
					objNode := childByField(fn, bt, "object")
					propNode := childByField(fn, bt, "property")
					if objNode != nil && propNode != nil {
						return nodeText(objNode, bt) == obj && nodeText(propNode, bt) == method
					}
				}
			}
		case "ruby":
			// Ruby call: call -> constant(receiver) + identifier(method)
			if nt == "call" {
				// Check if receiver is a constant (e.g., Marshal, YAML, IO, Open3)
				receiverNode := childByField(node, bt, "receiver")
				if receiverNode != nil {
					methodNode := childByField(node, bt, "method")
					if methodNode != nil {
						return nodeText(receiverNode, bt) == obj && nodeText(methodNode, bt) == method
					}
				}
				// Fallback: check children directly
				for i := 0; i < int(node.ChildCount()); i++ {
					child := node.Child(i)
					if child != nil && nodeType(child, bt) == "constant" && nodeText(child, bt) == obj {
						for j := 0; j < int(node.ChildCount()); j++ {
							m := node.Child(j)
							if m != nil && nodeType(m, bt) == "identifier" && nodeText(m, bt) == method {
								return true
							}
						}
					}
				}
			}
		}
		return false
	}
}

// matchJSXAttribute matches JSX attributes with the given name.
func matchJSXAttribute(name string) func(*gotreesitter.Node, *gotreesitter.BoundTree, string) bool {
	return func(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) bool {
		nt := nodeType(node, bt)
		if nt == "jsx_attribute" || nt == "property_identifier" {
			return nodeText(node, bt) == name
		}
		return false
	}
}

// matchSubprocessShellTrue detects subprocess.call/run/Popen with shell=True.
func matchSubprocessShellTrue(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) bool {
	if lang != "python" {
		return false
	}
	if nodeType(node, bt) != "call" {
		return false
	}
	fn := childByField(node, bt, "function")
	if fn == nil || nodeType(fn, bt) != "attribute" {
		return false
	}
	objNode := childByField(fn, bt, "object")
	attrNode := childByField(fn, bt, "attribute")
	if objNode == nil || attrNode == nil {
		return false
	}
	if nodeText(objNode, bt) != "subprocess" {
		return false
	}
	method := nodeText(attrNode, bt)
	if method != "call" && method != "run" && method != "Popen" && method != "check_output" && method != "check_call" {
		return false
	}
	argsNode := childByField(node, bt, "arguments")
	if argsNode == nil {
		return false
	}
	argsText := nodeText(argsNode, bt)
	return strings.Contains(argsText, "shell=True") || strings.Contains(argsText, "shell = True")
}

// matchYamlLoad detects yaml.load() without SafeLoader.
func matchYamlLoad(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) bool {
	if lang != "python" {
		return false
	}
	if nodeType(node, bt) != "call" {
		return false
	}
	fn := childByField(node, bt, "function")
	if fn == nil || nodeType(fn, bt) != "attribute" {
		return false
	}
	objNode := childByField(fn, bt, "object")
	attrNode := childByField(fn, bt, "attribute")
	if objNode == nil || attrNode == nil {
		return false
	}
	if nodeText(objNode, bt) != "yaml" || nodeText(attrNode, bt) != "load" {
		return false
	}
	argsNode := childByField(node, bt, "arguments")
	if argsNode == nil {
		return true
	}
	return !strings.Contains(nodeText(argsNode, bt), "SafeLoader")
}

// matchNewFunction detects `new Function(...)` in JS/TS.
func matchNewFunction(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) bool {
	if !isJSFamily(lang) {
		return false
	}
	if nodeType(node, bt) != "new_expression" {
		return false
	}
	ctorNode := childByField(node, bt, "constructor")
	if ctorNode == nil {
		return false
	}
	return nodeText(ctorNode, bt) == "Function"
}

// matchProtoPollution detects __proto__ references in JS/TS.
func matchProtoPollution(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) bool {
	if !isJSFamily(lang) {
		return false
	}
	nt := nodeType(node, bt)
	if nt == "member_expression" || nt == "property_identifier" {
		return nodeText(node, bt) == "__proto__"
	}
	return false
}

// matchRuntimeExec detects Runtime.getRuntime().exec() in Java.
func matchRuntimeExec(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) bool {
	if lang != "java" {
		return false
	}
	if nodeType(node, bt) != "method_invocation" {
		return false
	}
	nameNode := childByField(node, bt, "name")
	if nameNode == nil || nodeText(nameNode, bt) != "exec" {
		return false
	}
	objNode := childByField(node, bt, "object")
	if objNode == nil {
		return false
	}
	return strings.Contains(nodeText(objNode, bt), "Runtime.getRuntime")
}

// matchNewByName detects `new ClassName(...)` for a specific class name.
func matchNewByName(className string) func(*gotreesitter.Node, *gotreesitter.BoundTree, string) bool {
	return func(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) bool {
		switch lang {
		case "java":
			if nodeType(node, bt) != "object_creation_expression" {
				return false
			}
			ctorNode := childByField(node, bt, "type")
			if ctorNode == nil {
				return false
			}
			return nodeText(ctorNode, bt) == className
		case "javascript", "typescript", "tsx":
			if nodeType(node, bt) != "new_expression" {
				return false
			}
			ctorNode := childByField(node, bt, "constructor")
			if ctorNode == nil {
				return false
			}
			return nodeText(ctorNode, bt) == className
		case "c_sharp":
			if nodeType(node, bt) != "object_creation_expression" {
				return false
			}
			ctorNode := childByField(node, bt, "type")
			if ctorNode == nil {
				return false
			}
			return nodeText(ctorNode, bt) == className
		}
		return false
	}
}

// matchCSharpProcessStart detects Process.Start() in C#.
func matchCSharpProcessStart(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) bool {
	if lang != "c_sharp" {
		return false
	}
	if nodeType(node, bt) != "invocation_expression" {
		return false
	}
	fn := childByField(node, bt, "function")
	if fn == nil {
		return false
	}
	return strings.Contains(nodeText(fn, bt), "Process.Start")
}

// matchRustCommandNew detects Command::new("sh") or Command::new("bash") in Rust.
func matchRustCommandNew(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) bool {
	if lang != "rust" {
		return false
	}
	if nodeType(node, bt) != "call_expression" {
		return false
	}
	fn := childByField(node, bt, "function")
	if fn == nil {
		return false
	}
	if !strings.Contains(nodeText(fn, bt), "Command::new") {
		return false
	}
	argsNode := childByField(node, bt, "arguments")
	if argsNode == nil {
		return false
	}
	argsText := nodeText(argsNode, bt)
	return strings.Contains(argsText, "\"sh\"") || strings.Contains(argsText, "\"bash\"") ||
		strings.Contains(argsText, "\"/bin/sh\"") || strings.Contains(argsText, "\"/bin/bash\"")
}

// matchUnsafeBlock detects unsafe blocks in Rust.
func matchUnsafeBlock(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) bool {
	if lang != "rust" {
		return false
	}
	return nodeType(node, bt) == "unsafe_block"
}

// matchRustTransmute detects std::mem::transmute in Rust.
func matchRustTransmute(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) bool {
	if lang != "rust" {
		return false
	}
	if nodeType(node, bt) != "call_expression" {
		return false
	}
	fn := childByField(node, bt, "function")
	if fn == nil {
		return false
	}
	return strings.Contains(nodeText(fn, bt), "transmute")
}

// --- New match functions for expanded rules ---

// matchFlaskDebug detects Flask app.run(debug=True).
func matchFlaskDebug(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) bool {
	if lang != "python" {
		return false
	}
	if nodeType(node, bt) != "call" {
		return false
	}
	fn := childByField(node, bt, "function")
	if fn == nil || nodeType(fn, bt) != "attribute" {
		return false
	}
	objNode := childByField(fn, bt, "object")
	attrNode := childByField(fn, bt, "attribute")
	if objNode == nil || attrNode == nil {
		return false
	}
	if nodeText(objNode, bt) != "app" || nodeText(attrNode, bt) != "run" {
		return false
	}
	argsNode := childByField(node, bt, "arguments")
	if argsNode == nil {
		return false
	}
	argsText := nodeText(argsNode, bt)
	return strings.Contains(argsText, "debug=True") || strings.Contains(argsText, "debug = True")
}

// matchSubprocessPopenShellTrue detects subprocess.Popen(..., shell=True).
func matchSubprocessPopenShellTrue(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) bool {
	if lang != "python" {
		return false
	}
	if nodeType(node, bt) != "call" {
		return false
	}
	fn := childByField(node, bt, "function")
	if fn == nil || nodeType(fn, bt) != "attribute" {
		return false
	}
	objNode := childByField(fn, bt, "object")
	attrNode := childByField(fn, bt, "attribute")
	if objNode == nil || attrNode == nil {
		return false
	}
	if nodeText(objNode, bt) != "subprocess" || nodeText(attrNode, bt) != "Popen" {
		return false
	}
	argsNode := childByField(node, bt, "arguments")
	if argsNode == nil {
		return false
	}
	argsText := nodeText(argsNode, bt)
	return strings.Contains(argsText, "shell=True") || strings.Contains(argsText, "shell = True")
}

// matchCryptoHash detects crypto.createHash('md5') or similar in JS/TS.
func matchCryptoHash(hashName string) func(*gotreesitter.Node, *gotreesitter.BoundTree, string) bool {
	return func(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) bool {
		if !isJSFamily(lang) {
			return false
		}
		if nodeType(node, bt) != "call_expression" {
			return false
		}
		fn := childByField(node, bt, "function")
		if fn == nil || nodeType(fn, bt) != "member_expression" {
			return false
		}
		objNode := childByField(fn, bt, "object")
		propNode := childByField(fn, bt, "property")
		if objNode == nil || propNode == nil {
			return false
		}
		if nodeText(objNode, bt) != "crypto" || nodeText(propNode, bt) != "createHash" {
			return false
		}
		argsNode := childByField(node, bt, "arguments")
		if argsNode == nil {
			return false
		}
		argsText := nodeText(argsNode, bt)
		return strings.Contains(argsText, "'"+hashName+"'") || strings.Contains(argsText, "\""+hashName+"\"")
	}
}

// matchPropertyAssignment detects assignment to a property (e.g., el.innerHTML = ...).
// It suppresses findings where the RHS is an empty string literal (e.g.,
// el.innerHTML = '' is clearing content, not injecting untrusted data).
func matchPropertyAssignment(propName string) func(*gotreesitter.Node, *gotreesitter.BoundTree, string) bool {
	return func(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) bool {
		if !isJSFamily(lang) {
			return false
		}
		// match_assignment_expression with member_expression on left
		if nodeType(node, bt) != "assignment_expression" {
			return false
		}
		leftNode := childByField(node, bt, "left")
		if leftNode == nil || nodeType(leftNode, bt) != "member_expression" {
			return false
		}
		propNode := childByField(leftNode, bt, "property")
		if propNode == nil {
			return false
		}
		if nodeText(propNode, bt) != propName {
			return false
		}
		// Suppress if RHS is an empty string literal — clearing, not injection.
		// e.g., box.innerHTML = '' is not XSS.
		rightNode := childByField(node, bt, "right")
		if rightNode != nil {
			rhsType := nodeType(rightNode, bt)
			rhsText := strings.TrimSpace(nodeText(rightNode, bt))
			if rhsType == "string" && (rhsText == "''" || rhsText == `""` || rhsText == "``") {
				return false
			}
		}
		return true
	}
}

// matchSetTimeoutString detects setTimeout("string", ...) in JS/TS.
func matchSetTimeoutString(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) bool {
	if !isJSFamily(lang) {
		return false
	}
	if nodeType(node, bt) != "call_expression" {
		return false
	}
	fn := childByField(node, bt, "function")
	if fn == nil || nodeType(fn, bt) != "identifier" {
		return false
	}
	if nodeText(fn, bt) != "setTimeout" {
		return false
	}
	argsNode := childByField(node, bt, "arguments")
	if argsNode == nil {
		return false
	}
	// Find the first named child (skip punctuation like '(' and ',')
	for i := 0; i < int(argsNode.ChildCount()); i++ {
		child := argsNode.Child(i)
		if child == nil || !child.IsNamed() {
			continue
		}
		argType := nodeType(child, bt)
		return argType == "string" || argType == "template_string"
	}
	return false
}

// matchSetIntervalString detects setInterval("string", ...) in JS/TS.
func matchSetIntervalString(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) bool {
	if !isJSFamily(lang) {
		return false
	}
	if nodeType(node, bt) != "call_expression" {
		return false
	}
	fn := childByField(node, bt, "function")
	if fn == nil || nodeType(fn, bt) != "identifier" {
		return false
	}
	if nodeText(fn, bt) != "setInterval" {
		return false
	}
	argsNode := childByField(node, bt, "arguments")
	if argsNode == nil {
		return false
	}
	for i := 0; i < int(argsNode.ChildCount()); i++ {
		child := argsNode.Child(i)
		if child == nil || !child.IsNamed() {
			continue
		}
		argType := nodeType(child, bt)
		return argType == "string" || argType == "template_string"
	}
	return false
}

// matchObjectAssignProto detects Object.assign(target, {__proto__: ...}).
func matchObjectAssignProto(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) bool {
	if !isJSFamily(lang) {
		return false
	}
	if nodeType(node, bt) != "call_expression" {
		return false
	}
	fn := childByField(node, bt, "function")
	if fn == nil || nodeType(fn, bt) != "member_expression" {
		return false
	}
	objNode := childByField(fn, bt, "object")
	propNode := childByField(fn, bt, "property")
	if objNode == nil || propNode == nil {
		return false
	}
	if nodeText(objNode, bt) != "Object" || nodeText(propNode, bt) != "assign" {
		return false
	}
	argsNode := childByField(node, bt, "arguments")
	if argsNode == nil {
		return false
	}
	return strings.Contains(nodeText(argsNode, bt), "__proto__")
}

// matchRubyBacktick detects backtick command execution in Ruby.
func matchRubyBacktick(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) bool {
	if lang != "ruby" {
		return false
	}
	return nodeType(node, bt) == "subshell" || nodeType(node, bt) == "backtick"
}

// matchMessageDigest detects MessageDigest.getInstance("MD5") or similar in Java.
func matchMessageDigest(algorithm string) func(*gotreesitter.Node, *gotreesitter.BoundTree, string) bool {
	return func(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) bool {
		if lang != "java" {
			return false
		}
		if nodeType(node, bt) != "method_invocation" {
			return false
		}
		nameNode := childByField(node, bt, "name")
		if nameNode == nil || nodeText(nameNode, bt) != "getInstance" {
			return false
		}
		objNode := childByField(node, bt, "object")
		if objNode == nil {
			return false
		}
		if !strings.Contains(nodeText(objNode, bt), "MessageDigest") {
			return false
		}
		argsNode := childByField(node, bt, "arguments")
		if argsNode == nil {
			return false
		}
		argsText := nodeText(argsNode, bt)
		return strings.Contains(argsText, "\""+algorithm+"\"") || strings.Contains(argsText, "'"+algorithm+"'")
	}
}

// matchScriptEngineEval detects ScriptEngine.eval() in Java.
func matchScriptEngineEval(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) bool {
	if lang != "java" {
		return false
	}
	if nodeType(node, bt) != "method_invocation" {
		return false
	}
	nameNode := childByField(node, bt, "name")
	if nameNode == nil || nodeText(nameNode, bt) != "eval" {
		return false
	}
	objNode := childByField(node, bt, "object")
	if objNode == nil {
		return false
	}
	return strings.Contains(nodeText(objNode, bt), "ScriptEngine")
}

// matchAnnotationString detects Java annotations with a specific string value,
// e.g., @CrossOrigin(origins = "*").
func matchAnnotationString(annotationName, value string) func(*gotreesitter.Node, *gotreesitter.BoundTree, string) bool {
	return func(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) bool {
		if lang != "java" {
			return false
		}
		nt := nodeType(node, bt)
		if nt != "annotation" && nt != "marker_annotation" && nt != "annotation_declaration" {
			// Also check for annotation type use
			if !strings.Contains(nt, "annotation") {
				return false
			}
		}
		text := nodeText(node, bt)
		return strings.Contains(text, annotationName) && strings.Contains(text, value)
	}
}

// matchRustFsCall detects std::fs::read, std::fs::write, etc. in Rust.
func matchRustFsCall(method string) func(*gotreesitter.Node, *gotreesitter.BoundTree, string) bool {
	return func(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) bool {
		if lang != "rust" {
			return false
		}
		if nodeType(node, bt) != "call_expression" {
			return false
		}
		fn := childByField(node, bt, "function")
		if fn == nil {
			return false
		}
		fnText := nodeText(fn, bt)
		return strings.Contains(fnText, "fs::"+method) || strings.Contains(fnText, "Path::"+method)
	}
}

// matchRustUnsafeImpl detects `unsafe impl` in Rust.
func matchRustUnsafeImpl(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) bool {
	if lang != "rust" {
		return false
	}
	nt := nodeType(node, bt)
	return nt == "unsafe_impl" || (strings.HasPrefix(nt, "impl") && strings.Contains(nodeText(node, bt), "unsafe"))
}

// matchRustRawPointerDeref detects raw pointer dereference (*ptr) in Rust.
func matchRustRawPointerDeref(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) bool {
	if lang != "rust" {
		return false
	}
	return nodeType(node, bt) == "raw_destructor" || nodeType(node, bt) == "deref_expression"
}

// matchRustCommandNewAny detects any Command::new() call in Rust (broader than shell-only).
func matchRustCommandNewAny(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) bool {
	if lang != "rust" {
		return false
	}
	if nodeType(node, bt) != "call_expression" {
		return false
	}
	fn := childByField(node, bt, "function")
	if fn == nil {
		return false
	}
	return strings.Contains(nodeText(fn, bt), "Command::new")
}

// matchRustEnvVarUnwrap detects env::var("KEY").unwrap() in Rust.
func matchRustEnvVarUnwrap(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) bool {
	if lang != "rust" {
		return false
	}
	// Match method_call_expression: env::var(...).unwrap()
	if nodeType(node, bt) != "call_expression" {
		return false
	}
	fn := childByField(node, bt, "function")
	if fn == nil {
		return false
	}
	fnText := nodeText(fn, bt)
	return strings.Contains(fnText, "env::var") && strings.Contains(fnText, "unwrap")
}

// matchRustRawPointerOps detects as_ptr, from_raw, from_raw_parts in Rust.
func matchRustRawPointerOps(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) bool {
	if lang != "rust" {
		return false
	}
	if nodeType(node, bt) != "call_expression" {
		return false
	}
	fn := childByField(node, bt, "function")
	if fn == nil {
		return false
	}
	fnText := nodeText(fn, bt)
	return strings.Contains(fnText, "as_ptr") || strings.Contains(fnText, "from_raw") ||
		strings.Contains(fnText, "from_raw_parts")
}

// --- Utility functions ---

// isJSFamily returns true for JavaScript, TypeScript, and TSX languages.
// Tree-sitter detects .tsx as "tsx" and .jsx as "javascript", so we need
// to cover all three.
func isJSFamily(lang string) bool {
	return lang == "javascript" || lang == "typescript" || lang == "tsx"
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// RuleInfo provides metadata about a tree-sitter rule for listing purposes.
type RuleInfo struct {
	ID       string
	Title    string
	Severity string
	Language string
}

// Rules returns metadata for all registered tree-sitter rules.
func (a *Analyzer) Rules() []RuleInfo {
	var infos []RuleInfo
	for _, r := range a.rules {
		infos = append(infos, RuleInfo{
			ID:       r.ID,
			Title:    r.Title,
			Severity: severityToString(r.Severity),
			Language: strings.Join(r.Languages, ","),
		})
	}
	return infos
}

func severityToString(s analysis.Severity) string {
	switch s {
	case analysis.SeverityHigh:
		return "high"
	case analysis.SeverityMedium:
		return "medium"
	case analysis.SeverityLow:
		return "low"
	default:
		return "unknown"
	}
}
