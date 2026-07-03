// Package patterns provides a multi-language regex-based SAST scanner that
// detects common security vulnerabilities in Python, JavaScript/TypeScript,
// Ruby, and PHP source files without requiring any external tools.
//
// The scanner uses curated regex patterns covering the OWASP Top 10:
// - Injection (SQL, command, eval, SSRF)
// - Broken Access Control (debug mode, CORS)
// - Cryptographic Failures (weak hashes, weak random, hardcoded secrets)
// - Security Misconfiguration (TLS verification, debug flags)
// - Sensitive Data Exposure (logging secrets, error disclosure)
//
// This is Phase 1 (regex-based). Phase 2 will add tree-sitter for AST-based
// analysis with lower false-positive rates.
package patterns

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
)

// Language represents a programming language supported by the pattern scanner.
type Language string

const (
	LangPython     Language = "python"
	LangJavaScript Language = "javascript"
	LangTypeScript Language = "typescript"
	LangRuby       Language = "ruby"
	LangPHP        Language = "php"
	LangJava       Language = "java"
	LangCSharp     Language = "csharp"
	LangRust       Language = "rust"
	LangGo         Language = "go"
	LangGeneric    Language = "generic"
	LangDockerfile Language = "dockerfile"
	LangYAML       Language = "yaml"
	LangTerraform  Language = "terraform"
	LangHTML       Language = "html"
)

// PatternRule defines a security pattern to detect.
type PatternRule struct {
	ID          string
	Title       string
	Description string
	Severity    analysis.Severity
	Confidence  analysis.Confidence
	Languages   []Language
	Pattern     *regexp.Regexp
	CWEID       string // associated CWE ID (e.g., "CWE-89" for SQL injection)
	// SkipQuoteFilter disables the quoted-string filter for this rule. Set to
	// true for injection rules that specifically detect patterns inside string
	// literals (e.g., SQL injection via "$var" interpolation in PHP).
	SkipQuoteFilter bool
	// SkipCommentFilter skips matches inside comments. When true, lines that
	// are entirely comments (//, #, /*, *) are not scanned for this rule.
	SkipCommentFilter bool
	// RequiresAssignment, when true, only fires if the pattern match is on the
	// right-hand side of an assignment (e.g., hardcoded secret = "value").
	// This prevents false positives in comparisons or string references.
	RequiresAssignment bool
	// SuppressFunc, if non-nil, is called after a pattern match. If it returns
	// true, the finding is suppressed (not reported). This allows post-match
	// validation that requires inspecting the full line content beyond what
	// the regex alone can express.
	SuppressFunc func(line string) bool
}

var terraformS3PostureRules = map[string]bool{
	"TF001": true,
	"TF006": true,
	"TF011": true,
}

// IgnoreMatcher is the interface implemented by the gitignore matcher.
// If set on a Scanner, files matching .gitignore patterns are skipped.
type IgnoreMatcher interface {
	Match(path string, isDir bool) bool
	IsEmpty() bool
}

// Scanner is the multi-language pattern-based SAST scanner.
type Scanner struct {
	rules             []PatternRule
	ignoredDirs       map[string]bool
	ignoredExtensions map[string]bool
	maxFileSize       int64
	ignoreMatcher     IgnoreMatcher
}

// NewScanner creates a new pattern scanner with all built-in rules.
func NewScanner() *Scanner {
	s := &Scanner{
		maxFileSize: 2 * 1024 * 1024, // 2MB
		ignoredDirs: map[string]bool{
			"node_modules": true, "vendor": true, ".git": true, "dist": true,
			"build": true, "target": true, ".next": true, ".cache": true,
			"__pycache__": true, ".venv": true, "venv": true, "env": true,
			".env": true, ".tox": true, ".pytest_cache": true, ".mypy_cache": true,
			"site-packages": true, ".eggs": true, ".eggs-info": true,
			".ruff_cache": true,
			// Third-party library directories
			"lib": true, "libs": true, "wwwroot": true, "third_party": true,
			"thirdparty": true, "external": true, "deps": true,
			"bower_components": true, "jspm_packages": true, "webjars": true,
			"packages": true, "Content": true, "Scripts": true,
		},
		ignoredExtensions: map[string]bool{
			".min.js": true, ".min.css": true, ".map": true,
			".lock": true, ".sum": true,
		},
	}
	s.registerRules()
	return s
}

// AddRules adds custom rules to the scanner. Custom rules are appended after
// the built-in rules and take precedence for suppression purposes (custom IDs
// should use a distinctive prefix like CUSTOM- or ORG-).
func (s *Scanner) AddRules(rules []PatternRule) {
	s.rules = append(s.rules, rules...)
}

// SetIgnoreMatcher sets the .gitignore matcher for this scanner. When set,
// files matching .gitignore patterns are skipped during scanning.
func (s *Scanner) SetIgnoreMatcher(m IgnoreMatcher) {
	s.ignoreMatcher = m
}

// Rules returns a copy of all registered rules (built-in + custom).
// Used by the `patchflow rules list` command.
func (s *Scanner) Rules() []PatternRule {
	result := make([]PatternRule, len(s.rules))
	copy(result, s.rules)
	return result
}

// registerRules registers all built-in security pattern rules.
func (s *Scanner) registerRules() {
	s.rules = []PatternRule{
		// --- Python rules (replaces key bandit rules) ---

		// Code injection — pattern-based (regex) findings are Medium confidence;
		// taint-confirmed findings (TP-PY*) remain High.
		{ID: "PY001", Title: "Use of eval() with potential user input", Description: "eval() can execute arbitrary code. Avoid using it, especially with user input.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`\beval\s*\(`)},
		{ID: "PY002", Title: "Use of exec() with potential user input", Description: "exec() can execute arbitrary code. Avoid using it, especially with user input.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`\bexec\s*\(`)},
		{ID: "PY003", Title: "Use of os.system()", Description: "os.system() is vulnerable to command injection. Use subprocess with shell=False instead.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`\bos\.system\s*\(`)},
		{ID: "PY004", Title: "subprocess with shell=True", Description: "subprocess with shell=True is vulnerable to command injection. Use shell=False and pass args as a list.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)shell\s*=\s*True`)},
		{ID: "PY005", Title: "Use of pickle.loads()", Description: "pickle.loads() can execute arbitrary code during deserialization. Avoid unpickling untrusted data.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`\bpickle\.loads?\s*\(`)},
		{ID: "PY006", Title: "Use of yaml.load() without SafeLoader", Description: "yaml.load() without SafeLoader can execute arbitrary code. Use yaml.safe_load() instead.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`\byaml\.load\s*\(`), SuppressFunc: suppressPY006},

		// SQL injection
		{ID: "PY007", Title: "SQL query with string formatting", Description: "SQL query constructed with string formatting is vulnerable to SQL injection. Use parameterized queries.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)(execute|cursor\.execute)\s*\(\s*(f["']\s*(SELECT|INSERT|UPDATE|DELETE)|["'].*%s.*["']\s*%(.*SELECT|INSERT|UPDATE|DELETE))`), CWEID: "CWE-89", SkipQuoteFilter: true},
		{ID: "PY008", Title: "Raw SQL string concatenation", Description: "SQL query built with string concatenation is vulnerable to SQL injection.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)(query|sql|stmt)\s*[\+]=?\s*.*["'].*\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b`)},

		// Crypto
		{ID: "PY009", Title: "Use of MD5 hash", Description: "MD5 is a weak hash algorithm. Use SHA-256 or stronger.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`\bhashlib\.md5\s*\(`)},
		{ID: "PY010", Title: "Use of SHA1 hash", Description: "SHA1 is a weak hash algorithm. Use SHA-256 or stronger.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`\bhashlib\.sha1\s*\(`)},
		{ID: "PY011", Title: "Use of random module for security", Description: "random module is not cryptographically secure. Use secrets module instead.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)\brandom\.(choice|randint|random|uniform)\s*\(`)},
		{ID: "PY012", Title: "Hardcoded password", Description: "Hardcoded password detected. Use environment variables or a secret manager.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)\b(password|passwd|pwd)\b\s*=\s*["'][^"']{4,}["']`), SuppressFunc: suppressPY045},

		// Network/TLS
		{ID: "PY013", Title: "SSL verification disabled", Description: "SSL certificate verification is disabled. This makes the connection vulnerable to MITM attacks.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)(verify|ssl_verify|insecure)\s*=\s*False\b`), SuppressFunc: suppressPY013},
		{ID: "PY014", Title: "Requests with verify=False", Description: "Disabling SSL verification in requests is dangerous.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)requests\.(get|post|put|delete|patch|head)\s*\(.*verify\s*=\s*False`)},

		// Debug/dev mode
		{ID: "PY015", Title: "Debug mode enabled", Description: "Debug mode should never be enabled in production.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)debug\s*=\s*True`)},

		// Flask/Django specific
		{ID: "PY016", Title: "Flask app with debug=True", Description: "Running Flask with debug=True exposes the Werkzeug debugger, which can lead to RCE.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)app\.run\s*\(.*debug\s*=\s*True`)},
		{ID: "PY017", Title: "Django ALLOWED_HOSTS wildcard", Description: "ALLOWED_HOSTS = ['*'] allows requests from any host.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)ALLOWED_HOSTS\s*=\s*\[.*['"]\*['"]`)},

		// Additional Python rules (PY018-PY025)
		{ID: "PY018", Title: "Flask SSRF via requests with user-controlled URL", Description: "requests call with a user-controlled URL/host/target/endpoint may be vulnerable to SSRF. Validate and restrict the destination.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)requests\.(get|post|put|delete|patch)\s*\(\s*.*\b(url|host|target|endpoint)\b`)},
		{ID: "PY019", Title: "Path traversal via open() with user input", Description: "open() with a path derived from user input or request data may be vulnerable to path traversal. Validate and sanitize paths.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)\bopen\s*\(\s*.*\b(os\.path\.join|os\.getcwd|request\.|input)\b`), SuppressFunc: suppressPY019},
		{ID: "PY020", Title: "Django SQL injection via raw()", Description: "Model.objects.raw() with string formatting (%s) is vulnerable to SQL injection. Use parameterized raw queries.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)\.raw\s*\(\s*.*%s.*%\s*\(`)},
		{ID: "PY021", Title: "Django SQL injection via extra()", Description: "QuerySet.extra(select=...) can introduce SQL injection. Use annotated queries or parameterized raw queries instead.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)\.extra\s*\(\s*.*select\s*=`)},
		{ID: "PY022", Title: "subprocess with shell=True and user input", Description: "subprocess.call/run/Popen with shell=True and user-controlled input is vulnerable to command injection. Use shell=False and pass args as a list.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)subprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True.*\b(input|args|cmd|request)\b`)},
		{ID: "PY023", Title: "Use of ctypes.CDLL", Description: "ctypes.CDLL can load arbitrary shared libraries, which may execute untrusted native code. Avoid loading untrusted libraries.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`\bctypes\.CDLL\s*\(`)},
		{ID: "PY024", Title: "Hardcoded API key", Description: "Hardcoded API key detected. Use environment variables or a secret manager.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*=\s*["'][a-zA-Z0-9]{20,}["']`)},
		{ID: "PY025", Title: "XML external entity (XXE) via xml.etree.ElementTree", Description: "xml.etree.ElementTree.parse is vulnerable to XXE without defusedxml. Use defusedxml to mitigate XXE attacks.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)xml\.etree\.ElementTree\.parse\s*\(`)},

		// --- JavaScript/TypeScript rules ---

		// Code injection
		{ID: "JS001", Title: "Use of eval()", Description: "eval() can execute arbitrary code. Avoid using it, especially with user input.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`\beval\s*\(`), CWEID: "CWE-94"},
		{ID: "JS002", Title: "Use of Function constructor", Description: "new Function() is equivalent to eval() and can execute arbitrary code.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`\bnew\s+Function\s*\(`)},
		{ID: "JS003", Title: "Use of child_process.exec", Description: "child_process.exec runs commands in a shell and is vulnerable to command injection. Use execFile or spawn with shell=false.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`\bchild_process\.exec\s*\(`)},
		{ID: "JS004", Title: "Use of child_process.execSync", Description: "child_process.execSync runs commands in a shell and is vulnerable to command injection.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`\bchild_process\.execSync\s*\(`)},

		// SQL injection
		{ID: "JS005", Title: "SQL query with string interpolation", Description: "SQL query with template literals or string concatenation is vulnerable to SQL injection. Use parameterized queries.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)(query|execute)\s*\(\s*` + "`" + `\s*(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|INTO)\b.*\$\{`), CWEID: "CWE-89", SkipQuoteFilter: true},

		// Crypto
		{ID: "JS006", Title: "Use of MD5", Description: "MD5 is a weak hash algorithm. Use SHA-256 or stronger.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)\b(createHash|md5|MD5)\s*[\(\.]`)},
		{ID: "JS007", Title: "Use of SHA1", Description: "SHA1 is a weak hash algorithm. Use SHA-256 or stronger.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)\b(createHash\s*\(\s*['"]sha1['"]|sha1\s*\()`)},
		{ID: "JS008", Title: "Use of Math.random() for security", Description: "Math.random() is not cryptographically secure. Use crypto.randomBytes() or crypto.getRandomValues() instead.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)\bMath\.random\s*\(\s*\)`)},

		// Express/Node security
		{ID: "JS009", Title: "Express app with CORS wildcard", Description: "CORS with origin '*' allows requests from any domain.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)cors\s*\(\s*\{[^}]*origin\s*:\s*['"]\*['"]`), CWEID: "CWE-942"},
		{ID: "JS010", Title: "Helmet disabled", Description: "Disabling Helmet removes important security headers.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceLow, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)helmet\s*\(\s*false\s*\)`)},

		// Debug
		{ID: "JS011", Title: "Node.js debug mode", Description: "Running Node.js with --inspect flag exposes the debugger.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`--inspect(--brk)?(?:=\d+)?`)},

		// React/Next.js
		{ID: "JS012", Title: "dangerouslySetInnerHTML", Description: "dangerouslySetInnerHTML can lead to XSS if the content is not properly sanitized.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`dangerouslySetInnerHTML`)},

		// Additional JS/TS rules (JS013-JS020)
		{ID: "JS013", Title: "Prototype pollution via __proto__", Description: "Assignment to __proto__ can lead to prototype pollution. Use Object.create(null) or Map instead.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`\b__proto__\b`)},
		{ID: "JS014", Title: "SSRF via axios/fetch with user-controlled URL", Description: "axios/fetch call with a request-controlled URL/host/endpoint may be vulnerable to SSRF. Validate and restrict the destination.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)(axios|fetch)\s*\(\s*.*\b(req\.|request\.)\b`)},
		{ID: "JS015", Title: "Path traversal via fs with user input", Description: "fs.readFile/writeFile/createReadStream/createWriteStream with user-controlled paths may be vulnerable to path traversal. Validate and sanitize paths.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)fs\.(readFile|writeFile|createReadStream|createWriteStream)\s*\(\s*.*\b(req\.|params|query|body)\b`)},
		{ID: "JS016", Title: "SQL injection via Sequelize.query with user input", Description: "sequelize.query with user-controlled input is vulnerable to SQL injection. Use parameterized queries or replacements.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)sequelize\.query\s*\(\s*.*\b(req\.|params|body|query)\b`), CWEID: "CWE-89", SkipQuoteFilter: true},
		{ID: "JS017", Title: "Express body-parser limit too high", Description: "body-parser JSON limit set very high (>= 100MB) can enable denial-of-service via large payloads. Use a reasonable limit.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceLow, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)limit\s*:\s*["'](\d{3,})mb["']`)},
		{ID: "JS018", Title: "Insecure cookie settings", Description: "res.cookie without secure/httpOnly flags may expose cookies to XSS or transport interception. Set secure and httpOnly appropriately.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceLow, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)res\.cookie\s*\(\s*["'][^"']+["']\s*,\s*[^,]+,\s*\{[^}]*\}\s*\)`)},
		{ID: "JS019", Title: "eval in require context", Description: "require() with eval can lead to arbitrary code execution. Avoid dynamic requires with dangerous modules.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`\brequire\s*\(\s*.*\beval\b`)},
		{ID: "JS020", Title: "Dynamic require with user input", Description: "require() with user-controlled input can lead to arbitrary module loading and code execution. Avoid dynamic requires with user input.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`\brequire\s*\(\s*.*\b(req\.|params|query|body|input)\b`)},

		// --- Ruby rules ---

		{ID: "RB001", Title: "Ruby eval()", Description: "eval() can execute arbitrary code. Avoid using it.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`\beval\s*\(`)},
		{ID: "RB002", Title: "Ruby system() call", Description: "system() is vulnerable to command injection. Use system with separate arguments.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`\bsystem\s*\(`)},
		{ID: "RB003", Title: "Ruby backtick execution", Description: "Backtick execution is vulnerable to command injection.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile("`.*\\#\\{.*\\}.*`")},
		{ID: "RB004", Title: "Ruby SQL injection", Description: "SQL query with string interpolation is vulnerable to SQL injection.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)(execute|query)\s*\(.*["'].*\b(SELECT|INSERT|UPDATE|DELETE)\b.*#\{`), CWEID: "CWE-89", SkipQuoteFilter: true},
		{ID: "RB005", Title: "Ruby OpenSSL weak cipher", Description: "Weak cipher detected. Use AES-256 or stronger.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)OpenSSL::Cipher::(DES|RC4|AES128)`)},

		// Additional Ruby rules (RB006, RB008; RB007 eval already covered by RB001)
		{ID: "RB006", Title: "Rails send_file with user-controlled path", Description: "send_file with user-controlled params/request may allow path traversal or arbitrary file download. Validate and restrict the path.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)send_file\s*\(.*\b(params|request)\b`), CWEID: "CWE-22"},
		{ID: "RB008", Title: "Hardcoded credentials", Description: "Hardcoded password/secret/api_key detected. Use environment variables or a secret manager.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)(password|secret|api_key)\s*=\s*["'][^"']{8,}["']`)},

		// --- PHP rules ---

		{ID: "PHP001", Title: "PHP eval()", Description: "eval() can execute arbitrary code. Avoid using it.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`\beval\s*\(`)},
		{ID: "PHP002", Title: "PHP exec/system call", Description: "exec/system/shell_exec are vulnerable to command injection.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`\b(exec|system|shell_exec|passthru|popen)\s*\(`)},
		{ID: "PHP003", Title: "PHP SQL injection", Description: "SQL query with string interpolation is vulnerable to SQL injection. Use prepared statements.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)(mysql_query|mysqli_query|pg_query)\s*\(\s*["'].*\$`), CWEID: "CWE-89", SkipQuoteFilter: true},
		{ID: "PHP004", Title: "PHP md5/sha1 for passwords", Description: "md5/sha1 are not suitable for password hashing. Use password_hash() instead.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`\b(md5|sha1)\s*\(`)},
		{ID: "PHP005", Title: "PHP file inclusion with variable", Description: "include/require with a variable can lead to LFI/RFI.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`\b(include|require|include_once|require_once)\s*\(\s*\$`), CWEID: "CWE-22"},

		// Additional PHP rules (PHP006-PHP008)
		{ID: "PHP006", Title: "Path traversal via include with user input", Description: "include/require with direct user input ($_GET/$_POST/$_REQUEST) is vulnerable to LFI/RFI. Validate and restrict included paths.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)(include|require)(_once)?\s*\(\s*\$_(GET|POST|REQUEST)`), CWEID: "CWE-22"},
		{ID: "PHP007", Title: "Deserialization via unserialize()", Description: "unserialize() can execute arbitrary code via magic methods or gadget chains. Avoid unserializing untrusted data.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`\bunserialize\s*\(`)},
		{ID: "PHP008", Title: "Command injection via system/exec with user input", Description: "system/exec/shell_exec/passthru/popen with direct user input ($_GET/$_POST/$_REQUEST) is vulnerable to command injection. Use escapeshellarg/escapeshellcmd.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`\b(system|exec|shell_exec|passthru|popen)\s*\(\s*\$_(GET|POST|REQUEST)`)},

		// --- Java rules ---

		// Command injection
		{ID: "JAVA001", Title: "Use of Runtime.exec()", Description: "Runtime.exec() is vulnerable to command injection if the command string includes user input. Use ProcessBuilder with argument lists instead.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`\bRuntime\.getRuntime\(\)\.exec\s*\(`)},
		{ID: "JAVA002", Title: "ProcessBuilder with shell", Description: "ProcessBuilder invoking sh -c is vulnerable to command injection. Pass arguments as a list without a shell.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`\bProcessBuilder\s*\(\s*["']sh["']\s*,\s*["']-c["']`)},

		// SQL injection
		{ID: "JAVA003", Title: "SQL query with string concatenation", Description: "SQL query built with string concatenation is vulnerable to SQL injection. Use parameterized queries with PreparedStatement.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)(Statement|createStatement)\s*\(\s*\).*\+\s*`), CWEID: "CWE-89", SkipQuoteFilter: true},
		{ID: "JAVA004", Title: "PreparedStatement with string concatenation", Description: "PreparedStatement built with string concatenation is vulnerable to SQL injection. Use placeholders (?) and setter methods.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)prepareStatement\s*\(\s*["'].*\+\s*`), CWEID: "CWE-89", SkipQuoteFilter: true},

		// Deserialization
		{ID: "JAVA005", Title: "ObjectInputStream deserialization", Description: "ObjectInputStream can execute arbitrary code during deserialization. Avoid deserializing untrusted data.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`\bObjectInputStream\s*\(`), CWEID: "CWE-502"},

		// Crypto
		{ID: "JAVA006", Title: "Use of MD5 hash", Description: "MD5 is a weak hash algorithm. Use SHA-256 or stronger via MessageDigest.getInstance(\"SHA-256\").", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`\bMessageDigest\.getInstance\s*\(\s*["']MD5["']\s*\)`), CWEID: "CWE-328"},
		{ID: "JAVA007", Title: "Use of SHA1 hash", Description: "SHA1 is a weak hash algorithm. Use SHA-256 or stronger via MessageDigest.getInstance(\"SHA-256\").", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`\bMessageDigest\.getInstance\s*\(\s*["']SHA-?1["']\s*\)`), CWEID: "CWE-328"},
		{ID: "JAVA008", Title: "Use of Random() for security", Description: "java.util.Random is not cryptographically secure. Use java.security.SecureRandom instead.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)(new\s+(java\.util\.)?Random\s*\(\s*\)|Math\.random\s*\(\s*\))`), CWEID: "CWE-330"},

		// TLS / trust
		{ID: "JAVA009", Title: "TrustAllCerts / X509TrustManager with no check", Description: "A TrustManager that performs no validation disables certificate verification, enabling MITM attacks.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)trustAll|checkServerTrusted\s*\([^)]*\)\s*\{\s*\}`), CWEID: "CWE-295"},

		// JNDI injection
		{ID: "JAVA010", Title: "JNDI injection", Description: "Context.lookup with a user-controlled string can lead to JNDI injection and RCE (e.g. Log4Shell). Avoid untrusted lookup targets.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`\bContext\.lookup\s*\(\s*[^"]*["']`), CWEID: "CWE-74"},

		// --- C# rules ---

		// SQL injection
		{ID: "CS001", Title: "SQL query with string concatenation", Description: "SQL query built with string concatenation is vulnerable to SQL injection. Use parameterized queries with SqlParameter.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)(SqlCommand|OleDbCommand)\s*\(\s*["'].*\+\s*`)},

		// Command injection
		{ID: "CS002", Title: "Use of Process.Start with shell", Description: "Process.Start invoking cmd /c is vulnerable to command injection. Pass arguments as a list without a shell.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`\bProcess\.Start\s*\(\s*["']cmd["']\s*,\s*["']/c`)},

		// Crypto
		{ID: "CS003", Title: "Use of MD5", Description: "MD5 is a weak hash algorithm. Use SHA-256 or stronger via SHA256.Create().", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`\bMD5\.Create\s*\(\s*\)|\bMD5CryptoServiceProvider\s*\(`)},
		{ID: "CS004", Title: "Use of SHA1", Description: "SHA1 is a weak hash algorithm. Use SHA-256 or stronger via SHA256.Create().", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`\bSHA1\.Create\s*\(\s*\)|\bSHA1CryptoServiceProvider\s*\(`)},
		{ID: "CS005", Title: "Use of Random() for security", Description: "System.Random is not cryptographically secure. Use System.Security.Cryptography.RandomNumberGenerator instead.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`\bnew\s+Random\s*\(\s*\)`)},

		// Deserialization
		{ID: "CS006", Title: "XML deserialization", Description: "XmlSerializer deserializing untrusted XML can lead to code execution. Validate and restrict types before deserialization.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`\bXmlSerializer\s*\(\s*typeof\s*\(`)},

		// Misconfiguration
		{ID: "CS007", Title: "Request validation disabled", Description: "ValidateRequest=false disables ASP.NET request validation, increasing XSS risk. Keep validation enabled.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)ValidateRequest\s*=\s*false`)},
		{ID: "CS008", Title: "Unsafe SQL connection string", Description: "Integrated Security=SSPI uses Windows auth credentials in the connection string. Ensure the connection string is not exposed.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceLow, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)Integrated\s+Security\s*=\s*SSPI`)},

		// --- Rust rules ---

		// Command injection
		{ID: "RS001", Title: "Use of Command::new with shell", Description: "Command::new with sh/bash can lead to command injection if arguments include user input. Pass arguments directly without a shell.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangRust}, Pattern: regexp.MustCompile(`\bCommand::new\s*\(\s*["']sh["']\s*\)|\bCommand::new\s*\(\s*["']bash["']\s*\)`)},

		// unsafe
		{ID: "RS002", Title: "unsafe block usage", Description: "unsafe blocks bypass Rust's safety guarantees. Review carefully for memory safety and undefined behavior.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangRust}, Pattern: regexp.MustCompile(`\bunsafe\s*\{`)},

		// Path traversal
		{ID: "RS003", Title: "Use of std::fs::read with user path", Description: "std::fs::read with a user-controlled path can lead to path traversal. Validate and canonicalize paths before reading.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangRust}, Pattern: regexp.MustCompile(`\bstd::fs::read\s*\(\s*`)},

		// Process exec
		{ID: "RS004", Title: "Use of std::process::exec", Description: "std::process::exec replaces the current process image and can lead to command injection if the path is user-controlled.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangRust}, Pattern: regexp.MustCompile(`\bstd::process::exec\s*\(`)},

		// Undefined behavior
		{ID: "RS005", Title: "transmute usage", Description: "std::mem::transmute reinterprets memory and can cause undefined behavior. Avoid unless absolutely necessary and verified safe.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangRust}, Pattern: regexp.MustCompile(`\bstd::mem::transmute\s*\(`)},

		// Crypto
		{ID: "RS006", Title: "Use of rust-crypto md5", Description: "MD5 is a weak hash algorithm. Use SHA-256 or stronger from a maintained crate.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangRust}, Pattern: regexp.MustCompile(`\bmd5::Md5\b`)},

		// --- Cross-language patterns ---

		{ID: "XLANG001", Title: "Hardcoded IP address", Description: "Hardcoded IP address detected. This may leak internal infrastructure details.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceLow, Languages: []Language{LangPython, LangJavaScript, LangTypeScript, LangRuby, LangPHP}, Pattern: regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)},
		{ID: "XLANG002", Title: "TODO/FIXME security comment", Description: "Security-related TODO or FIXME comment found. This should be addressed.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceLow, Languages: []Language{LangPython, LangJavaScript, LangTypeScript, LangRuby, LangPHP}, Pattern: regexp.MustCompile(`(?i)(TODO|FIXME|HACK|XXX).*(security|vulnerab|insecure|unsafe|auth|password|token|secret|inject)`)},

		// --- Django/Flask framework rules (PY026-PY040) ---

		{ID: "PY026", Title: "Django DEBUG=True in settings", Description: "Debug mode should never be enabled in production Django settings.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)DEBUG\s*=\s*True`)},
		{ID: "PY027", Title: "Django ALLOWED_HOSTS wildcard", Description: "ALLOWED_HOSTS = ['*'] allows requests from any host.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)ALLOWED_HOSTS\s*=\s*\[\s*['"]\*['"]\s*\]`)},
		{ID: "PY028", Title: "Django SECRET_KEY hardcoded", Description: "Hardcoded Django SECRET_KEY detected. Load it from an environment variable.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)SECRET_KEY\s*=\s*['"][^'"]{8,}['"]`)},
		{ID: "PY029", Title: "Django DATABASES with hardcoded credentials", Description: "Hardcoded database password in Django settings. Use environment variables or a secret manager.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)('|")PASSWORD('|")\s*:\s*['"][^'"]+['"]`)},
		{ID: "PY030", Title: "Flask app.run with debug=True", Description: "Running Flask with debug=True exposes the Werkzeug debugger, which can lead to RCE.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)app\.run\(.*debug\s*=\s*True`)},
		{ID: "PY031", Title: "Flask SECRET_KEY hardcoded", Description: "Hardcoded Flask SECRET_KEY detected. Load it from an environment variable.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)app\.config\[['"]SECRET_KEY['"]\]\s*=\s*['"][^'"]+['"]`)},
		{ID: "PY032", Title: "Flask session with permanent=True", Description: "Permanent sessions can increase the risk of session hijacking. Consider shorter session lifetimes.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceLow, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)session\.permanent\s*=\s*True`)},
		{ID: "PY033", Title: "Django SECURE_SSL_REDIRECT disabled", Description: "SECURE_SSL_REDIRECT=False disables automatic HTTPS redirection. Enable it to enforce TLS.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)SECURE_SSL_REDIRECT\s*=\s*False`)},
		{ID: "PY034", Title: "Django CSRF middleware disabled", Description: "Commenting out the CSRF middleware disables cross-site request forgery protection. Keep it enabled.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)#.*django\.middleware\.csrf\.CsrfViewMiddleware`)},
		{ID: "PY035", Title: "Django SECURE_HSTS_SECONDS = 0", Description: "SECURE_HSTS_SECONDS=0 disables HTTP Strict Transport Security. Set a non-zero value to enforce HSTS.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)SECURE_HSTS_SECONDS\s*=\s*0`)},
		{ID: "PY036", Title: "Flask CORS with wildcard origins", Description: "CORS with origins='*' allows requests from any domain. Restrict to trusted origins.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)CORS\(.*origins\s*=\s*['"]\*['"]`)},
		{ID: "PY037", Title: "Hardcoded AWS access key", Description: "Hardcoded AWS access key detected. Use environment variables or IAM roles.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{ID: "PY038", Title: "Hardcoded AWS secret access key", Description: "Hardcoded AWS secret access key detected. Use environment variables or IAM roles.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)aws_secret_access_key\s*=\s*['"][A-Za-z0-9/+=]{40}['"]`)},
		{ID: "PY039", Title: "Hardcoded JWT secret", Description: "Hardcoded JWT secret detected. Use environment variables or a secret manager.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)jwt\.secret\s*=\s*['"][^'"]{8,}['"]`)},
		{ID: "PY040", Title: "Use of telnetlib", Description: "telnetlib transmits data in plaintext and is deprecated. Use SSH or encrypted protocols instead.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`\btelnetlib\.`)},

		// --- Express/Node.js framework rules (JS021-JS035) ---

		{ID: "JS021", Title: "Express CORS with wildcard origin", Description: "CORS with origin:'*' allows requests from any domain. Restrict to trusted origins.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)cors\s*\(\s*\{[^}]*origin\s*:\s*['"]\*['"]`)},
		{ID: "JS022", Title: "Express session with hardcoded secret", Description: "Hardcoded session secret detected. Use environment variables or a secret manager.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)session\s*\(\s*\{[^}]*secret\s*:\s*['"][^'"]+['"]`)},
		{ID: "JS023", Title: "Express cookie without secure flag", Description: "res.cookie with maxAge but potentially without the secure flag may expose cookies over insecure transport. Set secure:true.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceLow, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)res\.cookie\s*\([^)]*maxAge[^)]*\)`)},
		{ID: "JS024", Title: "JWT signed with hardcoded secret", Description: "jwt.sign with a hardcoded secret is insecure. Load the secret from an environment variable.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)jwt\.sign\s*\([^)]*['"][^'"]{8,}['"]`)},
		{ID: "JS025", Title: "JWT verified with hardcoded secret", Description: "jwt.verify with a hardcoded secret is insecure. Load the secret from an environment variable.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)jwt\.verify\s*\([^)]*['"][^'"]{8,}['"]`)},
		{ID: "JS026", Title: "Hardcoded AWS access key", Description: "Hardcoded AWS access key detected. Use environment variables or IAM roles.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{ID: "JS027", Title: "Hardcoded Stripe key", Description: "Hardcoded Stripe secret key detected. Use environment variables or a secret manager.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`)},
		{ID: "JS028", Title: "Hardcoded GitHub token", Description: "Hardcoded GitHub token detected. Use environment variables or a secret manager.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36}`)},
		{ID: "JS029", Title: "Hardcoded Slack token", Description: "Hardcoded Slack token detected. Use environment variables or a secret manager.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,}`)},
		{ID: "JS030", Title: "MongoDB connection with credentials", Description: "MongoDB connection string with embedded credentials may leak secrets. Use environment variables.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)mongodb(\+srv)?://[^:]+:[^@]+@`)},
		{ID: "JS031", Title: "PostgreSQL connection with credentials", Description: "PostgreSQL connection string with embedded credentials may leak secrets. Use environment variables.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)postgres(ql)?://[^:]+:[^@]+@`)},
		{ID: "JS032", Title: "MySQL connection with credentials", Description: "MySQL connection string with embedded credentials may leak secrets. Use environment variables.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)mysql://[^:]+:[^@]+@`)},
		{ID: "JS033", Title: "Redis connection with password", Description: "Redis connection string with embedded password may leak secrets. Use environment variables.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)redis://:[^@]+@`)},
		{ID: "JS034", Title: "process.env injection from request", Description: "Accessing process.env with a request-derived key can lead to information disclosure or injection. Avoid dynamic env access.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)process\.env\[.*req\.`)},
		{ID: "JS035", Title: "Express body-parser with large limit", Description: "body-parser with a large limit (>=100MB) can enable denial-of-service via large payloads. Use a reasonable limit.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceLow, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)bodyparser?\.(json|urlencoded)\s*\([^)]*limit\s*:\s*['"](\d{3,})mb['"]`)},

		// --- Rails framework rules (RB009-RB018) ---

		{ID: "RB009", Title: "Rails secret_key_base hardcoded", Description: "Hardcoded Rails secret_key_base detected. Load it from an environment variable or credentials store.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)config\.secret_key_base\s*=\s*['"][^'"]+['"]`)},
		{ID: "RB010", Title: "Rails force_ssl disabled", Description: "config.force_ssl=false disables HTTPS enforcement. Enable it to protect transport security.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)config\.force_ssl\s*=\s*false`)},
		{ID: "RB011", Title: "Rails CSRF protection skipped", Description: "skip_before_action :verify_authenticity_token disables CSRF protection. Keep it enabled unless absolutely necessary.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)skip_before_action\s+:verify_authenticity_token`)},
		{ID: "RB012", Title: "Rails has_attached_file without validation", Description: "has_attached_file without a content_type validation may allow upload of malicious files. Add validation.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceLow, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)has_attached_file\s*:(\w+)\s*$`)},
		{ID: "RB013", Title: "Rails find_by_sql with interpolation", Description: "find_by_sql with string interpolation is vulnerable to SQL injection. Use parameterized queries.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)find_by_sql\s*\(\s*["'].*#\{`)},
		{ID: "RB014", Title: "Rails update_attributes (mass assignment)", Description: "update_attributes is deprecated and can lead to mass assignment vulnerabilities. Use strong parameters with update.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)update_attributes\s*\(`)},
		{ID: "RB015", Title: "Hardcoded AWS key in Ruby", Description: "Hardcoded AWS access key detected. Use environment variables or IAM roles.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{ID: "RB016", Title: "Ruby Net::HTTP without SSL", Description: "http.use_ssl=false disables TLS for HTTP requests, exposing data to interception. Enable SSL.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)http\.use_ssl\s*=\s*false`)},
		{ID: "RB017", Title: "Ruby hardcoded Stripe key", Description: "Hardcoded Stripe secret key detected. Use environment variables or a secret manager.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`)},
		{ID: "RB018", Title: "Ruby Open3 with user input", Description: "Open3.capture/popen/spawn with user input (params/request/input) is vulnerable to command injection.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)Open3\.(capture|popen|spawn)\s*\(.*\b(params|request|input)\b`)},

		// --- PHP framework rules (PHP009-PHP018) ---

		{ID: "PHP009", Title: "Laravel APP_KEY hardcoded", Description: "Hardcoded Laravel APP_KEY (base64:) detected. Load it from an environment variable.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)APP_KEY\s*=\s*base64:`)},
		{ID: "PHP010", Title: "Laravel debug mode enabled", Description: "APP_DEBUG=true enables debug mode in production, exposing sensitive information. Set it to false in production.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)APP_DEBUG\s*=\s*true`)},
		{ID: "PHP011", Title: "Laravel DB password in .env", Description: "Hardcoded database password in .env detected. Ensure .env is not committed and use secret management.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)DB_PASSWORD\s*=\s*[^\s]+`)},
		{ID: "PHP012", Title: "PHP md5 for password hashing", Description: "md5 is not suitable for password hashing. Use password_hash() with PASSWORD_BCRYPT or PASSWORD_ARGON2ID.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)md5\s*\(\s*\$.*password`)},
		{ID: "PHP013", Title: "PHP sha1 for password hashing", Description: "sha1 is not suitable for password hashing. Use password_hash() with PASSWORD_BCRYPT or PASSWORD_ARGON2ID.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)sha1\s*\(\s*\$.*password`)},
		{ID: "PHP014", Title: "PHP mysql_connect (deprecated)", Description: "mysql_connect is deprecated and insecure. Use PDO or mysqli with prepared statements.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)mysql_connect\s*\(`)},
		{ID: "PHP015", Title: "PHP preg_replace with /e modifier", Description: "preg_replace with the /e modifier executes the replacement as PHP code, leading to code injection. Use preg_replace_callback instead.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)preg_replace\s*\(\s*['"][^'"]*\/[a-z]*e[a-z]*['"]`)},
		{ID: "PHP016", Title: "PHP eval with variable", Description: "eval() with a variable can execute arbitrary code. Avoid eval entirely.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)\beval\s*\(\s*\$`)},
		{ID: "PHP017", Title: "PHP assert with string", Description: "assert() with a string argument evaluates it as PHP code, leading to code injection. Avoid assert with strings.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)\bassert\s*\(\s*['"]`)},
		{ID: "PHP018", Title: "PHP hardcoded AWS key", Description: "Hardcoded AWS access key detected. Use environment variables or IAM roles.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},

		// --- Java/Spring framework rules (JAVA011-JAVA022) ---

		{ID: "JAVA011", Title: "Spring Boot actuator endpoints exposed", Description: "Exposing all actuator endpoints (include=*) can leak sensitive information. Restrict to necessary endpoints.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)management\.endpoints\.web\.exposure\.include\s*=\s*\*`), CWEID: "CWE-200"},
		{ID: "JAVA012", Title: "Spring hardcoded password in properties", Description: "Hardcoded password in Spring properties detected. Use environment variables or a vault.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)password\s*=\s*[^\s${}]+`), CWEID: "CWE-798", SuppressFunc: suppressJAVA012},
		{ID: "JAVA013", Title: "Spring datasource URL with credentials", Description: "JDBC URL with embedded credentials may leak secrets. Use environment variables or a secret manager.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)jdbc:.*://[^:]+:[^@]+@`), CWEID: "CWE-798"},
		{ID: "JAVA014", Title: "Java hardcoded AWS key", Description: "Hardcoded AWS access key detected. Use environment variables or IAM roles.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), CWEID: "CWE-798"},
		{ID: "JAVA015", Title: "Java System.setProperty trustAll", Description: "Disabling SSL certificate validation via System.setProperty enables MITM attacks. Do not disable certificate checks.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)System\.setProperty\s*\(\s*["']com\.sun\.net\.ssl\.checkEorValidateCert["']`), CWEID: "CWE-295"},
		{ID: "JAVA016", Title: "Java SSLContext.getInstance(\"SSL\")", Description: "SSLContext.getInstance(\"SSL\") uses the deprecated SSL protocol. Use \"TLS\" or \"TLSv1.2\" instead.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)SSLContext\.getInstance\s*\(\s*["']SSL["']\s*\)`), CWEID: "CWE-327"},
		{ID: "JAVA017", Title: "Java HttpsURLConnection.setDefaultHostnameVerifier", Description: "Overriding the default hostname verifier can disable hostname validation, enabling MITM attacks. Avoid overriding.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)HttpsURLConnection\.setDefaultHostnameVerifier`), CWEID: "CWE-295"},
		{ID: "JAVA018", Title: "Java setHostnameVerifier returning true", Description: "A hostname verifier that always returns true disables hostname validation, enabling MITM attacks. Implement proper validation.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)setHostnameVerifier\s*\(\s*\([^)]*\)\s*->\s*true`), CWEID: "CWE-295"},
		{ID: "JAVA019", Title: "Spring @CrossOrigin with wildcard origins", Description: "@CrossOrigin with origins=\"*\" allows requests from any domain. Restrict to trusted origins.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)@CrossOrigin\s*\(\s*origins\s*=\s*["']\*["']`), CWEID: "CWE-942"},
		{ID: "JAVA020", Title: "Java hardcoded private key", Description: "Hardcoded private key detected. Store keys in a secure vault or key management service.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`-----BEGIN (RSA |EC )?PRIVATE KEY-----`), CWEID: "CWE-798"},
		{ID: "JAVA021", Title: "Java System.exit in web app", Description: "System.exit() in a web application can shut down the entire server, causing denial of service. Avoid it in web contexts.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceLow, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`\bSystem\.exit\s*\(`), CWEID: "CWE-400"},
		{ID: "JAVA022", Title: "Java Thread.sleep in web app", Description: "Thread.sleep() in a web application can block request threads and cause denial of service. Avoid blocking calls in request handlers.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceLow, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`\bThread\.sleep\s*\(`), CWEID: "CWE-400"},

		// --- C# / ASP.NET framework rules (CS009-CS018) ---

		{ID: "CS009", Title: "ASP.NET debug=true", Description: "Debug mode enabled in ASP.NET configuration exposes detailed error pages. Disable in production.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)debug\s*=\s*["']true["']`)},
		{ID: "CS010", Title: "ASP.NET customErrors off", Description: "customErrors mode=off exposes detailed error information to users. Set mode to On or RemoteOnly.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)customErrors\s+mode\s*=\s*["']off["']`)},
		{ID: "CS011", Title: "ASP.NET trace enabled", Description: "Trace output enabled in production can leak sensitive application information. Disable tracing in production.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)trace\s*=\s*["']true["']`)},
		{ID: "CS012", Title: "Hardcoded connection string with password", Description: "Connection string with an embedded password detected. Use integrated security or a secret manager.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)connectionString\s*=\s*["'][^"']*password=[^"']*["']`)},
		{ID: "CS013", Title: "C# hardcoded AWS key", Description: "Hardcoded AWS access key detected. Use environment variables or IAM roles.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{ID: "CS014", Title: "Forms authentication without SSL", Description: "requireSSL=false for forms authentication allows cookies to be sent over insecure transport. Enable requireSSL.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)requireSSL\s*=\s*["']false["']`)},
		{ID: "CS015", Title: "ASP.NET ViewStateMac disabled", Description: "viewStateMac=false disables message authentication codes on ViewState, enabling tampering. Keep it enabled.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)viewStateMac\s*=\s*["']false["']`)},
		{ID: "CS016", Title: "Hardcoded SQL connection string", Description: "SQL connection string with embedded credentials detected. Use integrated security or a secret manager.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)Data Source=.*;.*User ID=.*;.*Password=`)},
		{ID: "CS017", Title: ".NET hardcoded private key", Description: "Hardcoded private key detected. Store keys in a secure vault or key management service.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`-----BEGIN (RSA |EC )?PRIVATE KEY-----`)},
		{ID: "CS018", Title: "C# Process.Start with cmd", Description: "Process.Start with cmd can lead to command injection if arguments include user input. Pass arguments as a list without a shell.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)Process\.Start\s*\(\s*["']cmd["']`)},

		// --- Rust framework rules (RS007-RS012) ---

		{ID: "RS007", Title: "Rust unwrap() in production", Description: "unwrap() can panic and crash the application. Use proper error handling with Result and ? operator.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceLow, Languages: []Language{LangRust}, Pattern: regexp.MustCompile(`\.unwrap\s*\(\s*\)`)},
		{ID: "RS008", Title: "Rust expect() with message", Description: "expect() can panic and crash the application. Use proper error handling with Result and ? operator.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceLow, Languages: []Language{LangRust}, Pattern: regexp.MustCompile(`\.expect\s*\(`)},
		{ID: "RS009", Title: "Rust hardcoded password", Description: "Hardcoded password detected. Use environment variables or a secret manager.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangRust}, Pattern: regexp.MustCompile(`(?i)password\s*=\s*["'][^""]{8,}["']`)},
		{ID: "RS010", Title: "Rust hardcoded AWS key", Description: "Hardcoded AWS access key detected. Use environment variables or IAM roles.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangRust}, Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{ID: "RS011", Title: "Rust env::var unwrap", Description: "env::var().unwrap() can panic if the variable is unset. Use expect with a clear message or handle the error.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceLow, Languages: []Language{LangRust}, Pattern: regexp.MustCompile(`env::var\s*\([^)]+\)\.unwrap\s*\(\s*\)`)},
		{ID: "RS012", Title: "Rust SQL string concatenation", Description: "format! with SQL keywords and interpolation is vulnerable to SQL injection. Use parameterized queries.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangRust}, Pattern: regexp.MustCompile(`(?i)format!\s*\(\s*["'].*SELECT.*\{`)},

		// --- Go framework rules (GO020-GO028) ---

		{ID: "GO020", Title: "Go hardcoded AWS key", Description: "Hardcoded AWS access key detected. Use environment variables or IAM roles.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangGo}, Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{ID: "GO021", Title: "Go hardcoded private key", Description: "Hardcoded private key detected. Store keys in a secure vault or key management service.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangGo}, Pattern: regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`)},
		{ID: "GO022", Title: "Go TLS InsecureSkipVerify", Description: "InsecureSkipVerify:true disables TLS certificate verification, enabling MITM attacks. Do not skip verification.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangGo}, Pattern: regexp.MustCompile(`(?i)InsecureSkipVerify\s*:\s*true`)},
		{ID: "GO023", Title: "Go HTTP redirect without validation", Description: "http.Redirect with user-controlled URLs without validation can enable open redirect attacks. Validate redirect targets.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceLow, Languages: []Language{LangGo}, Pattern: regexp.MustCompile(`http\.Redirect\s*\(\s*w,\s*r,\s*[^,]+,\s*http\.StatusFound\s*\)`)},
		{ID: "GO024", Title: "Go hardcoded database URL", Description: "Database connection string with embedded credentials detected. Use environment variables or a secret manager.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangGo}, Pattern: regexp.MustCompile(`(?i)(postgres|mysql|mongodb|redis)://[^:]+:[^@]+@`)},
		{ID: "GO025", Title: "Go exec.Command with shell", Description: "exec.Command with sh -c is vulnerable to command injection if arguments include user input. Pass arguments as a list.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangGo}, Pattern: regexp.MustCompile(`exec\.Command\s*\(\s*["']sh["']\s*,\s*["']-c["']`)},
		{ID: "GO026", Title: "Go crypto/md5 usage", Description: "MD5 is a weak hash algorithm. Use SHA-256 or stronger from crypto/sha256.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangGo}, Pattern: regexp.MustCompile(`(?i)crypto/md5`)},
		{ID: "GO027", Title: "Go crypto/sha1 usage", Description: "SHA1 is a weak hash algorithm. Use SHA-256 or stronger from crypto/sha256.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangGo}, Pattern: regexp.MustCompile(`(?i)crypto/sha1`)},
		{ID: "GO028", Title: "Go math/rand for security", Description: "math/rand is not cryptographically secure. Use crypto/rand for security-sensitive randomness.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangGo}, Pattern: regexp.MustCompile(`math/rand`)},

		// --- Generic/Cross-language rules (GEN001-GEN010) ---

		{ID: "GEN001", Title: "Hardcoded AWS access key", Description: "Hardcoded AWS access key detected. Use environment variables or IAM roles.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangGeneric}, Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{ID: "GEN002", Title: "Hardcoded private key", Description: "Hardcoded private key detected. Store keys in a secure vault or key management service.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangGeneric}, Pattern: regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`)},
		{ID: "GEN003", Title: "Hardcoded JWT token", Description: "Hardcoded JWT token detected. Store tokens securely and never commit them to source control.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangGeneric}, Pattern: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
		{ID: "GEN004", Title: "Hardcoded Slack token", Description: "Hardcoded Slack token detected. Use environment variables or a secret manager.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangGeneric}, Pattern: regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,}`)},
		{ID: "GEN005", Title: "Hardcoded Stripe key", Description: "Hardcoded Stripe key detected. Use environment variables or a secret manager.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangGeneric}, Pattern: regexp.MustCompile(`(sk|pk)_(live|test)_[0-9a-zA-Z]{24,}`)},
		{ID: "GEN006", Title: "Hardcoded GitHub token", Description: "Hardcoded GitHub token detected. Use environment variables or a secret manager.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangGeneric}, Pattern: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36}`)},
		{ID: "GEN007", Title: "Hardcoded Google API key", Description: "Hardcoded Google API key detected. Use environment variables or a secret manager.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangGeneric}, Pattern: regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`)},
		{ID: "GEN008", Title: "Hardcoded Twilio token", Description: "Hardcoded Twilio token detected. Use environment variables or a secret manager.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangGeneric}, Pattern: regexp.MustCompile(`SK[0-9a-fA-F]{32}`)},
		{ID: "GEN009", Title: "Connection string with credentials", Description: "Connection string with embedded credentials detected. Use environment variables or a secret manager.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangGeneric}, Pattern: regexp.MustCompile(`(?i)(postgres|mysql|mongodb|redis|amqp)://[^:]+:[^@]+@`)},
		{ID: "GEN010", Title: "Hardcoded password assignment", Description: "Hardcoded password detected. Use environment variables or a secret manager.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangGeneric}, Pattern: regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[=:]\s*["'][^"']{6,}["']`)},

		// --- Dockerfile security rules (DOCKER001-DOCKER010) ---
		{ID: "DOCKER001", Title: "Running as root in Docker", Description: "Container runs as root user. Specify a non-root USER.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangDockerfile}, Pattern: regexp.MustCompile(`(?i)^\s*USER\s+root\b`)},
		{ID: "DOCKER002", Title: "Privileged container", Description: "Container runs in privileged mode, granting full host access.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangDockerfile}, Pattern: regexp.MustCompile(`(?i)^\s*--privileged\b`)},
		{ID: "DOCKER004", Title: "ADD instead of COPY", Description: "ADD can fetch remote URLs and extract archives, increasing supply chain risk.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangDockerfile}, Pattern: regexp.MustCompile(`(?i)^\s*ADD\s+`)},
		{ID: "DOCKER005", Title: "APT-GET without cleanup", Description: "apt-get install without rm -rf /var/lib/apt/lists/* leaves cache in image.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangDockerfile}, Pattern: regexp.MustCompile(`(?i)apt-get\s+install`)},
		{ID: "DOCKER006", Title: "Secrets in ENV", Description: "ENV instruction contains a potential secret (key, token, password).", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangDockerfile}, Pattern: regexp.MustCompile(`(?i)^\s*ENV\s+\w*(SECRET|PASSWORD|TOKEN|KEY|CREDENTIAL)\w*\s*=\s*\S+`)},
		{ID: "DOCKER007", Title: "Latest tag used", Description: "Using :latest tag can lead to non-reproducible builds and unexpected changes.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangDockerfile}, Pattern: regexp.MustCompile(`(?i)^\s*FROM\s+\S+:latest\b`)},
		{ID: "DOCKER008", Title: "Exposed sensitive port", Description: "EXPOSE reveals internal service ports. Avoid exposing database or debug ports.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceLow, Languages: []Language{LangDockerfile}, Pattern: regexp.MustCompile(`(?i)^\s*EXPOSE\s+(22|2375|2376|3306|5432|6379|27017|9200|11211)\b`)},
		{ID: "DOCKER009", Title: "curl | bash pattern in RUN", Description: "Downloading and executing scripts in RUN is a supply chain risk.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangDockerfile}, Pattern: regexp.MustCompile(`(?i)curl\s+[^|]*\|\s*(bash|sh)`)},
		{ID: "DOCKER010", Title: "sudo in Dockerfile", Description: "Using sudo inside a container is an anti-pattern. Run as the appropriate USER instead.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangDockerfile}, Pattern: regexp.MustCompile(`(?i)^\s*RUN\s+.*\bsudo\b`)},

		// --- Kubernetes / Helm security rules (K8S001-K8S010) ---
		{ID: "K8S001", Title: "Privileged container in K8s", Description: "securityContext.privileged: true grants full host access.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangYAML}, Pattern: regexp.MustCompile(`(?i)privileged:\s*true`), CWEID: "CWE-269"},
		{ID: "K8S002", Title: "Container runs as root", Description: "runAsUser: 0 or missing runAsUser means the container runs as root.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangYAML}, Pattern: regexp.MustCompile(`runAsUser:\s*0\b`), CWEID: "CWE-269"},
		{ID: "K8S004", Title: "allowPrivilegeEscalation not false", Description: "allowPrivilegeEscalation should be set to false.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangYAML}, Pattern: regexp.MustCompile(`allowPrivilegeEscalation:\s*true`), CWEID: "CWE-269"},
		{ID: "K8S005", Title: "readOnlyRootFilesystem not set", Description: "readOnlyRootFilesystem should be true to prevent writes to the root filesystem.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceLow, Languages: []Language{LangYAML}, Pattern: regexp.MustCompile(`readOnlyRootFilesystem:\s*false`)},
		{ID: "K8S006", Title: "Host network enabled", Description: "hostNetwork: true gives the container access to the host's network interfaces.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangYAML}, Pattern: regexp.MustCompile(`hostNetwork:\s*true`), CWEID: "CWE-269"},
		{ID: "K8S007", Title: "Host PID enabled", Description: "hostPID: true gives the container access to the host's process namespace.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangYAML}, Pattern: regexp.MustCompile(`hostPID:\s*true`), CWEID: "CWE-269"},
		{ID: "K8S008", Title: "Host IPC enabled", Description: "hostIPC: true gives the container access to the host's IPC namespace.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangYAML}, Pattern: regexp.MustCompile(`hostIPC:\s*true`), CWEID: "CWE-269"},
		{ID: "K8S009", Title: "CAP_SYS_ADMIN in securityContext", Description: "CAP_SYS_ADMIN grants broad privileges. Drop all capabilities and add only needed ones.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangYAML}, Pattern: regexp.MustCompile(`(?i)SYS_ADMIN`), CWEID: "CWE-269"},
		{ID: "K8S010", Title: "Image uses latest tag", Description: "Using :latest in Kubernetes manifests leads to non-reproducible deployments.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangYAML}, Pattern: regexp.MustCompile(`image:\s*\S+:latest\b`)},
		// K8s base64-encoded secret in YAML (CWE-798)
		{ID: "K8S011", Title: "Base64-encoded secret in Kubernetes YAML", Description: "Base64-encoded secret data in Kubernetes ConfigMap/Secret. Use a secrets manager or encrypted secrets.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangYAML}, Pattern: regexp.MustCompile(`(?i)\b\w*key\b.*:\s*[A-Za-z0-9+/=]{20,}`), CWEID: "CWE-798"},
		// K8s overly permissive RBAC (CWE-269)
		{ID: "K8S012", Title: "Overly permissive RBAC wildcard resources", Description: "RBAC rule with resources: [\"*\"] grants access to all resources. Follow least-privilege principle.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangYAML}, Pattern: regexp.MustCompile(`resources:\s*\["\*"\]`), CWEID: "CWE-269"},

		// --- Terraform security rules (TF001-TF010) ---
		{ID: "TF001", Title: "AWS S3 bucket without versioning", Description: "S3 bucket should have versioning enabled for data recovery.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`(?i)aws_s3_bucket\b`)},
		{ID: "TF002", Title: "AWS S3 bucket public ACL", Description: "S3 bucket has a public-read or public-read-write ACL.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`(?i)(public-read|public-read-write|website_endpoint)`)},
		{ID: "TF003", Title: "Security group allows 0.0.0.0/0", Description: "Security group rule allows traffic from anywhere (0.0.0.0/0).", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`0\.0\.0\.0/0`)},
		{ID: "TF004", Title: "Hardcoded credentials in Terraform", Description: "Terraform resource contains hardcoded password or secret key.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`(?i)(password|secret_key|api_key|access_key)\s*=\s*["'][^"']{8,}["']`), CWEID: "CWE-798"},
		{ID: "TF005", Title: "RDS instance publicly accessible", Description: "RDS instance has publicly_accessible = true.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`publicly_accessible\s*=\s*true`)},
		{ID: "TF006", Title: "S3 bucket without encryption", Description: "S3 bucket should have server-side encryption enabled.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`(?i)aws_s3_bucket\b`)},
		{ID: "TF007", Title: "IAM policy with wildcard action", Description: "IAM policy uses Action: * or Resource: *, granting overly broad permissions.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`(?i)(Action|Resource)\s*=\s*["']?\*["']?`), CWEID: "CWE-284"},
		// Terraform IAM wildcard in JSON heredoc (CWE-284)
		{ID: "TF007b", Title: "IAM policy with wildcard action in JSON", Description: "IAM policy JSON with Action: * or Resource: * grants overly broad permissions. Follow least-privilege principle.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`(?i)"(Action|Resource)"\s*:\s*["']\*["']`), CWEID: "CWE-284", SkipQuoteFilter: true},
		// Terraform IAM service-specific wildcard (ec2:*, s3:*, etc.) (CWE-284)
		{ID: "TF007c", Title: "IAM policy with service wildcard action", Description: "IAM policy with service-level wildcard (e.g. ec2:*, s3:*) grants overly broad permissions. Specify only needed actions.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`(?i)"(Action|Resource)"\s*:\s*\[[^\]]*"\w+:\*"`), CWEID: "CWE-284", SkipQuoteFilter: true},
		{ID: "TF008", Title: "No TLS for database", Description: "RDS or database resource does not enforce TLS/SSL connections.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceLow, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`(?i)require_ssl\s*=\s*false`)},
		{ID: "TF009", Title: "Lambda with excessive timeout", Description: "Lambda function has timeout > 300 seconds, which can increase cost and complexity.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceLow, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`timeout\s*=\s*(3[0-9]{2}|[4-9][0-9]{2}|[0-9]{4,})`)},
		{ID: "TF010", Title: "EKS cluster endpoint public", Description: "EKS cluster has public endpoint access enabled.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`(?i)endpoint_public_access\s*=\s*true`)},
		// Additional Terraform/IaC rules (TF011-TF025)
		{ID: "TF011", Title: "S3 bucket logging disabled", Description: "S3 bucket does not have access logging enabled for audit trail.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`(?i)aws_s3_bucket\b`), CWEID: "CWE-778"},
		{ID: "TF012", Title: "CloudTrail disabled", Description: "AWS CloudTrail is not enabled, missing API call audit logging.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`(?i)enable_logging\s*=\s*false`)},
		{ID: "TF013", Title: "RDS without deletion protection", Description: "RDS instance lacks deletion protection, risking accidental data loss.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`(?i)deletion_protection\s*=\s*false`)},
		{ID: "TF014", Title: "RDS storage unencrypted", Description: "RDS instance has storage encryption disabled.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`(?i)storage_encrypted\s*=\s*false`)},
		{ID: "TF015", Title: "EBS volume unencrypted", Description: "EBS volume has encryption disabled.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`(?i)encrypted\s*=\s*false`)},
		{ID: "TF016", Title: "Security group allows all ports", Description: "Security group rule allows all ports (0-65535), exposing services unnecessarily.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`(?i)(from_port|to_port)\s*=\s*0\b`)},
		{ID: "TF017", Title: "IAM access key without expiry", Description: "IAM access key created without an expiry policy.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceLow, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`(?i)aws_iam_access_key\b`)},
		{ID: "TF018", Title: "Azure storage account public blob", Description: "Azure storage account allows public blob access.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`(?i)allow_blob_public_access\s*=\s*true`)},
		{ID: "TF019", Title: "Azure network security group open RDP", Description: "Azure NSG allows RDP (port 3389) from internet.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`(?i)destination_port_range\s*=\s*["']?3389["']?`)},
		{ID: "TF020", Title: "GCP firewall rule allows all", Description: "GCP firewall rule allows traffic from 0.0.0.0/0 on all ports.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`(?i)source_ranges\s*=\s*\[.*0\.0\.0\.0/0`)},
		{ID: "TF021", Title: "KMS key rotation disabled", Description: "KMS key does not have automatic rotation enabled.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`(?i)enable_key_rotation\s*=\s*false`)},
		{ID: "TF022", Title: "DynamoDB table without PITR", Description: "DynamoDB table does not have point-in-time recovery enabled.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`(?i)point_in_time_recovery\s*=\s*false`)},
		{ID: "TF023", Title: "Lambda function without VPC", Description: "Lambda function is not configured within a VPC, limiting network security controls.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceLow, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`(?i)aws_lambda_function\b`)},
		{ID: "TF024", Title: "SNS topic public access", Description: "SNS topic policy allows access from all principals (*).", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`(?i)"Principal"\s*:\s*["']\*["']`), SkipQuoteFilter: true},
		{ID: "TF025", Title: "Container with privileged mode", Description: "Container definition runs in privileged mode, granting host access.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`(?i)privileged\s*=\s*true`)},

		// --- API security rules (API001-API010) ---
		{ID: "API001", Title: "GraphQL introspection enabled in production", Description: "GraphQL introspection can expose the entire schema to attackers.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript, LangPython}, Pattern: regexp.MustCompile(`(?i)introspection:\s*true`)},
		{ID: "API003", Title: "CORS wildcard in API config", Description: "CORS allows all origins (*), which can enable cross-site attacks.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript, LangPython, LangRuby, LangPHP}, Pattern: regexp.MustCompile(`(?i)(origins|origin|Access-Control-Allow-Origin)\s*[=:]\s*["']\*["']`)},
		{ID: "API005", Title: "JWT without expiry", Description: "JWT token does not set an expiration, increasing the risk of token theft.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript, LangPython, LangRuby, LangPHP, LangJava}, Pattern: regexp.MustCompile(`(?i)expiresIn\s*:\s*0|exp\s*:\s*0|noExpiry|neverExpires`)},
		{ID: "API006", Title: "API key in URL parameter", Description: "API key passed as a URL parameter can be logged in access logs and browser history.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangGeneric}, Pattern: regexp.MustCompile(`(?i)(api_key|apikey|access_token)\s*=\s*[{]?\w+[}]?`)},
		{ID: "API007", Title: "Insecure HTTP for API calls", Description: "API calls over HTTP transmit data unencrypted.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript, LangPython, LangRuby, LangPHP, LangJava}, Pattern: regexp.MustCompile(`http://[a-zA-Z0-9]`)},
		{ID: "API010", Title: "gRPC without TLS", Description: "gRPC server configured without TLS transmits data in plaintext.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangGeneric}, Pattern: regexp.MustCompile(`(?i)useTransportSecurity\s*=\s*false|grpc\.Insecure`)},

		// --- CWE-tagged rules for benchmark recall (CWE-89, CWE-22, CWE-352, CWE-94, CWE-601, CWE-918) ---

		// PHP SQL injection via mysqli_query with variable interpolation (CWE-89)
		{ID: "PHP009", Title: "PHP SQL injection via mysqli_query with variable", Description: "mysqli_query with a query string containing interpolated variables is vulnerable to SQL injection. Use prepared statements with mysqli_stmt_bind_param().", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)mysqli_query\s*\([^,]+,\s*["'].*\$\w+`), CWEID: "CWE-89", SkipQuoteFilter: true, SuppressFunc: phpHasSanitization},
		{ID: "PHP010", Title: "PHP SQL injection via PDO query with variable", Description: "PDO::query() with a query string containing interpolated variables is vulnerable to SQL injection. Use prepared statements with prepare() and execute().", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)->query\s*\(\s*["'].*\$\w+`), CWEID: "CWE-89", SkipQuoteFilter: true, SuppressFunc: phpHasSanitization},
		{ID: "PHP011", Title: "PHP SQL injection via string concatenation in query", Description: "SQL query built with string concatenation (.) and user input is vulnerable to SQL injection. Use prepared statements.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b.*["'].*\.\s*\$\w+`), CWEID: "CWE-89", SkipQuoteFilter: true, SuppressFunc: phpHasSanitization},
		// PHP SQL injection via variable interpolation in query string (CWE-89)
		{ID: "PHP016", Title: "PHP SQL injection via variable interpolation in query", Description: "SQL query string with interpolated PHP variables ($var) is vulnerable to SQL injection. Use prepared statements with parameter binding.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)["'].*\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|INTO)\b.*\$\w+.*["']`), CWEID: "CWE-89", SkipQuoteFilter: true, SuppressFunc: phpHasSanitization},

		// PHP path traversal via include/require with $_GET/$_POST (CWE-22)
		{ID: "PHP012", Title: "PHP path traversal via include with superglobal", Description: "include/require with $_GET/$_POST/$_REQUEST allows path traversal and LFI/RFI. Use a whitelist of allowed files.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)(include|require)(_once)?\s*\(?\s*\$_(GET|POST|REQUEST|SERVER)`), CWEID: "CWE-22"},
		{ID: "PHP013", Title: "PHP path traversal via file operations with superglobal", Description: "file_get_contents/fopen/readfile with $_GET/$_POST/$_REQUEST allows path traversal. Validate and canonicalize paths.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)(file_get_contents|fopen|readfile|file)\s*\(\s*\$_(GET|POST|REQUEST)`), CWEID: "CWE-22"},

		// PHP CSRF: state-changing GET request with database write (CWE-352)
		{ID: "PHP014", Title: "PHP CSRF via GET request with state change", Description: "State-changing operation (UPDATE/INSERT/DELETE) triggered by $_GET without CSRF token validation. Use POST with CSRF tokens.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)\$_GET\s*\[.*['"]?(Change|Update|Delete|Submit|Action)['"]?\]`), CWEID: "CWE-352"},
		{ID: "PHP015", Title: "PHP CSRF: password change via GET without token", Description: "Password change operation via GET request without CSRF token. Use POST with CSRF token validation.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)\$_GET\s*\[.*password`), CWEID: "CWE-352"},

		// PHP SSRF via file_get_contents/curl with user input (CWE-918)
		{ID: "PHP019", Title: "PHP SSRF via file_get_contents with user input", Description: "file_get_contents() with user-controlled input can fetch remote URLs (SSRF) or local files (LFI). Validate and restrict URLs.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)file_get_contents\s*\(\s*\$\w+`), CWEID: "CWE-918"},
		{ID: "PHP020", Title: "PHP SSRF via curl_exec with user input", Description: "curl_exec() with a user-controlled URL allows SSRF. Validate and restrict destination URLs.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$\w+`), CWEID: "CWE-918"},

		// PHP LDAP injection (CWE-90)
		{ID: "PHP021", Title: "PHP LDAP injection via ldap_search with user input", Description: "ldap_search() with user-controlled filter allows LDAP injection. Use ldap_escape() on user input.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)ldap_search\s*\([^)]*\$\w+`), CWEID: "CWE-90"},

		// PHP XPath injection (CWE-643)
		{ID: "PHP022", Title: "PHP XPath injection via DOMXPath with user input", Description: "XPath query with user-controlled input allows XPath injection. Use parameterized XPath queries.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)->(query|xpath)\s*\(\s*["'].*\$\w+`), CWEID: "CWE-643", SkipQuoteFilter: true},
		{ID: "PHP022b", Title: "PHP XPath injection via DOMXPath with variable", Description: "XPath query with a variable that may contain user input allows XPath injection. Use parameterized XPath queries.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)->(query|xpath)\s*\(\s*\$\w+\s*\)`), CWEID: "CWE-643"},

		// PHP file inclusion (CWE-98) — include/require with variable
		{ID: "PHP023", Title: "PHP file inclusion via include/require with variable", Description: "include/require with a variable allows Local/Remote File Inclusion. Use a whitelist of allowed files.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)(include|require)(_once)?\s*\(?\s*\$\w+`), CWEID: "CWE-98"},

		// PHP XPath injection via xpath() method (CWE-643)
		{ID: "PHP024", Title: "PHP XPath injection via xpath() with user input", Description: "SimpleXMLElement xpath() with user-controlled input allows XPath injection. Use parameterized XPath queries.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)->xpath\s*\(\s*["'].*\$`), CWEID: "CWE-643", SkipQuoteFilter: true},

		// Java SQL injection via Statement.executeQuery with concatenation (CWE-89)
		{ID: "JAVA011", Title: "Java SQL injection via executeQuery with concatenation", Description: "Statement.executeQuery() with a query built via string concatenation is vulnerable to SQL injection. Use PreparedStatement with parameter placeholders.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)executeQuery\s*\(\s*["'].*\+\s*\w+`), CWEID: "CWE-89", SkipQuoteFilter: true},
		{ID: "JAVA012", Title: "Java SQL injection via executeUpdate with concatenation", Description: "Statement.executeUpdate() with a query built via string concatenation is vulnerable to SQL injection. Use PreparedStatement.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)executeUpdate\s*\(\s*["'].*\+\s*\w+`), CWEID: "CWE-89", SkipQuoteFilter: true},
		{ID: "JAVA013", Title: "Java SQL injection via createStatement and string concat", Description: "createStatement() followed by a query with string concatenation (+) is vulnerable to SQL injection. Use PreparedStatement.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)createStatement\s*\([^)]*\)\s*\.execute(Query|Update)\s*\(\s*["'].*\+\s*`), CWEID: "CWE-89", SkipQuoteFilter: true},

		// Java path traversal via new File with request parameter (CWE-22)
		{ID: "JAVA014", Title: "Java path traversal via File constructor with user input", Description: "new File() with user-controlled input from request.getParameter() or @RequestParam allows path traversal. Validate and canonicalize paths.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)new\s+File\s*\([^)]*(request\.getParameter|@RequestParam|getParameter)`), CWEID: "CWE-22"},
		{ID: "JAVA015", Title: "Java zip-slip via ZipEntry.getName in File constructor", Description: "new File(dir, zipEntry.getName()) without canonical path validation allows zip-slip path traversal. Validate entry names against the target directory.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)new\s+File\s*\([^)]*(ZipEntry|zipEntry|entry)\.getName\(\)`), CWEID: "CWE-22"},
		{ID: "JAVA016", Title: "Java path traversal via FileInputStream with user input", Description: "FileInputStream with user-controlled path allows path traversal. Validate and canonicalize paths before opening.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)new\s+FileInputStream\s*\([^)]*(request\.getParameter|@RequestParam|getParameter)`), CWEID: "CWE-22"},

		// Ruby path traversal and code injection (CWE-22, CWE-94)
		{ID: "RB009", Title: "Ruby path traversal via File.open with params", Description: "File.open with user-controlled params allows path traversal. Validate and restrict file paths.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)File\.open\s*\(.*\bparams\b`), CWEID: "CWE-22"},
		{ID: "RB010", Title: "Ruby code injection via params.constantize", Description: "params[:...].constantize allows arbitrary class instantiation, leading to code execution. Avoid dynamic constant resolution with user input.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)params\[.*\]\.classify\.constantize|params\[.*\]\.constantize`), CWEID: "CWE-94"},

		// JS NoSQL injection via $where with template literal (CWE-89)
		{ID: "JS021", Title: "NoSQL injection via $where with template literal", Description: "MongoDB $where operator with template literal interpolation allows JavaScript injection into the query. Use proper query operators instead of $where.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`\$where\s*:\s*` + "`" + `.*\$\{`), CWEID: "CWE-89", SkipQuoteFilter: true},
		{ID: "JS022", Title: "NoSQL injection via $where with string concatenation", Description: "MongoDB $where operator with string concatenation allows JavaScript injection. Use proper query operators.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`\$where\s*:\s*["'].*\+\s*\w+`), CWEID: "CWE-89", SkipQuoteFilter: true},

		// JS open redirect (CWE-601)
		{ID: "JS023", Title: "Open redirect via res.redirect with user input", Description: "res.redirect with user-controlled input from req.query/req.params allows open redirect attacks. Validate URLs against a whitelist.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)res\.redirect\s*\(\s*.*\breq\.(query|params|body)`), CWEID: "CWE-601"},

		// JS SSRF via needle/axios/fetch with user-controlled URL (CWE-918)
		{ID: "JS024", Title: "SSRF via HTTP request with user-controlled URL", Description: "HTTP request (needle/axios/fetch/http.get) with user-controlled URL allows SSRF. Validate and restrict destination URLs.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)(needle|axios|fetch|http\.get|https\.get|request)\s*\(\s*.*\breq\.(query|params|body)`), CWEID: "CWE-918"},

		// JS eval with req.body — more specific than JS001 (CWE-94)
		{ID: "JS025", Title: "Server-side JavaScript injection via eval with user input", Description: "eval() with user-controlled input from req.body/req.query allows arbitrary code execution. Use parseInt/JSON.parse instead.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)\beval\s*\(\s*.*\breq\.(body|query|params)`), CWEID: "CWE-94"},

		// JS XSS via res.write with external body (CWE-79)
		{ID: "JS026", Title: "XSS via res.write with unescaped content", Description: "res.write with unescaped external content can lead to XSS. Sanitize and encode output before writing to response.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)res\.write\s*\(\s*(body|data|content|html|text)\b`), CWEID: "CWE-79"},

		// JS autoescape disabled (CWE-79)
		{ID: "JS027", Title: "Template autoescape disabled", Description: "Disabling autoescaping in template engines (swig, nunjucks, ejs) allows XSS. Keep autoescaping enabled.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)autoescape\s*:\s*false`), CWEID: "CWE-79", SkipQuoteFilter: true},

		// --- Java SQL injection: string concatenation in query literals (CWE-89) ---

		// SQL query string built with + concatenation and user input variable
		{ID: "JAVA017", Title: "Java SQL injection via string concatenation in query", Description: "SQL query string built with string concatenation (+) and user-controlled variables is vulnerable to SQL injection. Use PreparedStatement with parameter placeholders (?).", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)"[^"]*\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|INTO|VALUES|LIKE|ORDER|BY)\b[^"]*"\s*\+\s*\w+`), CWEID: "CWE-89", SkipQuoteFilter: true},
		// executeQuery/executeUpdate with a bare variable (query built elsewhere with concatenation)
		{ID: "JAVA018", Title: "Java SQL execution with variable query", Description: "executeQuery/executeUpdate with a variable query that may be built with string concatenation. Verify the query is parameterized.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)\b(executeQuery|executeUpdate)\s*\(\s*[a-zA-Z_]\w*\s*\)`), CWEID: "CWE-89"},
		// prepareStatement with string concatenation (partial parameterization)
		{ID: "JAVA019", Title: "Java SQL injection via prepareStatement with concatenation", Description: "prepareStatement with string concatenation (+) is vulnerable to SQL injection even if some placeholders are used. Use placeholders for all user input.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)prepareStatement\s*\([^)]*"\s*\+\s*\w+`), CWEID: "CWE-89", SkipQuoteFilter: true},

		// --- Java path traversal: new File with user-controlled variable (CWE-22) ---

		// new File(dir, variable) — second arg is user-controlled filename
		{ID: "JAVA020", Title: "Java path traversal via new File with variable", Description: "new File with a user-controlled variable as the filename/path argument allows path traversal. Validate and canonicalize paths.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)new\s+File\s*\([^,]+,\s*[a-zA-Z_]\w*\s*\)`), CWEID: "CWE-22"},
		// new File with string concatenation in path argument
		{ID: "JAVA021", Title: "Java path traversal via new File with concatenation", Description: "new File with string concatenation in the path argument allows path traversal. Validate and canonicalize paths.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)new\s+File\s*\([^)]*"\s*\+\s*\w+`), CWEID: "CWE-22", SkipQuoteFilter: true},
		// new File(dir, entry.getName()) — zip-slip via ZipEntry.getName()
		{ID: "JAVA022", Title: "Java zip-slip via ZipEntry.getName in File constructor", Description: "new File(dir, zipEntry.getName()) without canonical path validation allows zip-slip path traversal. Validate entry names against the target directory.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)new\s+File\s*\([^,]+,\s*\w+\.getName\(\)\)`), CWEID: "CWE-22"},

		// Java SSRF via URL.openConnection / HttpURLConnection (CWE-918)
		{ID: "JAVA023", Title: "Java SSRF via URL.openConnection", Description: "URL.openConnection() can connect to arbitrary URLs. If the URL is user-controlled, this allows SSRF. Validate and restrict destination URLs.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)\.openConnection\s*\(\s*\)`), CWEID: "CWE-918"},
		{ID: "JAVA024", Title: "Java SSRF via RestTemplate with variable URL", Description: "RestTemplate exchange/getForObject with a variable URL allows SSRF if the URL is user-controlled. Validate and restrict destination URLs.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)restTemplate\s*\.\s*(exchange|getForObject|getForEntity|postForObject)\s*\(\s*\w+`), CWEID: "CWE-918"},

		// Java weak hash (CWE-328)
		{ID: "JAVA025", Title: "Java weak hash algorithm MD5/SHA1", Description: "MD5 or SHA1 hash algorithm is cryptographically weak. Use SHA-256 or stronger for security-sensitive operations.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-?1)["']`), CWEID: "CWE-328"},

		// Java weak random (CWE-330)
		{ID: "JAVA026", Title: "Java weak random number generator", Description: "java.util.Random is not cryptographically secure. Use SecureRandom for security-sensitive tokens, keys, or session IDs.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)\bnew\s+Random\s*\(`), CWEID: "CWE-330"},

		// Java XPath injection (CWE-643)
		{ID: "JAVA027", Title: "Java XPath injection via XPath.evaluate with user input", Description: "XPath.evaluate() with user-controlled expression allows XPath injection. Use parameterized XPath or validate input.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)xpath\s*\.\s*evaluate\s*\(\s*.*\+`), CWEID: "CWE-643", SkipQuoteFilter: true},

		// Java LDAP injection (CWE-90)
		{ID: "JAVA028", Title: "Java LDAP injection via DirContext.search with user input", Description: "DirContext.search() with user-controlled filter allows LDAP injection. Use proper escaping of user input in LDAP filters.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)(DirContext|InitialDirContext|LdapContext).*\.search\s*\(|\.search\s*\(\s*\w+\s*,\s*[^)]*filter`), CWEID: "CWE-90", SkipQuoteFilter: true},
		// Java unsigned JWT (PlainJWT) — CWE-287
		{ID: "JAVA029", Title: "Java unsigned JWT (PlainJWT)", Description: "Using PlainJWT creates unsigned tokens that can be forged. Use SignedJWT with a strong algorithm (RS256) and proper key management.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)PlainJWT`), CWEID: "CWE-287"},
		// Java XPath injection via evaluate with concatenation (CWE-643)
		{ID: "JAVA030", Title: "Java XPath injection via evaluate with concatenation", Description: "XPath.evaluate() with a query built via string concatenation is vulnerable to XPath injection. Use parameterized XPath expressions.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)\.evaluate\s*\(\s*[a-zA-Z_]\w*\s*,`), CWEID: "CWE-643"},
		// Java XPath injection via compile with concatenation (CWE-643)
		{ID: "JAVA031", Title: "Java XPath injection via compile with concatenation", Description: "XPath.compile() with a query built via string concatenation is vulnerable to XPath injection. Use parameterized XPath expressions.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)\.compile\s*\(\s*["'].*\+\s*\w+`), CWEID: "CWE-643", SkipQuoteFilter: true},

		// --- Ruby SQL injection: where/select with string interpolation (CWE-89) ---

		// where("... #{params[...]} ...") — string interpolation in where clause
		{ID: "RB011", Title: "Ruby SQL injection via where with params interpolation", Description: "ActiveRecord where() with string interpolation of params allows SQL injection. Use parameterized queries: where(field: params[:field]).", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)\.where\s*\(\s*["'].*#\{.*params`), CWEID: "CWE-89", SkipQuoteFilter: true},
		// select("#{col}") — string interpolation in select clause
		{ID: "RB012", Title: "Ruby SQL injection via select with interpolation", Description: "ActiveRecord select() with string interpolation allows SQL injection in the SELECT clause. Use parameterized queries or whitelist allowed columns.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)\bselect\s*\(\s*["'].*#\{`), CWEID: "CWE-89", SkipQuoteFilter: true},
		// order("... #{params[...]} ...") — string interpolation in order clause
		{ID: "RB013", Title: "Ruby SQL injection via order with interpolation", Description: "ActiveRecord order() with string interpolation of params allows SQL injection. Use whitelist of allowed column names.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)\border\s*\(\s*["'].*#\{.*params`), CWEID: "CWE-89", SkipQuoteFilter: true},

		// --- Ruby path traversal and code injection (CWE-22, CWE-94) ---

		// File.open with interpolated filename
		{ID: "RB014", Title: "Ruby path traversal via File.open with interpolation", Description: "File.open with interpolated filename (#{...}) allows path traversal if the interpolated value is user-controlled. Validate and sanitize filenames.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)File\.open\s*\(\s*["'].*#\{`), CWEID: "CWE-22", SkipQuoteFilter: true},
		// send_file with a variable (path may be user-controlled)
		{ID: "RB016", Title: "Ruby path traversal via send_file with variable", Description: "send_file with a variable that may be user-controlled allows path traversal or arbitrary file download. Validate and restrict file paths.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)send_file\s+\w+`), CWEID: "CWE-22"},
		// params[...].constantize — arbitrary class instantiation
		{ID: "RB015", Title: "Ruby code injection via params.constantize", Description: "params[:...].constantize allows arbitrary class instantiation and code execution. Avoid dynamic constant resolution with user input.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)params\[.*\]\.constantize`), CWEID: "CWE-94"},

		// --- Python XSS: Flask render_template with user input (CWE-79) ---

		// render_template_string with a variable (not a string literal) as first arg —
		// the template source is dynamic, which means it may contain user input.
		{ID: "PY028", Title: "Flask render_template_string with dynamic template", Description: "render_template_string with a variable template source can lead to XSS if the template contains user input. Use render_template with auto-escaping instead.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)render_template_string\s*\(\s*[a-zA-Z_]\w*\s*[,)]`), CWEID: "CWE-79"},
		// render_template with request.* in arguments
		{ID: "PY029", Title: "Flask render_template with user input", Description: "render_template with user-controlled input from request object may lead to XSS if auto-escaping is disabled. Ensure auto-escaping is enabled.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)render_template\s*\([^)]*request\.`), CWEID: "CWE-79", SkipQuoteFilter: true},

		// Python SSRF via requests with user input (CWE-918)
		{ID: "PY041", Title: "Python SSRF via requests with request data", Description: "requests.get/post/put/delete with user-controlled input from request.data/request.json/request.form allows SSRF. Validate and restrict destination URLs.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)requests\.(get|post|put|delete|head|patch)\s*\([^)]*request\.(data|json|form|GET|POST|args)`), CWEID: "CWE-918", SkipQuoteFilter: true},
		{ID: "PY042", Title: "Python SSRF via os.popen/subprocess with curl", Description: "os.popen or subprocess with curl command and user-controlled URL allows SSRF. Use requests library with URL validation instead.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)(os\.popen|subprocess\.(call|run|Popen|check_output))\s*\([^)]*curl`), CWEID: "CWE-918", SkipQuoteFilter: true},
		// Python command execution via os.popen with variable (CWE-78)
		{ID: "PY042b", Title: "Python command injection via os.popen with variable", Description: "os.popen() with a variable argument allows command injection if the variable contains user input. Use subprocess with shell=False and argument arrays.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`os\.popen\s*\(\s*[a-zA-Z_]\w*\s*\)`), CWEID: "CWE-78"},
		// Python SSRF via helper function with curl (CWE-918)
		{ID: "PY042c", Title: "Python SSRF via curl command with user input", Description: "Executing curl with user-controlled URL allows SSRF. Validate and restrict destination URLs before making requests.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)(run_cmd|popen|system|subprocess)\s*\([^)]*curl\s+[^)]*\{`), CWEID: "CWE-918", SkipQuoteFilter: true},

		// Python weak hash MD5/SHA1 (CWE-328)
		{ID: "PY043", Title: "Python weak hash algorithm MD5/SHA1", Description: "MD5 or SHA1 hash algorithm is cryptographically weak. Use hashlib.sha256() or stronger for security-sensitive operations.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)hashlib\.(md5|sha1)\s*\(`), CWEID: "CWE-328"},

		// Python weak random (CWE-330)
		{ID: "PY044", Title: "Python weak random for security context", Description: "random module is not cryptographically secure. Use secrets module for tokens, session IDs, or passwords.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)\brandom\.(choice|randint|random)\s*\(`), CWEID: "CWE-330"},

		// Python hardcoded credentials (CWE-798)
		{ID: "PY045", Title: "Python hardcoded password/secret", Description: "Hardcoded password or secret key detected. Use environment variables or a secret manager.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)\b(password|passwd|secret|api_key|apikey|access_token|auth_token|session_token|refresh_token|private_key)\b\s*=\s*['"][^'"]{4,}['"]`), CWEID: "CWE-798", SuppressFunc: suppressPY045},

		// Python SQL injection via SQLAlchemy text() with string formatting (CWE-89)
		{ID: "PY046", Title: "SQL injection via SQLAlchemy text() with formatting", Description: "SQLAlchemy text() with string formatting (% or f-string) allows SQL injection. Use parameterized queries with text() and bind parameters.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)\btext\s*\(\s*["'].*%s.*["']\s*%`), CWEID: "CWE-89", SkipQuoteFilter: true},

		// Python auth bypass: plaintext password comparison (CWE-287)
		{ID: "PY047", Title: "Authentication with plaintext password comparison", Description: "filter_by(password=...) or filter(password == ...) suggests plaintext password comparison. Use password hashing (bcrypt, argon2).", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)filter_by\s*\([^)]*password\s*=`), CWEID: "CWE-287"},

		// Python JWT verification disabled (CWE-287)
		{ID: "PY048", Title: "JWT verification disabled", Description: "JWT verification with verify_signature:False disables signature validation, allowing token forgery. Always verify JWT signatures.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)verify_signature\s*:\s*False`), CWEID: "CWE-287"},

		// Python access control via cookie value (CWE-284)
		{ID: "PY049", Title: "Access control via client-controlled cookie", Description: "Authorization check based on cookie value is client-controllable and can be bypassed. Use server-side session validation.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`request\.cookies\.get\s*\([^)]+\)\s*==\s*["']`), CWEID: "CWE-284"},

		// --- JS/TS insecure randomness: Math.random() (CWE-611) ---

		{ID: "JS028", Title: "Insecure random number generation via Math.random", Description: "Math.random() is not cryptographically secure. Use crypto.randomBytes() or crypto.getRandomValues() for security-sensitive values like tokens, session IDs, or passwords.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`Math\.random\s*\(`), CWEID: "CWE-611"},

		// --- JS/TS Angular XSS: bypassSecurityTrustHtml (CWE-79) ---

		{ID: "JS029", Title: "Angular XSS via bypassSecurityTrustHtml", Description: "bypassSecurityTrustHtml bypasses Angular's built-in XSS protection, allowing injection of untrusted HTML. Avoid using bypassSecurityTrustHtml with user-controlled data.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`bypassSecurityTrust(Html|Script|Style|Url)\s*\(`), CWEID: "CWE-79"},

		// --- JS/TS insufficiently protected credentials (CWE-522) ---

		// MD5 used for password/credential hashing
		{ID: "JS030", Title: "Weak password hashing with MD5", Description: "MD5 is cryptographically broken and should not be used for password hashing. Use bcrypt, scrypt, or Argon2 for password storage.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)createHash\s*\(\s*['"]md5['"]\s*\)`), CWEID: "CWE-522"},
		// SHA1 used for password/credential hashing
		{ID: "JS031", Title: "Weak password hashing with SHA1", Description: "SHA1 is cryptographically broken and should not be used for password hashing. Use bcrypt, scrypt, or Argon2 for password storage.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)createHash\s*\(\s*['"]sha1['"]\s*\)`), CWEID: "CWE-522"},
		// Auth tokens stored in localStorage
		{ID: "JS032", Title: "Authentication token stored in localStorage", Description: "Storing authentication tokens in localStorage exposes them to XSS attacks. Use httpOnly cookies for session tokens.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)localStorage\.setItem\s*\(\s*['"]token['"]`), CWEID: "CWE-522"},
		// Hardcoded HMAC secret
		{ID: "JS033", Title: "Hardcoded HMAC secret key", Description: "Hardcoding HMAC secret keys in source code exposes credentials. Use environment variables or a secrets manager.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)createHmac\s*\([^,]+,\s*['"][^'"]{4,}['"]\s*\)`), CWEID: "CWE-522"},
		// Hardcoded RSA private key
		{ID: "JS034", Title: "Hardcoded RSA private key", Description: "Hardcoding RSA private keys in source code exposes credentials. Use environment variables or a secrets manager.", Severity: analysis.SeverityCritical, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----`), CWEID: "CWE-522"},

		// JS/TS command injection via exec/spawn with user input (CWE-78)
		{ID: "JS035", Title: "Command injection via exec with user input", Description: "child_process.exec with user-controlled input from req.query/req.body/req.params allows command injection. Validate and sanitize input.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)(exec|execSync)\s*\(\s*.*\breq\.(query|body|params)`), CWEID: "CWE-78"},
		{ID: "JS036", Title: "Command injection via exec with template literal", Description: "child_process.exec with template literal containing variables allows command injection if variables are user-controlled. Use execFile with argument arrays.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)(exec|execSync)\s*\(\s*` + "`" + `[^` + "`" + `]*\$\{`), CWEID: "CWE-78", SkipQuoteFilter: true},

		// JS/TS SSRF via fetch/axios/http with request body (CWE-918)
		{ID: "JS037", Title: "SSRF via fetch with user-controlled URL", Description: "fetch() with user-controlled URL from req.body/req.query allows SSRF. Validate and restrict destination URLs.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)\bfetch\s*\(\s*.*\breq\.(body|query|params)`), CWEID: "CWE-918"},

		// JS/TS hardcoded credentials (CWE-798)
		{ID: "JS038", Title: "Hardcoded password/secret in source", Description: "Hardcoded password, secret, or API key detected. Use environment variables or a secrets manager.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)(password|passwd|secret|api_key|apikey|apiKey)\s*[:=]\s*['"][^'"]{4,}['"]`), CWEID: "CWE-798", SuppressFunc: suppressUISecretLabel},

		// JS/TS weak hash MD5/SHA1 (CWE-328)
		{ID: "JS039", Title: "Weak hash algorithm MD5/SHA1", Description: "MD5 or SHA1 hash algorithm is cryptographically weak. Use SHA-256 or stronger for security-sensitive operations.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)createHash\s*\(\s*['"](md5|sha1)['"]\s*\)`), CWEID: "CWE-328"},

		// JS/TS NoSQL injection via where with string (CWE-89)
		{ID: "JS040", Title: "NoSQL injection via $where with string concatenation", Description: "MongoDB $where with string concatenation allows JavaScript injection in the database. Use proper query operators.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`\$where\s*:\s*["'].*\+\s*\w+`), CWEID: "CWE-89", SkipQuoteFilter: true},

		// JS/TS command injection via exec with string concatenation (CWE-78)
		{ID: "JS041", Title: "Command injection via exec with string concatenation", Description: "child_process.exec with string concatenation (+) allows command injection if variables are user-controlled. Use execFile with argument arrays.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)\bexec\s*\(\s*["'].*\+\s*\w+`), CWEID: "CWE-78", SkipQuoteFilter: true},

		// JS/TS SQL injection via string concatenation (CWE-89)
		{ID: "JS042", Title: "SQL injection via string concatenation in query", Description: "SQL query built with string concatenation (+) is vulnerable to SQL injection. Use parameterized queries with placeholders.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)["'].*\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b.*["'].*\+\s*\w+`), CWEID: "CWE-89", SkipQuoteFilter: true, SuppressFunc: suppressJS042},

		// ============ P1 RULES: CWE coverage expansion ============

		// --- CWE-79: XSS (Cross-Site Scripting) ---

		// C# ASP.NET: Html.Raw bypasses Razor auto-encoding
		{ID: "CS029", Title: "XSS via Html.Raw with user input", Description: "Html.Raw() renders content without HTML encoding, allowing XSS. Avoid Html.Raw with user-controlled data. Use @Model directly which auto-encodes.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)Html\.Raw\s*\(`), CWEID: "CWE-79"},
		// C# ASP.NET: Response.Write with variable
		{ID: "CS030", Title: "XSS via Response.Write with variable", Description: "Response.Write with a variable may output unescaped content leading to XSS. Use HTML encoding (HttpUtility.HtmlEncode) before writing to response.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)Response\.Write\s*\(\s*[a-zA-Z_]`), CWEID: "CWE-79"},
		// C# ASP.NET: innerHTML assignment
		{ID: "CS031", Title: "DOM XSS via innerHTML assignment", Description: "Setting innerHTML with user-controlled content allows DOM-based XSS. Use textContent or innerText instead, or sanitize the input.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)\.innerHTML\s*=\s*[^"']`), CWEID: "CWE-79"},

		// Ruby/Rails: .html_safe bypasses ERB auto-escaping
		{ID: "RB028", Title: "XSS via html_safe in Rails template", Description: "Calling .html_safe on user-controlled content bypasses Rails' auto-escaping, allowing XSS. Avoid html_safe with user input.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`\.html_safe\b`), CWEID: "CWE-79"},
		// Ruby/Rails: raw helper in ERB
		{ID: "RB029", Title: "XSS via raw helper in Rails template", Description: "Using raw() in ERB templates bypasses HTML escaping, allowing XSS. Avoid raw with user-controlled content.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)\braw\s*\(`), CWEID: "CWE-79"},
		// Ruby/Rails: content_tag with html_safe
		{ID: "RB030", Title: "XSS via content_tag with unescaped content", Description: "content_tag with html_safe content may allow XSS if the content is user-controlled. Ensure content is sanitized before marking as html_safe.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)content_tag.*\.html_safe`), CWEID: "CWE-79"},

		// Java/JSP: <%= request.getParameter() %>
		{ID: "JAVA032", Title: "XSS via JSP scriptlet with request parameter", Description: "Using <%= request.getParameter() %> outputs user input without HTML encoding, allowing XSS. Use <c:out value=\"${param.name}\"/> which escapes XML by default.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`<%=\s*request\.getParameter`), CWEID: "CWE-79"},
		// Java/JSP: <%= request.getAttribute() %>
		{ID: "JAVA033", Title: "XSS via JSP scriptlet with request attribute", Description: "Using <%= request.getAttribute() %> outputs data without HTML encoding. Use JSTL <c:out> tag which escapes XML by default.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`<%=\s*request\.getAttribute`), CWEID: "CWE-79"},
		// Java/Struts2: escape="false" on s:property
		{ID: "JAVA034", Title: "XSS via Struts2 property with escape disabled", Description: "Struts2 <s:property> with escape=\"false\" outputs content without HTML encoding, allowing XSS. Remove escape=\"false\" to enable default escaping.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)escape\s*=\s*["']false["']`), CWEID: "CWE-79"},
		// Java: PrintWriter/OutputStream with variable
		{ID: "JAVA035", Title: "XSS via PrintWriter with variable", Description: "PrintWriter.write/print with a variable may output unescaped content. Use HTML encoding before writing to the response.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)(PrintWriter|response\.getWriter)\s*\(\s*\).*\.write\s*\(\s*[a-zA-Z_]`), CWEID: "CWE-79"},

		// JS/TS: document.write with variable
		{ID: "JS043", Title: "DOM XSS via document.write with variable", Description: "document.write with a variable can lead to DOM-based XSS if the variable contains user input. Use textContent or innerText instead.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)document\.write\s*\(\s*[a-zA-Z_$]`), CWEID: "CWE-79"},
		// JS/TS: innerHTML assignment with variable
		{ID: "JS044", Title: "DOM XSS via innerHTML with variable", Description: "Setting innerHTML with a variable can lead to DOM-based XSS. Use textContent or innerText, or sanitize the input with DOMPurify.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)\.innerHTML\s*=\s*[a-zA-Z_$]`), CWEID: "CWE-79", SuppressFunc: suppressJS044},
		// JS/TS: dangerouslySetInnerHTML (React)
		{ID: "JS045", Title: "XSS via React dangerouslySetInnerHTML", Description: "dangerouslySetInnerHTML with user-controlled content allows XSS. Sanitize input with DOMPurify before setting dangerouslySetInnerHTML.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`dangerouslySetInnerHTML`), CWEID: "CWE-79"},

		// PHP: echo with $_GET/$_POST without htmlspecialchars
		{ID: "PHP025", Title: "XSS via echo with superglobal without encoding", Description: "Echoing $_GET/$_POST/$_REQUEST directly without htmlspecialchars() allows XSS. Use htmlspecialchars() to encode output.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)(echo|print)\s*\(?\s*\$_(GET|POST|REQUEST|COOKIE)`), CWEID: "CWE-79", SkipQuoteFilter: true},
		// PHP: printf with $_GET/$_POST
		{ID: "PHP026", Title: "XSS via printf with superglobal", Description: "printf/sprintf with $_GET/$_POST without htmlspecialchars() allows XSS. Encode output before printing.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)(printf|sprintf)\s*\([^)]*\$_(GET|POST|REQUEST)`), CWEID: "CWE-79"},

		// --- CWE-601: Open Redirect ---

		// C# ASP.NET: Response.Redirect with variable
		{ID: "CS032", Title: "Open redirect via Response.Redirect with variable", Description: "Response.Redirect with a user-controlled variable allows open redirect attacks. Validate URLs against a whitelist before redirecting.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)Response\.Redirect\s*\(\s*[a-zA-Z_]`), CWEID: "CWE-601"},
		// C# ASP.NET MVC: Redirect() helper with variable (not Response.Redirect)
		{ID: "CS028", Title: "Open redirect via Redirect() with variable", Description: "Redirect() with a user-controlled variable allows open redirect attacks. Validate URLs against a whitelist before redirecting.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)\breturn\s+Redirect\s*\(\s*[a-zA-Z_]`), CWEID: "CWE-601"},
		// C# ASP.NET: RedirectToAction with variable
		{ID: "CS033", Title: "Open redirect via RedirectToAction with variable", Description: "RedirectToAction with a user-controlled variable may allow open redirect. Validate the redirect target.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)RedirectToAction\s*\(\s*[a-zA-Z_]`), CWEID: "CWE-601"},
		// Java: response.sendRedirect with variable
		{ID: "JAVA036", Title: "Open redirect via sendRedirect with variable", Description: "response.sendRedirect with a user-controlled URL allows open redirect attacks. Validate URLs against a whitelist.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)sendRedirect\s*\(\s*[a-zA-Z_]`), CWEID: "CWE-601"},
		// Java: setHeader Location with variable
		{ID: "JAVA037", Title: "Open redirect via Location header with variable", Description: "Setting the Location header with a user-controlled variable allows open redirect. Validate the redirect URL.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)setHeader\s*\(\s*["']Location["']\s*,\s*[a-zA-Z_]`), CWEID: "CWE-601"},
		// Java Spring: ResponseEntity with Location header and FOUND status
		{ID: "JAVA048", Title: "Open redirect via Spring ResponseEntity with Location header", Description: "Setting the Location header on a ResponseEntity with HttpStatus.FOUND allows open redirect if the URL is user-controlled. Validate the redirect URL.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)(put|add)\s*\(\s*(LOCATION_HEADER|["']Location["'])`), CWEID: "CWE-601"},
		// Java: addHeader Location with variable
		{ID: "JAVA049", Title: "Open redirect via addHeader Location with variable", Description: "addHeader(\"Location\", ...) with a user-controlled URL allows open redirect. Validate the redirect URL.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)addHeader\s*\(\s*["']Location["']\s*,\s*[a-zA-Z_]`), CWEID: "CWE-601"},

		// --- CWE-862: Missing Authorization ---

		// Ruby/Rails: skip_before_action :authenticate
		{ID: "RB020", Title: "Missing authorization via skip_before_action", Description: "skip_before_action :authenticate_user! or :verify_user disables authentication for controller actions. Ensure proper authorization checks are in place.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)skip_before_action\s+:(authenticate|verify|authorize|check_auth)`), CWEID: "CWE-862"},
		// Ruby/Rails: skip_before_filter (older Rails)
		{ID: "RB021", Title: "Missing authorization via skip_before_filter", Description: "skip_before_filter disables authentication filters for controller actions. Ensure proper authorization checks are in place.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)skip_before_filter\s+:(authenticate|verify|authorize|check_auth)`), CWEID: "CWE-862"},
		// Ruby/Rails: only/except on controllers without auth check
		{ID: "RB022", Title: "Controller action without authentication", Description: "Controller with skip_before_action or no before_action :authenticate may expose actions without authorization. Add authentication filters.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)skip_before_action\s+:(require_login|authenticate_user|verify_user|authorize_user)`), CWEID: "CWE-862"},

		// --- CWE-502: Deserialization ---

		// C#: BinaryFormatter.Deserialize
		{ID: "CS034", Title: "Insecure deserialization via BinaryFormatter", Description: "BinaryFormatter.Deserialize can execute arbitrary code during deserialization. Use DataContractSerializer or JsonSerializer with type restrictions.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)new\s+BinaryFormatter\s*\(`), CWEID: "CWE-502"},
		// C#: XmlSerializer with Type.GetType
		{ID: "CS035", Title: "Insecure deserialization via XmlSerializer with dynamic type", Description: "XmlSerializer with Type.GetType() can lead to type confusion attacks. Use known type restrictions.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)XmlSerializer\s*\(\s*Type\.GetType`), CWEID: "CWE-502"},
		// C#: JsonConvert.DeserializeObject with type
		{ID: "CS036", Title: "Insecure deserialization via JsonConvert with type", Description: "JsonConvert.DeserializeObject with a Type parameter can lead to insecure deserialization if the type is user-controlled. Use typed deserialization.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)JsonConvert\.DeserializeObject.*Type\.GetType`), CWEID: "CWE-502"},
		// C#: LosFormatter
		{ID: "CS037", Title: "Insecure deserialization via LosFormatter", Description: "LosFormatter.Deserialize can execute arbitrary code. Use DataContractSerializer or JsonSerializer instead.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)LosFormatter\s*\(`), CWEID: "CWE-502"},
		// C#: ObjectStateFormatter
		{ID: "CS038", Title: "Insecure deserialization via ObjectStateFormatter", Description: "ObjectStateFormatter.Deserialize can execute arbitrary code. Use safer serialization formats.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)ObjectStateFormatter\s*\(`), CWEID: "CWE-502"},
		// PHP: unserialize with variable
		{ID: "PHP027", Title: "Insecure deserialization via unserialize with variable", Description: "unserialize() with user-controlled input can execute arbitrary code. Use json_decode() instead, or validate input before deserialization.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)\bunserialize\s*\(\s*\$\w+`), CWEID: "CWE-502"},
		// PHP: maybe_unserialize
		{ID: "PHP028", Title: "Insecure deserialization via maybe_unserialize", Description: "maybe_unserialize() with user-controlled input can lead to code execution. Validate input before deserialization.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)\bmaybe_unserialize\s*\(`), CWEID: "CWE-502"},

		// --- CWE-94: Code Injection (PHP) ---

		// PHP: eval with variable
		{ID: "PHP029", Title: "Code injection via eval with variable", Description: "eval() with user-controlled input executes arbitrary PHP code. Avoid eval() entirely.", Severity: analysis.SeverityCritical, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)\beval\s*\(\s*\$`), CWEID: "CWE-94"},
		// PHP: assert with variable (assert evaluates string as PHP code)
		{ID: "PHP030", Title: "Code injection via assert with variable", Description: "assert() with a string argument evaluates it as PHP code, allowing code injection. Use assert() with boolean expressions only.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)\bassert\s*\(\s*\$`), CWEID: "CWE-94"},
		// PHP: preg_replace with /e modifier (deprecated but dangerous)
		{ID: "PHP031", Title: "Code injection via preg_replace with /e modifier", Description: "preg_replace() with the /e modifier evaluates the replacement string as PHP code, allowing code injection. Use preg_replace_callback() instead.", Severity: analysis.SeverityCritical, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)preg_replace\s*\(\s*["'][^"']*\/[a-z]*e[a-z]*["']`), CWEID: "CWE-94"},
		// PHP: create_function (deprecated, eval-based)
		{ID: "PHP032", Title: "Code injection via create_function", Description: "create_function() uses eval() internally and is deprecated. Use anonymous functions (closures) instead.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)\bcreate_function\s*\(`), CWEID: "CWE-94"},
		// PHP: system/exec/passthru with variable (also CWE-78, but relevant to code injection)
		{ID: "PHP033", Title: "Code injection via call_user_func with variable", Description: "call_user_func() with a user-controlled function name allows arbitrary function execution. Validate the function name against an allowlist.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)call_user_func\s*\(\s*\$`), CWEID: "CWE-94"},
		// PHP: Smarty SSTI via fetch/display with variable template
		{ID: "PHP034", Title: "Server-side template injection via Smarty fetch/display", Description: "Smarty fetch() or display() with a user-controlled template name allows SSTI. Validate template names against an allowlist.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)\$\w*smarty\w*->(fetch|display)\s*\(\s*\$`), CWEID: "CWE-94"},
		// PHP: Smarty force_compile enables SSTI
		{ID: "PHP035", Title: "Smarty force_compile enables template injection", Description: "Smarty force_compile=true recompiles templates on every request, enabling server-side template injection if templates contain user input. Disable force_compile in production.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)force_compile\s*=\s*true`), CWEID: "CWE-94"},
		// PHP: fwrite to .tpl file with user input (template injection vector)
		{ID: "PHP036", Title: "Template injection via fwrite to template file", Description: "Writing user input to a .tpl template file enables server-side template injection. Sanitize input before writing to template files.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)fwrite\s*\([^,]+,\s*\$_(POST|GET|REQUEST|COOKIE)`), CWEID: "CWE-94"},
		// Java: XMLDecoder
		{ID: "JAVA038", Title: "Insecure deserialization via XMLDecoder", Description: "XMLDecoder.readObject can execute arbitrary code. Avoid XMLDecoder with untrusted input. Use JAXB with type restrictions.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)XMLDecoder\s*\(`), CWEID: "CWE-502"},
		// Java: Yaml().load (SnakeYAML)
		{ID: "JAVA039", Title: "Insecure deserialization via Yaml.load", Description: "SnakeYAML Yaml().load() can instantiate arbitrary classes. Use Yaml().loadAs() with a specific type to restrict deserialization.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)new\s+Yaml\s*\(\s*\)\s*\.load`), CWEID: "CWE-502"},

		// --- CWE-611: XXE (XML External Entity) ---

		// Java: DocumentBuilderFactory without disabling external entities
		{ID: "JAVA040", Title: "XXE via DocumentBuilderFactory without entity restriction", Description: "DocumentBuilderFactory without setFeature to disable external entities allows XXE attacks. Set disallow-doctype-decl to true and disable external entities.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)DocumentBuilderFactory\.newInstance`), CWEID: "CWE-611"},
		// Java: SAXParserFactory without disabling external entities
		{ID: "JAVA041", Title: "XXE via SAXParserFactory without entity restriction", Description: "SAXParserFactory without setFeature to disable external entities allows XXE attacks. Disable external entities and DTDs.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)SAXParserFactory\.newInstance`), CWEID: "CWE-611"},
		// Java: XMLInputFactory without disabling external entities
		{ID: "JAVA042", Title: "XXE via XMLInputFactory without entity restriction", Description: "XMLInputFactory without setProperty to disable external entities allows XXE attacks. Set IS_SUPPORTING_EXTERNAL_ENTITIES to false.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)XMLInputFactory\.newInstance`), CWEID: "CWE-611"},
		// Java: SAXReader (dom4j)
		{ID: "JAVA043", Title: "XXE via SAXReader without entity restriction", Description: "dom4j SAXReader without disabling external entities allows XXE attacks. Set disallow-doctype-decl to true.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)new\s+SAXReader\s*\(`), CWEID: "CWE-611"},
		// C#: XmlDocument.Load
		{ID: "CS039", Title: "XXE via XmlDocument.Load without XmlResolver restriction", Description: "XmlDocument.Load without setting XmlResolver to null allows XXE attacks. Set XmlResolver to null to disable external entity resolution.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)XmlDocument\s*\(\s*\).*\.Load\s*\(`), CWEID: "CWE-611"},
		// C#: XmlTextReader
		{ID: "CS040", Title: "XXE via XmlTextReader without entity restriction", Description: "XmlTextReader without setting XmlResolver to null allows XXE attacks. Set XmlResolver to null.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)new\s+XmlTextReader\s*\(`), CWEID: "CWE-611"},
		// C#: XmlReader.Create without secure settings
		{ID: "CS041", Title: "XXE via XmlReader.Create without secure settings", Description: "XmlReader.Create without DtdProcessing.Prohibit and XmlResolver set to null allows XXE attacks. Use secure XmlReaderSettings.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)XmlReader\.Create\s*\(`), CWEID: "CWE-611"},

		// --- CWE-918: SSRF (Server-Side Request Forgery) ---

		// C#: HttpClient.GetAsync/PostAsync with variable
		{ID: "CS042", Title: "SSRF via HttpClient with variable URL", Description: "HttpClient.GetAsync/PostAsync with a user-controlled URL allows SSRF. Validate and restrict destination URLs.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)HttpClient\s*\(\s*\).*\.(GetAsync|PostAsync|PutAsync|DeleteAsync|SendAsync)\s*\(\s*[a-zA-Z_$]`), CWEID: "CWE-918"},
		// C#: WebClient.DownloadString with variable
		{ID: "CS043", Title: "SSRF via WebClient with variable URL", Description: "WebClient.DownloadString/DownloadFile with a user-controlled URL allows SSRF. Validate and restrict destination URLs.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)WebClient\s*\(\s*\).*\.(DownloadString|DownloadFile|UploadString|UploadFile)\s*\(\s*[a-zA-Z_$]`), CWEID: "CWE-918"},
		// Java: URL constructor with variable
		{ID: "JAVA044", Title: "SSRF via URL constructor with variable", Description: "new URL() with a user-controlled variable allows SSRF. Validate and restrict destination URLs.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)new\s+URL\s*\(\s*[a-zA-Z_]`), CWEID: "CWE-918"},
		// Java: HttpClient.execute with variable
		{ID: "JAVA045", Title: "SSRF via HttpClient.execute with variable", Description: "HttpClient.execute with a user-controlled URI allows SSRF. Validate and restrict destination URLs.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)httpClient\s*\.\s*execute\s*\(\s*[a-zA-Z_]`), CWEID: "CWE-918"},

		// --- CWE-915: Mass Assignment ---

		// Ruby/Rails: permit! (allows all parameters)
		{ID: "RB023", Title: "Mass assignment via permit! in Rails", Description: "params.permit! allows all parameters to be mass-assigned, enabling mass assignment attacks. Use permit() with an explicit allowlist of parameters.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)params\.(require\s*\([^)]+\)\s*\.)?permit!`), CWEID: "CWE-915"},
		// Ruby/Rails: update_attributes with params
		{ID: "RB024", Title: "Mass assignment via update_attributes with params", Description: "update_attributes with params directly allows mass assignment. Use strong parameters (permit) to restrict which attributes can be set.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)update_attributes\s*\(\s*params\[`), CWEID: "CWE-915"},

		// --- CWE-22: Path Traversal (additional C# rules) ---

		// C#: Path.Combine with variable
		{ID: "CS044", Title: "Path traversal via Path.Combine with variable", Description: "Path.Combine with a user-controlled variable allows path traversal. Validate and canonicalize paths before combining.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)Path\.Combine\s*\([^,]+,\s*[a-zA-Z_$]`), CWEID: "CWE-22"},
		// C#: File.ReadAllText with variable
		{ID: "CS045", Title: "Path traversal via File.Read with variable", Description: "File.ReadAllText/ReadAllBytes with a user-controlled variable allows path traversal. Validate and canonicalize paths.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)File\.(ReadAllText|ReadAllBytes|ReadAllLines|Open)\s*\(\s*[a-zA-Z_$]`), CWEID: "CWE-22"},

		// --- CWE-78: OS Command Injection (additional Java rules) ---

		// Java: Runtime.exec with variable
		{ID: "JAVA046", Title: "Command injection via Runtime.exec with variable", Description: "Runtime.getRuntime().exec() with a user-controlled variable allows command injection. Use ProcessBuilder with argument arrays.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)Runtime\.getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(\s*[a-zA-Z_$]`), CWEID: "CWE-78"},
		// Java: ProcessBuilder with variable
		{ID: "JAVA047", Title: "Command injection via ProcessBuilder with variable", Description: "ProcessBuilder with a user-controlled command variable allows command injection. Validate and sanitize input.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)new\s+ProcessBuilder\s*\(\s*[a-zA-Z_$]`), CWEID: "CWE-78"},

		// --- CWE-352: CSRF (additional Ruby rule) ---

		// Ruby/Rails: protect_from_forgery with :null_session
		{ID: "RB025", Title: "CSRF protection disabled via protect_from_forgery with null_session", Description: "protect_from_forgery with :null_session disables CSRF protection for the controller. Use :exception or :reset_session instead.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)protect_from_forgery.*:null_session`), CWEID: "CWE-352"},
		// Ruby/Rails: skip_forgery_protection
		{ID: "RB026", Title: "CSRF protection skipped via skip_forgery_protection", Description: "skip_forgery_protection disables CSRF protection for controller actions. Ensure CSRF protection is enabled for state-changing operations.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)skip_forgery_protection|skip_before_action\s+:verify_authenticity_token`), CWEID: "CWE-352"},

		// --- CWE-287: Authentication (additional Ruby/C# rules) ---

		// Ruby/Rails: has_secure_password with plaintext comparison
		{ID: "RB027", Title: "Authentication bypass via plaintext password comparison", Description: "Comparing passwords with == instead of using authenticate() method suggests plaintext password storage. Use has_secure_password with bcrypt.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)(password|passwd)\s*==\s*params`), CWEID: "CWE-287"},
		// C#: hardcoded password comparison
		{ID: "CS046", Title: "Authentication bypass via hardcoded password comparison", Description: "Comparing input against a hardcoded password string is insecure. Use proper password hashing (bcrypt, PBKDF2) for authentication.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)(password|passwd)\s*==\s*["'][^"']+["']`), CWEID: "CWE-287"},

		// --- v6.1: Rules for repos at 0% recall ---

		// DVRA (Ruby on Rails): hardcoded secret_token
		{ID: "RB031", Title: "Hardcoded Rails secret_token", Description: "Hardcoded secret_token in Rails config allows session cookie forgery. Use environment variables or Rails credentials.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)config\.secret_token\s*=\s*['"][a-f0-9]{32,}['"]`), CWEID: "CWE-798"},
		// DVRA: session hijacking via cookies[:user_id]
		{ID: "RB032", Title: "Session hijacking via cookie-based authentication", Description: "Using cookies[:user_id] for authentication without session verification allows session hijacking. Use Rails session[] instead of cookies[].", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)User\.find\s*\(\s*cookies\[:`), CWEID: "CWE-384"},
		// DVRA: mass assignment via direct params[:user] return
		{ID: "RB033", Title: "Mass assignment via direct params return without permit", Description: "Returning params[:model] directly without .require().permit() allows mass assignment. Use strong parameters: params.require(:model).permit(:field1, :field2).", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)params\[:\w+\]\s*$`), CWEID: "CWE-915"},
		// DVRA: CSRF protection commented out
		{ID: "RB034", Title: "CSRF protection disabled via commented protect_from_forgery", Description: "Commented-out protect_from_forgery disables CSRF protection. Uncomment it to enable CSRF protection.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)#\s*protect_from_forgery`), CWEID: "CWE-352"},

		// Eoftedal-Deserialize (Java): XStreamMarshaller without security
		{ID: "JAVA050", Title: "Insecure deserialization via XStreamMarshaller", Description: "XStreamMarshaller without security framework allows arbitrary type deserialization. Use XStream security framework with allowlist.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)XStreamMarshaller`), CWEID: "CWE-502"},
		// Eoftedal: XStream direct usage
		{ID: "JAVA051", Title: "Insecure deserialization via XStream", Description: "new XStream() without security framework allows arbitrary type deserialization. Use XStream.addPermission() with allowlist.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)new\s+XStream\s*\(`), CWEID: "CWE-502"},
		// Eoftedal: XSLT injection via TransformerFactory
		{ID: "JAVA052", Title: "XSLT injection via TransformerFactory with user input", Description: "TransformerFactory.newInstance().newTransformer() with user-controlled XSLT allows arbitrary code execution. Validate XSLT input.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)TransformerFactory\.newInstance`), CWEID: "CWE-94"},
		// Eoftedal: ObjectInputStream.readObject
		{ID: "JAVA053", Title: "Insecure deserialization via ObjectInputStream", Description: "ObjectInputStream.readObject() can execute arbitrary code during deserialization. Avoid deserializing untrusted input.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)ObjectInputStream`), CWEID: "CWE-502"},

		// Vuln-SpringBoot-App: hardcoded admin credentials
		{ID: "JAVA054", Title: "Hardcoded admin credentials in source", Description: "Hardcoded admin password in source code allows authentication bypass. Use environment variables or secret management.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)(ADMIN_PASSWORD|admin_password)\s*=\s*["'][^"']+["']`), CWEID: "CWE-798"},
		// Vuln-SpringBoot-App: weak JWT secret default
		{ID: "JAVA055", Title: "Weak default JWT secret in configuration", Description: "JWT secret with a hardcoded default value allows token forgery. Use environment variables without defaults.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)jwt\.secret\s*=\s*\$\{[^}]*:`), CWEID: "CWE-798"},
		// Vuln-SpringBoot-App: privilege escalation via user-controlled role
		{ID: "JAVA056", Title: "Privilege escalation via user-controlled role assignment", Description: "setRole() with user input allows privilege escalation. Use server-side role assignment, not user-provided roles.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)setRole\s*\(\s*request\.`), CWEID: "CWE-269"},

		// === v7.0 P2.1: C#/ASP.NET Framework Rules ===

		// C# ASP.NET: [AllowAnonymous] on sensitive endpoints
		{ID: "CS047", Title: "Missing authentication via [AllowAnonymous]", Description: "[AllowAnonymous] bypasses authentication for this endpoint. Remove it unless the endpoint is intentionally public (e.g., login/register).", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)\[AllowAnonymous\]`), CWEID: "CWE-862"},
		// C# ASP.NET: SqlCommand with string concatenation
		{ID: "CS048", Title: "SQL injection via SqlCommand with concatenation", Description: "SqlCommand with string concatenation (+) allows SQL injection. Use SqlParameter with parameterized queries.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)new\s+SqlCommand\s*\(\s*["'].*\+\s*\w+`), CWEID: "CWE-89", SkipQuoteFilter: true},
		// C# ASP.NET: ExecuteSqlRaw with string interpolation
		{ID: "CS049", Title: "SQL injection via ExecuteSqlRaw/FromSqlRaw with interpolation", Description: "ExecuteSqlRaw or FromSqlRaw with string interpolation ($\"{...}\") allows SQL injection. Use parameterized queries.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)(ExecuteSqlRaw|FromSqlRaw)\s*\(\s*\$"`), CWEID: "CWE-89", SkipQuoteFilter: true},
		// C# ASP.NET: Dapper Query with string concatenation
		{ID: "CS050", Title: "SQL injection via Dapper Query with concatenation", Description: "Dapper .Query<>() with string concatenation allows SQL injection. Use parameterized queries with @param syntax.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)\.Query\s*<.*>\s*\(\s*["'].*\+\s*\w+`), CWEID: "CWE-89", SkipQuoteFilter: true},
		// C# ASP.NET: WebRequest.Create with variable
		{ID: "CS051", Title: "SSRF via WebRequest.Create with variable", Description: "WebRequest.Create with a user-controlled URL allows SSRF. Validate and restrict destination URLs.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)WebRequest\.Create\s*\(\s*[a-zA-Z_$]`), CWEID: "CWE-918"},
		// C# ASP.NET: NetDataContractSerializer
		{ID: "CS052", Title: "Insecure deserialization via NetDataContractSerializer", Description: "NetDataContractSerializer can deserialize arbitrary types. Use DataContractSerializer with known types.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)NetDataContractSerializer\s*\(`), CWEID: "CWE-502"},
		// C# ASP.NET: Process.Start with variable
		{ID: "CS053", Title: "Command injection via Process.Start with variable", Description: "Process.Start with a user-controlled variable allows command injection. Use ProcessStartInfo with argument lists.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)Process\.Start\s*\(\s*[a-zA-Z_$]`), CWEID: "CWE-78"},
		// C# ASP.NET: SqlCommand with string interpolation ($")
		{ID: "CS054", Title: "SQL injection via SqlCommand with interpolation", Description: "SqlCommand with string interpolation ($\"{...}\") allows SQL injection. Use SqlParameter with parameterized queries.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)new\s+SqlCommand\s*\(\s*\$"`), CWEID: "CWE-89", SkipQuoteFilter: true},
		// C# ASP.NET: SqlCommand with string.Format
		{ID: "CS055", Title: "SQL injection via SqlCommand with string.Format", Description: "SqlCommand with string.Format allows SQL injection. Use SqlParameter with parameterized queries.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)new\s+SqlCommand\s*\(\s*string\.Format`), CWEID: "CWE-89"},
		// C# ASP.NET: [FromQuery]/[FromBody]/[FromRoute] with dangerous sinks (informational)
		{ID: "CS056", Title: "User input binding via [FromQuery]/[FromBody]/[FromRoute]", Description: "Direct binding of user input via model binding can be risky if the model contains sensitive fields. Use DTOs with whitelisted properties.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceLow, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)\[(FromQuery|FromBody|FromRoute|FromForm)\]`), CWEID: "CWE-915"},

		// === v7.0 P2.2: Java/Spring Boot Framework Rules ===

		// Spring Security: permitAll() without restrictions
		{ID: "JAVA058", Title: "Missing authorization via permitAll()", Description: "permitAll() allows unrestricted access to endpoints. Use authenticated() or hasRole() for sensitive endpoints.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)\.permitAll\s*\(\s*\)`), CWEID: "CWE-862"},
		// Spring Security: anonymous() access
		{ID: "JAVA059", Title: "Missing authorization via anonymous()", Description: "anonymous() allows unauthenticated access. Use authenticated() for sensitive endpoints.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceLow, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)\.anonymous\s*\(\s*\)`), CWEID: "CWE-862"},
		// Spring Security: antMatchers with permitAll
		{ID: "JAVA060", Title: "Missing authorization via antMatchers permitAll", Description: "antMatchers().permitAll() allows unrestricted access to matched paths. Restrict to authenticated users.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)antMatchers\s*\([^)]*\)\s*\.\s*permitAll`), CWEID: "CWE-862"},
		// Spring: SpEL injection via SpelExpressionParser
		{ID: "JAVA061", Title: "SpEL injection via SpelExpressionParser", Description: "SpelExpressionParser.parseExpression with user-controlled input allows arbitrary code execution. Validate input before parsing.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)SpelExpressionParser`), CWEID: "CWE-94"},
		// Spring: Jackson enableDefaultTyping
		{ID: "JAVA062", Title: "Insecure deserialization via Jackson enableDefaultTyping", Description: "ObjectMapper.enableDefaultTyping() allows deserialization of arbitrary types. Use @JsonTypeInfo or activateDefaultTyping with a validator.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)enableDefaultTyping`), CWEID: "CWE-502"},
		// Spring: WebClient with variable URL
		{ID: "JAVA063", Title: "SSRF via WebClient with variable URL", Description: "WebClient.get().uri() with a user-controlled URL allows SSRF. Validate and restrict destination URLs.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)webClient\s*\.\s*get\s*\(\s*\)\s*\.\s*uri\s*\(\s*[a-zA-Z_$]`), CWEID: "CWE-918"},
		// Spring: @RequestMapping without auth (broad pattern)
		{ID: "JAVA064", Title: "Endpoint without authorization annotation", Description: "RequestMapping/GetMapping/PostMapping without @PreAuthorize or @Secured may expose endpoints without authorization. Add authorization annotations.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceLow, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)@(RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping)\s*\(`), CWEID: "CWE-862"},
		// Spring: hardcoded credentials in properties
		{ID: "JAVA065", Title: "Hardcoded credentials in Spring properties", Description: "Hardcoded password or secret in application.properties allows authentication bypass. Use environment variables.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)(password|secret|api[_-]?key)\s*=\s*[a-zA-Z0-9]{8,}`), CWEID: "CWE-798"},
		// Spring: HttpInvokerServiceExporter (deserialization)
		{ID: "JAVA066", Title: "Insecure deserialization via HttpInvokerServiceExporter", Description: "HttpInvokerServiceExporter uses Java serialization for remote calls, allowing code execution. Use REST/JSON instead.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)HttpInvokerServiceExporter`), CWEID: "CWE-502"},

		// === v7.0 P2.3: XSS Template Engine Rules ===

		// Python/Django: mark_safe
		{ID: "PY050", Title: "XSS via Django mark_safe", Description: "mark_safe() marks content as safe for HTML output, bypassing Django's auto-escaping. Avoid mark_safe with user-controlled data.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)mark_safe\s*\(`), CWEID: "CWE-79"},
		// Python/Jinja2: autoescape off
		{ID: "PY051", Title: "XSS via Jinja2 autoescape disabled", Description: "Disabling autoescaping in Jinja2 allows XSS. Keep autoescaping enabled or use |e filter explicitly.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)autoescape\s*=\s*False`), CWEID: "CWE-79"},
		// Python/Jinja2: |safe filter in templates
		{ID: "PY052", Title: "XSS via Jinja2 |safe filter", Description: "The |safe filter bypasses Jinja2 auto-escaping, allowing XSS. Avoid |safe with user-controlled data.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`\|\s*safe\b`), CWEID: "CWE-79", SkipQuoteFilter: true},
		// Python/Django: HttpResponse with user input
		{ID: "PY053", Title: "XSS via HttpResponse with user input", Description: "HttpResponse with user-controlled content may allow XSS. Use template rendering with auto-escaping instead.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)HttpResponse\s*\(\s*.*request\.`), CWEID: "CWE-79", SkipQuoteFilter: true},

		// JS/TS: Angular bypassSecurityTrust (already JS029, add bypassSecurityTrustResourceUrl)
		{ID: "JS046", Title: "Angular XSS via bypassSecurityTrustResourceUrl", Description: "bypassSecurityTrustResourceUrl bypasses Angular's URL sanitization. Avoid using it with user-controlled data.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`bypassSecurityTrustResourceUrl\s*\(`), CWEID: "CWE-79"},
		// JS/TS: v-html directive (Vue.js)
		{ID: "JS047", Title: "XSS via Vue.js v-html directive", Description: "v-html renders raw HTML, bypassing Vue's escaping. Avoid v-html with user-controlled data.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`v-html`), CWEID: "CWE-79"},
		// JS/TS: $sce.trustAsHtml (AngularJS)
		{ID: "JS048", Title: "XSS via AngularJS $sce.trustAsHtml", Description: "$sce.trustAsHtml bypasses AngularJS sanitization. Avoid using it with user-controlled data.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`\$sce\.trustAs`), CWEID: "CWE-79"},

		// === v7.0 P2.4: Missing Auth Rules ===

		// C# ASP.NET: missing [Authorize] on controller (heuristic)
		{ID: "CS057", Title: "Controller without [Authorize] attribute", Description: "Controller without [Authorize] may expose endpoints without authentication. Add [Authorize] to controllers handling sensitive data.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceLow, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)\[Route\s*\(\s*["']api`), CWEID: "CWE-862"},
		// Java Spring: SecurityFilterChain without any authentication
		{ID: "JAVA067", Title: "SecurityFilterChain without authentication requirement", Description: "SecurityFilterChain without .anyRequest().authenticated() may expose endpoints without authentication.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceLow, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)SecurityFilterChain`), CWEID: "CWE-862"},

		// === v7.0 Additional patterns from subagent investigation ===

		// C# ASP.NET: TypeNameHandling.All (JSON.NET insecure deserialization)
		{ID: "CS058", Title: "Insecure deserialization via TypeNameHandling.All", Description: "JsonSerializerSettings with TypeNameHandling.All allows arbitrary type deserialization. Use TypeNameHandling.None.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)TypeNameHandling\.(All|Arrays|Auto|Objects)`), CWEID: "CWE-502"},
		// C# ASP.NET: XmlDocument with XmlUrlResolver (XXE)
		{ID: "CS059", Title: "XXE via XmlUrlResolver", Description: "XmlDocument with XmlUrlResolver allows external entity resolution. Set XmlResolver to null to disable XXE.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)XmlUrlResolver`), CWEID: "CWE-611"},
		// C# ASP.NET: SqlCommand with string interpolation ($")
		{ID: "CS060", Title: "SQL injection via SQLiteCommand with interpolation", Description: "SQLiteCommand with string interpolation ($\"{...}\") allows SQL injection. Use parameterized queries.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)new\s+(SqlCommand|SQLiteCommand|MySqlCommand|NpgsqlCommand)\s*\(\s*\$"`), CWEID: "CWE-89", SkipQuoteFilter: true},
		// C# ASP.NET: SqlCommand.CommandText with concatenation
		{ID: "CS061", Title: "SQL injection via CommandText with concatenation", Description: "Setting CommandText with string concatenation allows SQL injection. Use SqlParameter with parameterized queries.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)\.CommandText\s*=\s*["'].*\+\s*\w+`), CWEID: "CWE-89", SkipQuoteFilter: true},
		// C# ASP.NET: FromSql with string concatenation
		{ID: "CS062", Title: "SQL injection via FromSql with concatenation", Description: "FromSql() with string concatenation allows SQL injection. Use FromSqlInterpolated() or parameterized queries.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)\.FromSql\s*\(\s*["'].*\+\s*\w+`), CWEID: "CWE-89", SkipQuoteFilter: true},
		// C# ASP.NET: ExecuteSqlCommand with concatenation
		{ID: "CS063", Title: "SQL injection via ExecuteSqlCommand with concatenation", Description: "ExecuteSqlCommand with string concatenation allows SQL injection. Use parameterized queries.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)ExecuteSqlCommand\s*\(\s*["'].*\+\s*\w+`), CWEID: "CWE-89", SkipQuoteFilter: true},
		// C# ASP.NET: LDAP injection via DirectoryEntry/DirectorySearcher
		{ID: "CS064", Title: "LDAP injection via DirectoryEntry/DirectorySearcher with user input", Description: "DirectoryEntry or DirectorySearcher with user-controlled input allows LDAP injection. Use proper escaping of user input.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)new\s+DirectoryEntry\s*\([^)]*\+|new\s+DirectorySearcher\s*\(\s*["'].*\+`), CWEID: "CWE-90", SkipQuoteFilter: true},
		// C# ASP.NET: XPath injection
		{ID: "CS065", Title: "XPath injection via XPathNavigator with concatenation", Description: "XPath query with string concatenation allows XPath injection. Use parameterized XPath expressions.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)xpath.*["'].*\+\s*\w+|XPathExpression.*\+`), CWEID: "CWE-643", SkipQuoteFilter: true},
		// C# ASP.NET: [ValidateInput(false)] disables request validation
		{ID: "CS066", Title: "XSS via disabled request validation", Description: "[ValidateInput(false)] disables ASP.NET request validation, allowing XSS. Remove this attribute or use [AllowHtml] on specific properties.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)\[ValidateInput\s*\(\s*false\s*\)\]`), CWEID: "CWE-79"},
		// C# ASP.NET: SSTI via RazorEngine/RazorLight
		{ID: "CS067", Title: "SSTI via RazorEngine/RazorLight with user input", Description: "RazorEngine or RazorLight template compilation with user-controlled input allows server-side template injection. Validate template input.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)(Engine\.Razor\.RunCompile|razor\.CompileRenderStringAsync|RazorEngineRunner)`), CWEID: "CWE-94"},
		// C# ASP.NET: MD5/SHA1 weak hash
		{ID: "CS068", Title: "Weak hash algorithm MD5/SHA1", Description: "MD5 or SHA1 is cryptographically weak. Use SHA-256 or stronger for security-sensitive operations.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)(MD5|SHA1|SHA\.Manage)\.Create\s*\(`), CWEID: "CWE-328"},
		// C# ASP.NET: Weak random
		{ID: "CS069", Title: "Weak random number generator", Description: "System.Random is not cryptographically secure. Use RandomNumberGenerator for security-sensitive tokens.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)new\s+Random\s*\(`), CWEID: "CWE-330"},
		// C# ASP.NET: BinaryMessageFormatter (MSMQ deserialization)
		{ID: "CS070", Title: "Insecure deserialization via BinaryMessageFormatter", Description: "BinaryMessageFormatter can execute arbitrary code during deserialization. Use XML message formatting or validate the message source.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)BinaryMessageFormatter`), CWEID: "CWE-502"},

		// Node.js: serialize.unserialize (deserialization)
		{ID: "JS049", Title: "Insecure deserialization via serialize.unserialize", Description: "serialize.unserialize() can execute arbitrary code. Avoid deserializing untrusted input.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)serialize\.unserialize\s*\(`), CWEID: "CWE-502"},
		// Node.js: libxmljs parseXmlString with noent (XXE)
		{ID: "JS050", Title: "XXE via libxmljs parseXmlString with noent", Description: "libxmljs.parseXmlString with noent:true enables entity expansion, allowing XXE. Set noent to false.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)noent\s*:\s*true`), CWEID: "CWE-611"},
		// Node.js: exec with string concatenation (broader than JS041)
		{ID: "JS051", Title: "Command injection via exec with variable", Description: "child_process.exec with a variable command allows command injection. Use execFile with argument arrays.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)\bexec\s*\(\s*['"]`), CWEID: "CWE-78", SuppressFunc: suppressJS051},

		// Java: TrustAllStrategy / disabled SSL cert validation
		{ID: "JAVA068", Title: "SSL certificate validation disabled via TrustAllStrategy", Description: "TrustAllStrategy disables SSL certificate validation, allowing MITM attacks. Use proper certificate validation.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)TrustAllStrategy|TrustManager\s*\{[^}]*checkServerTrusted\s*\(\s*\)\s*\{[^}]*\}`), CWEID: "CWE-295"},
		// Java: RestTemplate with string concatenation (SSRF)
		{ID: "JAVA069", Title: "SSRF via RestTemplate with string concatenation", Description: "RestTemplate with a URL built via string concatenation allows SSRF. Validate and restrict destination URLs.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)restTemplate\s*\.\s*(getForObject|postForObject|exchange|getForEntity)\s*\(\s*\w+\s*\+`), CWEID: "CWE-918", SkipQuoteFilter: true},
		// Java: SnakeYAML Yaml().load (already have JAVA039, add loadAs variant)
		{ID: "JAVA070", Title: "Insecure deserialization via SnakeYAML loadAs", Description: "Yaml().loadAs() can instantiate arbitrary classes. Use Yaml().loadAs() with a specific safe type.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)new\s+Yaml\s*\(\s*\)\s*\.loadAs`), CWEID: "CWE-502"},

		// Python: requests.get with user-controlled URL (SSRF)
		{ID: "PY054", Title: "SSRF via requests.get with user input", Description: "requests.get with a user-controlled URL from request.args allows SSRF. Validate and restrict destination URLs.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)requests\.get\s*\(\s*.*request\.args`), CWEID: "CWE-918", SkipQuoteFilter: true},

		// === v7.1: Gap-filling rules for remaining CWE targets ===

		// C# ASP.NET: HttpClient.GetStringAsync with variable (SSRF)
		{ID: "CS071", Title: "SSRF via HttpClient.GetStringAsync with variable", Description: "HttpClient.GetStringAsync with a user-controlled URL allows SSRF. Validate and restrict destination URLs.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)\.GetStringAsync\s*\(\s*[a-zA-Z_$]`), CWEID: "CWE-918"},
		// C# ASP.NET: MD5CryptoServiceProvider / HMACMD5 / SHA1CryptoServiceProvider / SHA1Managed
		{ID: "CS072", Title: "Weak hash algorithm MD5/SHA1 crypto provider", Description: "MD5CryptoServiceProvider, HMACMD5, SHA1CryptoServiceProvider, or SHA1Managed is cryptographically weak. Use SHA-256 or stronger.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)new\s+(MD5CryptoServiceProvider|HMACMD5|SHA1CryptoServiceProvider|SHA1Managed|MD5Managed|MD5Cng|SHA1Cng)\s*\(`), CWEID: "CWE-328"},
		// C# ASP.NET: Hardcoded credential dictionary
		{ID: "CS073", Title: "Authentication bypass via hardcoded credentials", Description: "Hardcoded username/password dictionary allows authentication bypass. Use proper password hashing with a database.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)Dictionary.*string.*string.*\{.*\{.*".*".*".*".*\}`), CWEID: "CWE-287"},
		// C# ASP.NET: XmlDocument.Load with variable (XXE — broader than CS039)
		{ID: "CS074", Title: "XXE via XmlDocument without XmlResolver restriction", Description: "XmlDocument without setting XmlResolver to null allows XXE attacks. Set XmlResolver to null.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)new\s+XmlDocument\s*[\({]\s*[\)}]`), CWEID: "CWE-611"},
		// C# ASP.NET: MD5 hash string (pre-computed)
		{ID: "CS075", Title: "Pre-computed MD5 hash detected", Description: "Pre-computed MD5 hash strings are weak. Use bcrypt, scrypt, or Argon2 for password hashing.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceLow, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`["'][a-f0-9]{32}["']`), CWEID: "CWE-328"},
		// C# ASP.NET: Response.Write with string concatenation (XSS)
		{ID: "CS076", Title: "XSS via Response.Write with concatenation", Description: "Response.Write with string concatenation may output unescaped content. Use HttpUtility.HtmlEncode before writing to response.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangCSharp}, Pattern: regexp.MustCompile(`(?i)Response\.Write\s*\(\s*["'].*\+\s*\w+`), CWEID: "CWE-79", SkipQuoteFilter: true},

		// Java: RestTemplate.exchange with variable URL (SSRF — broader than JAVA024)
		{ID: "JAVA071", Title: "SSRF via RestTemplate.exchange with variable", Description: "RestTemplate.exchange with a user-controlled URL allows SSRF. Validate and restrict destination URLs.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)\.exchange\s*\(\s*[a-zA-Z_$]\w*`), CWEID: "CWE-918"},
		// Java: HttpURLConnection with variable URL (SSRF)
		{ID: "JAVA072", Title: "SSRF via HttpURLConnection with variable URL", Description: "HttpURLConnection.openConnection with a user-controlled URL allows SSRF. Validate and restrict destination URLs.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)HttpURLConnection`), CWEID: "CWE-918"},
		// Java: Hardcoded credentials in properties (broader than JAVA065)
		{ID: "JAVA073", Title: "Hardcoded password in properties file", Description: "Hardcoded password in Spring properties allows authentication bypass. Use environment variables.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)(spring\.datasource\.(password|username)|api\.gateway\.password)\s*=\s*\$\{[^}]*:`), CWEID: "CWE-798"},

		// Node.js: res.send with variable (XSS)
		{ID: "JS052", Title: "XSS via res.send with variable", Description: "res.send with a variable may output unescaped content. Use template engine with auto-escaping or encode output.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceLow, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)res\.send\s*\(\s*[a-zA-Z_$]\w*\s*\)`), CWEID: "CWE-79"},
		// Node.js: res.write with variable (XSS)
		{ID: "JS053", Title: "XSS via res.write with variable", Description: "res.write with a variable may output unescaped content. Encode output before writing to response.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceLow, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)res\.write\s*\(\s*[a-zA-Z_$]\w*\s*\)`), CWEID: "CWE-79"},

		// PHP: echo with concatenated HTML tags (XSS)
		{ID: "PHP037", Title: "XSS via echo with concatenated HTML", Description: "echo with string concatenation containing HTML tags may output unescaped content. Use htmlspecialchars() to encode output.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)(echo|print)\s.*["'].*<\w+.*\.\s*\$`), CWEID: "CWE-79", SkipQuoteFilter: true},

		// Ruby: ERB template with raw output (broader than RB028)
		{ID: "RB035", Title: "XSS via ERB raw output with variable", Description: "ERB template outputting a variable with raw/html_safe bypasses Rails auto-escaping. Avoid raw/html_safe with user-controlled data.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`<%=\s*\w+\.(html_safe|raw)\s*%>`), CWEID: "CWE-79"},
		// Ruby: ERB template with raw() helper
		{ID: "RB036", Title: "XSS via ERB raw helper", Description: "raw() in ERB templates bypasses HTML escaping. Avoid raw with user-controlled content.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`<%=\s*raw\s*\(`), CWEID: "CWE-79"},

		// Python: Jinja2 autoescape false in templates
		{ID: "PY055", Title: "XSS via Jinja2 autoescape false in template", Description: "{% autoescape false %} disables Jinja2 auto-escaping, allowing XSS. Keep autoescaping enabled.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)\{%\s*autoescape\s+false\s*%\}`), CWEID: "CWE-79", SkipQuoteFilter: true},

		// HTML template XSS rules (apply to .html files with template syntax)
		// Jinja2/Django autoescape false
		{ID: "HTML001", Title: "XSS via Jinja2 autoescape false", Description: "{% autoescape false %} disables Jinja2 auto-escaping, allowing XSS. Keep autoescaping enabled.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangHTML}, Pattern: regexp.MustCompile(`(?i)\{%\s*autoescape\s+false\s*%\}`), CWEID: "CWE-79"},
		// Jinja2 |safe filter
		{ID: "HTML002", Title: "XSS via Jinja2 |safe filter", Description: "The |safe filter bypasses Jinja2 auto-escaping, allowing XSS. Avoid |safe with user-controlled data.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangHTML}, Pattern: regexp.MustCompile(`\|\s*safe\b`), CWEID: "CWE-79"},
		// ERB html_safe
		{ID: "HTML003", Title: "XSS via ERB html_safe", Description: "html_safe bypasses Rails HTML escaping, allowing XSS. Avoid html_safe with user-controlled data.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangHTML}, Pattern: regexp.MustCompile(`<%=\s*\w+\.(html_safe|raw)\s*%>`), CWEID: "CWE-79"},
		// ERB raw helper
		{ID: "HTML004", Title: "XSS via ERB raw helper", Description: "raw() in ERB templates bypasses HTML escaping. Avoid raw with user-controlled content.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangHTML}, Pattern: regexp.MustCompile(`<%=\s*raw\s*\(`), CWEID: "CWE-79"},
		// Angular bypassSecurityTrustHtml in templates
		{ID: "HTML005", Title: "XSS via Angular bypassSecurityTrustHtml", Description: "bypassSecurityTrustHtml bypasses Angular's sanitization. Avoid using it with user-controlled data.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangHTML}, Pattern: regexp.MustCompile(`bypassSecurityTrustHtml\s*\(`), CWEID: "CWE-79"},
		// Vue v-html in templates
		{ID: "HTML006", Title: "XSS via Vue.js v-html directive", Description: "v-html renders raw HTML, bypassing Vue's escaping. Avoid v-html with user-controlled data.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangHTML}, Pattern: regexp.MustCompile(`v-html`), CWEID: "CWE-79"},
		// Django template {% autoescape off %}
		{ID: "HTML007", Title: "XSS via Django autoescape off", Description: "{% autoescape off %} disables Django's auto-escaping, allowing XSS. Keep autoescaping on.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangHTML}, Pattern: regexp.MustCompile(`(?i)\{%\s*autoescape\s+off\s*%\}`), CWEID: "CWE-79"},
		// EJS unescaped output <%- variable %>
		{ID: "HTML008", Title: "XSS via EJS unescaped output", Description: "<%- %> outputs content without HTML escaping in EJS templates. Use <%= %> for escaped output.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangHTML}, Pattern: regexp.MustCompile(`<%-\s*\w`), CWEID: "CWE-79"},
		// JSP unescaped output <%= request.getParameter() %>
		{ID: "HTML009", Title: "XSS via JSP unescaped expression", Description: "<%= %> outputs content without HTML escaping in JSP. Use <c:out value=\"...\"/> or JSTL escaping.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangHTML}, Pattern: regexp.MustCompile(`<%=\s*request\.get(Parameter|Attribute)`), CWEID: "CWE-79"},

		// === v7.2: Java framework gap-filling rules ===

		// Java: JPA createQuery/createNativeQuery with string concatenation (SQL injection)
		{ID: "JAVA074", Title: "SQL injection via JPA createQuery with concatenation", Description: "entityManager.createQuery with string concatenation allows SQL injection. Use parameterized queries with named or positional parameters.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)create(Native)?Query\s*\(\s*["'].*\+\s*\w+`), CWEID: "CWE-89", SkipQuoteFilter: true},
		// Java: Runtime.exec with variable (broader than JAVA001 — handles multi-line patterns)
		{ID: "JAVA075", Title: "Command injection via Runtime.exec with variable", Description: "Runtime.exec() with a variable command allows command injection. Use ProcessBuilder with argument lists.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)\.exec\s*\(\s*[a-zA-Z_$]\w*`), CWEID: "CWE-78"},
		// Java: ProcessBuilder with string concatenation (command injection)
		{ID: "JAVA079", Title: "Command injection via ProcessBuilder with concatenation", Description: "ProcessBuilder with string concatenation allows command injection. Pass arguments as separate list elements.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)ProcessBuilder\s*\(\s*new\s+String\[\]\s*\{[^}]*\+\s*\w+`), CWEID: "CWE-78", SkipQuoteFilter: true},
		// Java: Open redirect via Location header with user input
		{ID: "JAVA080", Title: "Open redirect via Location header with user input", Description: "Setting the Location header with user-controlled input allows open redirect attacks. Validate redirect URLs against a whitelist.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)(LOCATION_HEADER|Location).*\b(add|put)\s*\(\s*.*\w+`), CWEID: "CWE-601"},
		// Java: Spring Security CSRF disabled
		{ID: "JAVA076", Title: "CSRF protection disabled in Spring Security", Description: "csrf().disable() removes CSRF protection, allowing cross-site request forgery attacks. Keep CSRF protection enabled for state-changing endpoints.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)csrf\s*\(\s*\w*\s*->\s*\w*\.disable\(\)|csrf\.disable`), CWEID: "CWE-352"},
		// Java: Mass assignment via setRole with request input (privilege escalation)
		{ID: "JAVA077", Title: "Privilege escalation via mass assignment of role", Description: "setRole() with user-controlled input from request allows privilege escalation. Explicitly validate and restrict role assignment.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)\.setRole\s*\(\s*.*request\.`), CWEID: "CWE-269", SkipQuoteFilter: true},
		// Java: Hardcoded admin credentials in initializer
		{ID: "JAVA078", Title: "Hardcoded admin credentials in initializer", Description: "Hardcoded admin username and password in application initializer allows authentication bypass. Use environment variables or secret management.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)(ADMIN_PASSWORD|ADMIN_EMAIL|admin.*password)\s*=\s*["']`), CWEID: "CWE-798"},

		// Ruby: find_by_sql with string interpolation (SQL injection)
		{ID: "RB037", Title: "SQL injection via find_by_sql with interpolation", Description: "find_by_sql with string interpolation of params allows SQL injection. Use parameterized queries or ActiveRecord where clauses.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)find_by_sql\s*\(\s*["'].*#\{.*params`), CWEID: "CWE-89", SkipQuoteFilter: true},
		// Ruby: SQL injection in authentication context (auth bypass)
		{ID: "RB038", Title: "Authentication bypass via SQL injection in login", Description: "SQL injection in authentication logic allows login bypass. Use parameterized queries and proper password hashing.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)(find_by_sql|where).*password.*params\[:password\]`), CWEID: "CWE-287", SkipQuoteFilter: true},
		// Ruby: IDOR via Post.find(params[:id]) without ownership check
		{ID: "RB039", Title: "IDOR via direct object lookup without authorization", Description: "Finding records by params[:id] without ownership verification allows IDOR. Add authorization checks to verify the user owns the resource.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceLow, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)\.find\s*\(\s*params\[:id\]`), CWEID: "CWE-862"},

		// PHP: echo with variable in HTML attribute (XSS — broader than PHP025)
		{ID: "PHP038", Title: "XSS via echo with variable in HTML context", Description: "echo with a variable inside HTML tags may output unescaped content. Use htmlspecialchars() to encode output.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)(echo|print)\s.*\?\>\s*\<.*\$\w+`), CWEID: "CWE-79", SkipQuoteFilter: true},
	}
}

// Analyze scans all supported source files in the root directory.
func (s *Scanner) Analyze(ctx context.Context, root string) ([]analysis.Finding, error) {
	var findings []analysis.Finding

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			name := filepath.Base(path)
			if s.ignoredDirs[name] {
				return filepath.SkipDir
			}
			// Check .gitignore for directories
			if s.ignoreMatcher != nil && !s.ignoreMatcher.IsEmpty() {
				if s.ignoreMatcher.Match(path, true) {
					return filepath.SkipDir
				}
			}
			return nil
		}

		// Check .gitignore for files
		if s.ignoreMatcher != nil && !s.ignoreMatcher.IsEmpty() {
			if s.ignoreMatcher.Match(path, false) {
				return nil
			}
		}

		if info.Size() > s.maxFileSize {
			return nil
		}

		lang := detectLanguage(path)
		if lang == "" {
			return nil
		}

		fileFindings, err := s.scanFile(path, root, lang)
		if err != nil {
			return nil
		}
		findings = append(findings, fileFindings...)
		return nil
	})

	if err != nil {
		return nil, err
	}
	return findings, nil
}

// scanFile scans a single file with rules matching the detected language.
// It uses a context tracker to skip lines inside multi-line string literals,
// eliminating false positives where security keywords appear in docstrings
// or template strings.
func (s *Scanner) scanFile(absPath, root string, lang Language) ([]analysis.Finding, error) {
	if lang == LangTerraform {
		return s.scanTerraformFile(absPath, root)
	}

	file, err := os.Open(absPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var findings []analysis.Finding
	lineNum := 0
	tracker := NewTracker(string(lang))

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Check lexical context — skip lines inside multi-line strings
		ctx := tracker.Context(line)
		tracker.Advance(line)

		if ctx == ContextString || ctx == ContextComment {
			continue
		}

		for _, rule := range s.rules {
			if !ruleAppliesToLanguage(rule, lang) {
				continue
			}

			if matchesRule(rule, line, lang) {
				findings = append(findings, makePatternFinding(rule, absPath, root, lineNum, line))
			}
		}
	}

	return findings, nil
}

type terraformResource struct {
	Type      string
	Name      string
	LineStart int
	Body      string
	Line      string
}

var (
	terraformResourceQuotedRe   = regexp.MustCompile(`^\s*resource\s+"([^"]+)"\s+"([^"]+)"\s*\{`)
	terraformResourceUnquotedRe = regexp.MustCompile(`^\s*resource\s+([A-Za-z0-9_]+)\s+([A-Za-z0-9_]+)\s*\{`)
)

func (s *Scanner) scanTerraformFile(absPath, root string) ([]analysis.Finding, error) {
	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, err
	}

	content := string(data)
	lines := strings.Split(content, "\n")
	var findings []analysis.Finding
	tracker := NewTracker(string(LangTerraform))

	for i, line := range lines {
		lineNum := i + 1
		ctx := tracker.Context(line)
		tracker.Advance(line)
		if ctx == ContextString || ctx == ContextComment {
			continue
		}

		for _, rule := range s.rules {
			if terraformS3PostureRules[rule.ID] {
				continue
			}
			if !ruleAppliesToLanguage(rule, LangTerraform) {
				continue
			}
			if matchesRule(rule, line, LangTerraform) {
				findings = append(findings, makePatternFinding(rule, absPath, root, lineNum, line))
			}
		}
	}

	resources := parseTerraformResources(content)
	findings = append(findings, terraformS3PostureFindings(resources, absPath, root)...)
	return findings, nil
}

func parseTerraformResources(content string) []terraformResource {
	lines := strings.Split(content, "\n")
	resources := make([]terraformResource, 0)

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		resourceType, resourceName, ok := parseTerraformResourceHeader(line)
		if !ok {
			continue
		}

		var body strings.Builder
		braceDepth := strings.Count(line, "{") - strings.Count(line, "}")
		body.WriteString(line)
		body.WriteByte('\n')
		startLine := i + 1

		for braceDepth > 0 && i+1 < len(lines) {
			i++
			nextLine := lines[i]
			braceDepth += strings.Count(nextLine, "{") - strings.Count(nextLine, "}")
			body.WriteString(nextLine)
			body.WriteByte('\n')
		}

		resources = append(resources, terraformResource{
			Type:      resourceType,
			Name:      resourceName,
			LineStart: startLine,
			Body:      body.String(),
			Line:      line,
		})
	}

	return resources
}

func parseTerraformResourceHeader(line string) (resourceType, resourceName string, ok bool) {
	if match := terraformResourceQuotedRe.FindStringSubmatch(line); len(match) == 3 {
		return match[1], match[2], true
	}
	if match := terraformResourceUnquotedRe.FindStringSubmatch(line); len(match) == 3 {
		return match[1], match[2], true
	}
	return "", "", false
}

func terraformS3PostureFindings(resources []terraformResource, absPath, root string) []analysis.Finding {
	var findings []analysis.Finding

	for _, bucket := range resources {
		if bucket.Type != "aws_s3_bucket" {
			continue
		}

		if !terraformBucketHasVersioning(bucket, resources) {
			findings = append(findings, makeTerraformS3Finding("TF001", "AWS S3 bucket without versioning", "S3 bucket should have versioning enabled for data recovery.", analysis.SeverityLow, "", bucket, absPath, root))
		}
		if !terraformBucketHasEncryption(bucket, resources) {
			findings = append(findings, makeTerraformS3Finding("TF006", "S3 bucket without encryption", "S3 bucket should have server-side encryption enabled.", analysis.SeverityMedium, "", bucket, absPath, root))
		}
		if !terraformBucketHasLogging(bucket, resources) {
			findings = append(findings, makeTerraformS3Finding("TF011", "S3 bucket logging disabled", "S3 bucket does not have access logging enabled for audit trail.", analysis.SeverityLow, "CWE-778", bucket, absPath, root))
		}
	}

	return findings
}

func terraformBucketHasVersioning(bucket terraformResource, resources []terraformResource) bool {
	body := strings.ToLower(bucket.Body)
	if strings.Contains(body, "versioning") && strings.Contains(body, "enabled") {
		return true
	}
	return terraformHasCompanionResource(bucket, resources, "aws_s3_bucket_versioning")
}

func terraformBucketHasEncryption(bucket terraformResource, resources []terraformResource) bool {
	body := strings.ToLower(bucket.Body)
	if strings.Contains(body, "server_side_encryption_configuration") {
		return true
	}
	return terraformHasCompanionResource(bucket, resources, "aws_s3_bucket_server_side_encryption_configuration")
}

func terraformBucketHasLogging(bucket terraformResource, resources []terraformResource) bool {
	body := strings.ToLower(bucket.Body)
	if strings.Contains(body, "logging") {
		return true
	}
	return terraformHasCompanionResource(bucket, resources, "aws_s3_bucket_logging")
}

func terraformHasCompanionResource(bucket terraformResource, resources []terraformResource, resourceType string) bool {
	ref := "aws_s3_bucket." + bucket.Name
	for _, resource := range resources {
		if resource.Type != resourceType {
			continue
		}
		if strings.Contains(resource.Body, ref) {
			return true
		}
	}
	return false
}

func makeTerraformS3Finding(ruleID, title, description string, severity analysis.Severity, cweID string, bucket terraformResource, absPath, root string) analysis.Finding {
	relPath, _ := filepath.Rel(root, absPath)
	return analysis.Finding{
		ID:          fmt.Sprintf("pattern-%s-%s-%d", ruleID, filepath.Base(relPath), bucket.LineStart),
		Type:        analysis.TypeSAST,
		Analyzer:    "patterns-embedded",
		Severity:    severity,
		Confidence:  analysis.ConfidenceMedium,
		Title:       title,
		Description: description,
		FilePath:    relPath,
		LineStart:   bucket.LineStart,
		RuleID:      ruleID,
		CWEID:       cweID,
		Evidence:    strings.TrimSpace(bucket.Line),
		DetectedAt:  time.Now(),
	}
}

func matchesRule(rule PatternRule, line string, lang Language) bool {
	if isComment(line, lang) && rule.ID != "XLANG002" {
		return false
	}

	// RequiresAssignment: only fire when the pattern is on the RHS of an
	// assignment (contains '=' or ':' as key-value). This prevents FPs in
	// comparisons or string references for hardcoded-secret rules.
	if rule.RequiresAssignment && !hasAssignment(line) {
		return false
	}

	matches := rule.Pattern.FindAllStringIndex(line, -1)
	if len(matches) == 0 {
		return false
	}

	// Post-match suppression: if the rule has a SuppressFunc, call it on the
	// full line to allow context-aware false positive filtering.
	if rule.SuppressFunc != nil && rule.SuppressFunc(line) {
		return false
	}

	// Rules that detect injection patterns inside string literals (e.g., PHP
	// SQL injection via "$var" interpolation) bypass the quote filter.
	if rule.SkipQuoteFilter {
		return true
	}

	quoted := quotedOffsets(line)
	for _, match := range matches {
		if !quoted[match[0]] {
			return true
		}
	}
	return false
}

// hasAssignment checks if a line contains an assignment operator (= or :=),
// indicating the pattern is on the right-hand side of an assignment.
func hasAssignment(line string) bool {
	trimmed := strings.TrimSpace(line)
	// Look for = or := but not == or != or <= or >=
	for i := 0; i < len(trimmed); i++ {
		if trimmed[i] == '=' {
			// Check it's not ==, !=, <=, >=
			if i > 0 && (trimmed[i-1] == '!' || trimmed[i-1] == '<' || trimmed[i-1] == '>' || trimmed[i-1] == '=') {
				continue
			}
			if i+1 < len(trimmed) && trimmed[i+1] == '=' {
				continue
			}
			return true
		}
		// Check for := (Go-style)
		if i > 0 && trimmed[i] == '=' && trimmed[i-1] == ':' {
			return true
		}
	}
	// Also check for YAML-style key: value
	if idx := strings.Index(trimmed, ":"); idx >= 0 {
		rest := strings.TrimSpace(trimmed[idx+1:])
		if rest != "" && !strings.HasPrefix(rest, "//") && !strings.HasPrefix(rest, "/*") {
			return true
		}
	}
	return false
}

func suppressUISecretLabel(line string) bool {
	match := regexp.MustCompile(`(?i)(password|passwd|pwd|secret|api_key|apikey|apiKey)\s*[:=]\s*['"]([^'"]*)['"]`).FindStringSubmatch(line)
	if len(match) != 3 {
		return false
	}

	value := strings.TrimSpace(strings.ToLower(match[2]))
	if value == "" {
		return true
	}
	if strings.Trim(value, "•* ") == "" {
		return true
	}

	uiTerms := []string{
		"password", "passwort", "mot de passe", "كلمة المرور", "كلمة مرور",
		"at least", "confirm", "current", "new ", "forgot", "nouveau",
		"caracteres", "caractères", "characters", "zeichen", "أحرف",
	}
	for _, term := range uiTerms {
		if strings.Contains(value, term) {
			return true
		}
	}
	return false
}

func suppressJS042(line string) bool {
	lower := strings.ToLower(line)
	if strings.Contains(lower, "import") && strings.Contains(lower, " from") {
		return true
	}

	sqlContext := []string{"query", "execute", "sql", "statement", "sequelize", "knex", "prisma", "db."}
	for _, token := range sqlContext {
		if strings.Contains(lower, token) {
			return false
		}
	}
	return true
}

func quotedOffsets(line string) []bool {
	quoted := make([]bool, len(line))
	var quote rune
	escaped := false

	for i, r := range line {
		if quote != 0 {
			quoted[i] = true
			if escaped {
				escaped = false
				continue
			}
			if r == '\\' {
				escaped = true
				continue
			}
			if r == quote {
				quote = 0
			}
			continue
		}

		switch r {
		case '\'', '"', '`':
			quote = r
			quoted[i] = true
		}
	}

	return quoted
}

// DetectLanguagePublic is the exported version of detectLanguage for use by
// the single-pass file collector.
func DetectLanguagePublic(path string) Language {
	return detectLanguage(path)
}

// ScanFilePublic is the exported version of scanFile for use by the
// parallel file scanner. It scans a single file with pattern rules.
func (s *Scanner) ScanFilePublic(absPath, root string, lang Language) ([]analysis.Finding, error) {
	return s.scanFile(absPath, root, lang)
}

// detectLanguage determines the programming language from the file extension.
func detectLanguage(path string) Language {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".py", ".pyw":
		return LangPython
	case ".jinja", ".jinja2":
		return LangPython
	case ".js", ".jsx", ".mjs", ".cjs":
		return LangJavaScript
	case ".ts", ".tsx":
		return LangTypeScript
	case ".rb", ".erb", ".rhtml":
		return LangRuby
	case ".php", ".phtml", ".php5", ".php7":
		return LangPHP
	case ".java":
		return LangJava
	case ".cs", ".cshtml":
		return LangCSharp
	case ".rs":
		return LangRust
	case ".yml", ".yaml":
		return LangYAML
	case ".tf", ".tfvars":
		return LangTerraform
	case ".html", ".htm", ".jsp", ".ejs", ".hbs", ".twig":
		return LangHTML
	case ".json":
		// .tf.json is a Terraform JSON config variant
		base := strings.ToLower(filepath.Base(path))
		if strings.HasSuffix(base, ".tf.json") {
			return LangTerraform
		}
		return LangGeneric
	default:
		// Check for special filenames
		base := strings.ToLower(filepath.Base(path))
		if base == "rakefile" || strings.HasSuffix(base, ".rake") {
			return LangRuby
		}
		// Dockerfile: files named "Dockerfile", "Dockerfile.*", ".dockerfile"
		if base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") || base == ".dockerfile" {
			return LangDockerfile
		}
		return ""
	}
}

// ruleAppliesToLanguage checks if a rule applies to the given language.
func ruleAppliesToLanguage(rule PatternRule, lang Language) bool {
	for _, l := range rule.Languages {
		if l == lang {
			return true
		}
	}
	return false
}

// isComment checks if a line is a comment in the given language.
func isComment(line string, lang Language) bool {
	trimmed := strings.TrimSpace(line)
	switch lang {
	case LangPython, LangRuby, LangDockerfile, LangYAML, LangTerraform:
		return strings.HasPrefix(trimmed, "#")
	case LangJavaScript, LangTypeScript, LangPHP, LangJava, LangCSharp, LangRust:
		return strings.HasPrefix(trimmed, "//") ||
			strings.HasPrefix(trimmed, "/*") ||
			strings.HasPrefix(trimmed, "*") ||
			strings.HasPrefix(trimmed, "<!--")
	}
	return false
}

// phpSanitizationFunctions is the set of PHP function/method calls that
// sanitize user input before it reaches a SQL query. When a SQL injection
// pattern match line contains one of these functions wrapping the variable,
// the finding is suppressed because the input is sanitized.
var phpSanitizationFunctions = []string{
	"escapeString",
	"escape_string",
	"mysqli_real_escape_string",
	"mysql_real_escape_string",
	"addslashes",
	"intval",
	"floatval",
	"doubleval",
	"PDO::quote",
	"->quote(",
	"htmlspecialchars",
	"htmlentities",
	"filter_var",
	"filter_input",
	"pg_escape_string",
	"pg_escape_literal",
	"sqlite_escape_string",
	"dbi->escapeString",
	"this->dbi->escapeString",
	"this->_dbi->escapeString",
	"Util::backquote",
	"backquote(",
	// Prepared statement indicators (if the line uses prepare/bindParam/bindValue,
	// the query is parameterized and not vulnerable to SQL injection)
	"->prepare(",
	"->bindParam",
	"->bindValue",
	"->execute(",
	"mysqli_stmt_bind_param",
	"stmt->bind_param",
}

// phpHasSanitization checks whether a line that matched a SQL injection
// pattern also contains a sanitization function call. If the variable in
// the query is wrapped in a sanitization function, the finding is a false
// positive and should be suppressed.
//
// This is a heuristic: it checks whether the line contains any known
// sanitization function call. A more precise approach would use AST
// analysis to verify that the sanitized variable is the same one
// interpolated into the query, but that requires multi-line context.
// The heuristic is conservative — it only suppresses when the line
// clearly shows sanitization, reducing false negatives.
func phpHasSanitization(line string) bool {
	for _, fn := range phpSanitizationFunctions {
		if strings.Contains(line, fn) {
			return true
		}
	}
	return false
}

// makePatternFinding creates a finding from a pattern match.
func makePatternFinding(rule PatternRule, absPath, root string, lineNum int, line string) analysis.Finding {
	relPath, _ := filepath.Rel(root, absPath)
	return analysis.Finding{
		ID:          fmt.Sprintf("pattern-%s-%s-%d", rule.ID, filepath.Base(relPath), lineNum),
		Type:        analysis.TypeSAST,
		Analyzer:    "patterns-embedded",
		Severity:    rule.Severity,
		Confidence:  rule.Confidence,
		Title:       rule.Title,
		Description: rule.Description,
		FilePath:    relPath,
		LineStart:   lineNum,
		RuleID:      rule.ID,
		CWEID:       rule.CWEID,
		Evidence:    strings.TrimSpace(line),
		DetectedAt:  time.Now(),
	}
}
