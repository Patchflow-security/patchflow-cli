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

	"github.com/patchflow/patchflow-cli/internal/analysis"
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

		// Code injection
		{ID: "PY001", Title: "Use of eval() with potential user input", Description: "eval() can execute arbitrary code. Avoid using it, especially with user input.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`\beval\s*\(`)},
		{ID: "PY002", Title: "Use of exec() with potential user input", Description: "exec() can execute arbitrary code. Avoid using it, especially with user input.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`\bexec\s*\(`)},
		{ID: "PY003", Title: "Use of os.system()", Description: "os.system() is vulnerable to command injection. Use subprocess with shell=False instead.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`\bos\.system\s*\(`)},
		{ID: "PY004", Title: "subprocess with shell=True", Description: "subprocess with shell=True is vulnerable to command injection. Use shell=False and pass args as a list.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)shell\s*=\s*True`)},
		{ID: "PY005", Title: "Use of pickle.loads()", Description: "pickle.loads() can execute arbitrary code during deserialization. Avoid unpickling untrusted data.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`\bpickle\.loads?\s*\(`)},
		{ID: "PY006", Title: "Use of yaml.load() without SafeLoader", Description: "yaml.load() without SafeLoader can execute arbitrary code. Use yaml.safe_load() instead.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`\byaml\.load\s*\(`)},

		// SQL injection
		{ID: "PY007", Title: "SQL query with string formatting", Description: "SQL query constructed with string formatting is vulnerable to SQL injection. Use parameterized queries.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)(execute|cursor\.execute)\s*\(\s*(f["']\s*(SELECT|INSERT|UPDATE|DELETE)|["'].*%s.*["']\s*%(.*SELECT|INSERT|UPDATE|DELETE))`), CWEID: "CWE-89", SkipQuoteFilter: true},
		{ID: "PY008", Title: "Raw SQL string concatenation", Description: "SQL query built with string concatenation is vulnerable to SQL injection.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)(query|sql|stmt)\s*[\+]=?\s*.*["'].*\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b`)},

		// Crypto
		{ID: "PY009", Title: "Use of MD5 hash", Description: "MD5 is a weak hash algorithm. Use SHA-256 or stronger.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`\bhashlib\.md5\s*\(`)},
		{ID: "PY010", Title: "Use of SHA1 hash", Description: "SHA1 is a weak hash algorithm. Use SHA-256 or stronger.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`\bhashlib\.sha1\s*\(`)},
		{ID: "PY011", Title: "Use of random module for security", Description: "random module is not cryptographically secure. Use secrets module instead.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)\brandom\.(choice|randint|random|uniform)\s*\(`)},
		{ID: "PY012", Title: "Hardcoded password", Description: "Hardcoded password detected. Use environment variables or a secret manager.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)(password|passwd|pwd)\s*=\s*["'][^"']{4,}["']`)},

		// Network/TLS
		{ID: "PY013", Title: "SSL verification disabled", Description: "SSL certificate verification is disabled. This makes the connection vulnerable to MITM attacks.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)(verify|ssl_verify|insecure)\s*=\s*False\b`)},
		{ID: "PY014", Title: "Requests with verify=False", Description: "Disabling SSL verification in requests is dangerous.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)requests\.(get|post|put|delete|patch|head)\s*\(.*verify\s*=\s*False`)},

		// Debug/dev mode
		{ID: "PY015", Title: "Debug mode enabled", Description: "Debug mode should never be enabled in production.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)debug\s*=\s*True`)},

		// Flask/Django specific
		{ID: "PY016", Title: "Flask app with debug=True", Description: "Running Flask with debug=True exposes the Werkzeug debugger, which can lead to RCE.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)app\.run\s*\(.*debug\s*=\s*True`)},
		{ID: "PY017", Title: "Django ALLOWED_HOSTS wildcard", Description: "ALLOWED_HOSTS = ['*'] allows requests from any host.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)ALLOWED_HOSTS\s*=\s*\[.*['"]\*['"]`)},

		// Additional Python rules (PY018-PY025)
		{ID: "PY018", Title: "Flask SSRF via requests with user-controlled URL", Description: "requests call with a user-controlled URL/host/target/endpoint may be vulnerable to SSRF. Validate and restrict the destination.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)requests\.(get|post|put|delete|patch)\s*\(\s*.*\b(url|host|target|endpoint)\b`)},
		{ID: "PY019", Title: "Path traversal via open() with user input", Description: "open() with a path derived from user input or request data may be vulnerable to path traversal. Validate and sanitize paths.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)\bopen\s*\(\s*.*\b(os\.path\.join|os\.getcwd|request\.|input)\b`)},
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
		{ID: "JS014", Title: "SSRF via axios/fetch with user-controlled URL", Description: "axios/fetch call with a user-controlled URL/host/endpoint may be vulnerable to SSRF. Validate and restrict the destination.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)(axios|fetch)\s*\(\s*.*\b(url|host|endpoint|req\.|request\.)\b`)},
		{ID: "JS015", Title: "Path traversal via fs with user input", Description: "fs.readFile/writeFile/createReadStream/createWriteStream with user-controlled paths may be vulnerable to path traversal. Validate and sanitize paths.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)fs\.(readFile|writeFile|createReadStream|createWriteStream)\s*\(\s*.*\b(req\.|params|query|body)\b`)},
		{ID: "JS016", Title: "SQL injection via Sequelize.query with user input", Description: "sequelize.query with user-controlled input is vulnerable to SQL injection. Use parameterized queries or replacements.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)sequelize\.query\s*\(\s*.*\b(req\.|params|body|query)\b`), CWEID: "CWE-89", SkipQuoteFilter: true},
		{ID: "JS017", Title: "Express body-parser limit too high", Description: "body-parser JSON limit set very high (>= 100MB) can enable denial-of-service via large payloads. Use a reasonable limit.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceLow, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)limit\s*:\s*["'](\d{3,})mb["']`)},
		{ID: "JS018", Title: "Insecure cookie settings", Description: "res.cookie without secure/httpOnly flags may expose cookies to XSS or transport interception. Set secure and httpOnly appropriately.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceLow, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)res\.cookie\s*\(\s*["'][^"']+["']\s*,\s*[^,]+,\s*\{[^}]*\}\s*\)`)},
		{ID: "JS019", Title: "eval in require context", Description: "require() with eval or child_process can lead to arbitrary code execution. Avoid dynamic requires with dangerous modules.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`\brequire\s*\(\s*.*\b(eval|child_process)\b`)},
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
		{ID: "JAVA005", Title: "ObjectInputStream deserialization", Description: "ObjectInputStream can execute arbitrary code during deserialization. Avoid deserializing untrusted data.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`\bObjectInputStream\s*\(`)},

		// Crypto
		{ID: "JAVA006", Title: "Use of MD5 hash", Description: "MD5 is a weak hash algorithm. Use SHA-256 or stronger via MessageDigest.getInstance(\"SHA-256\").", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`\bMessageDigest\.getInstance\s*\(\s*["']MD5["']\s*\)`)},
		{ID: "JAVA007", Title: "Use of SHA1 hash", Description: "SHA1 is a weak hash algorithm. Use SHA-256 or stronger via MessageDigest.getInstance(\"SHA-256\").", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`\bMessageDigest\.getInstance\s*\(\s*["']SHA-?1["']\s*\)`)},
		{ID: "JAVA008", Title: "Use of Random() for security", Description: "java.util.Random is not cryptographically secure. Use java.security.SecureRandom instead.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`\bnew\s+Random\s*\(\s*\)`)},

		// TLS / trust
		{ID: "JAVA009", Title: "TrustAllCerts / X509TrustManager with no check", Description: "A TrustManager that performs no validation disables certificate verification, enabling MITM attacks.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)trustAll|checkServerTrusted\s*\([^)]*\)\s*\{\s*\}`)},

		// JNDI injection
		{ID: "JAVA010", Title: "JNDI injection", Description: "Context.lookup with a user-controlled string can lead to JNDI injection and RCE (e.g. Log4Shell). Avoid untrusted lookup targets.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`\bContext\.lookup\s*\(\s*[^"]*["']`)},

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

		{ID: "JAVA011", Title: "Spring Boot actuator endpoints exposed", Description: "Exposing all actuator endpoints (include=*) can leak sensitive information. Restrict to necessary endpoints.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)management\.endpoints\.web\.exposure\.include\s*=\s*\*`)},
		{ID: "JAVA012", Title: "Spring hardcoded password in properties", Description: "Hardcoded password in Spring properties detected. Use environment variables or a vault.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)password\s*=\s*[^\s${}]+`)},
		{ID: "JAVA013", Title: "Spring datasource URL with credentials", Description: "JDBC URL with embedded credentials may leak secrets. Use environment variables or a secret manager.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)jdbc:.*://[^:]+:[^@]+@`)},
		{ID: "JAVA014", Title: "Java hardcoded AWS key", Description: "Hardcoded AWS access key detected. Use environment variables or IAM roles.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{ID: "JAVA015", Title: "Java System.setProperty trustAll", Description: "Disabling SSL certificate validation via System.setProperty enables MITM attacks. Do not disable certificate checks.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)System\.setProperty\s*\(\s*["']com\.sun\.net\.ssl\.checkEorValidateCert["']`)},
		{ID: "JAVA016", Title: "Java SSLContext.getInstance(\"SSL\")", Description: "SSLContext.getInstance(\"SSL\") uses the deprecated SSL protocol. Use \"TLS\" or \"TLSv1.2\" instead.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)SSLContext\.getInstance\s*\(\s*["']SSL["']\s*\)`)},
		{ID: "JAVA017", Title: "Java HttpsURLConnection.setDefaultHostnameVerifier", Description: "Overriding the default hostname verifier can disable hostname validation, enabling MITM attacks. Avoid overriding.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)HttpsURLConnection\.setDefaultHostnameVerifier`)},
		{ID: "JAVA018", Title: "Java setHostnameVerifier returning true", Description: "A hostname verifier that always returns true disables hostname validation, enabling MITM attacks. Implement proper validation.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)setHostnameVerifier\s*\(\s*\([^)]*\)\s*->\s*true`)},
		{ID: "JAVA019", Title: "Spring @CrossOrigin with wildcard origins", Description: "@CrossOrigin with origins=\"*\" allows requests from any domain. Restrict to trusted origins.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`(?i)@CrossOrigin\s*\(\s*origins\s*=\s*["']\*["']`)},
		{ID: "JAVA020", Title: "Java hardcoded private key", Description: "Hardcoded private key detected. Store keys in a secure vault or key management service.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`-----BEGIN (RSA |EC )?PRIVATE KEY-----`)},
		{ID: "JAVA021", Title: "Java System.exit in web app", Description: "System.exit() in a web application can shut down the entire server, causing denial of service. Avoid it in web contexts.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceLow, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`\bSystem\.exit\s*\(`)},
		{ID: "JAVA022", Title: "Java Thread.sleep in web app", Description: "Thread.sleep() in a web application can block request threads and cause denial of service. Avoid blocking calls in request handlers.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceLow, Languages: []Language{LangJava}, Pattern: regexp.MustCompile(`\bThread\.sleep\s*\(`)},

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
		{ID: "K8S001", Title: "Privileged container in K8s", Description: "securityContext.privileged: true grants full host access.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangYAML}, Pattern: regexp.MustCompile(`(?i)privileged:\s*true`)},
		{ID: "K8S002", Title: "Container runs as root", Description: "runAsUser: 0 or missing runAsUser means the container runs as root.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangYAML}, Pattern: regexp.MustCompile(`runAsUser:\s*0\b`)},
		{ID: "K8S004", Title: "allowPrivilegeEscalation not false", Description: "allowPrivilegeEscalation should be set to false.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangYAML}, Pattern: regexp.MustCompile(`allowPrivilegeEscalation:\s*true`)},
		{ID: "K8S005", Title: "readOnlyRootFilesystem not set", Description: "readOnlyRootFilesystem should be true to prevent writes to the root filesystem.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceLow, Languages: []Language{LangYAML}, Pattern: regexp.MustCompile(`readOnlyRootFilesystem:\s*false`)},
		{ID: "K8S006", Title: "Host network enabled", Description: "hostNetwork: true gives the container access to the host's network interfaces.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangYAML}, Pattern: regexp.MustCompile(`hostNetwork:\s*true`)},
		{ID: "K8S007", Title: "Host PID enabled", Description: "hostPID: true gives the container access to the host's process namespace.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangYAML}, Pattern: regexp.MustCompile(`hostPID:\s*true`)},
		{ID: "K8S008", Title: "Host IPC enabled", Description: "hostIPC: true gives the container access to the host's IPC namespace.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangYAML}, Pattern: regexp.MustCompile(`hostIPC:\s*true`)},
		{ID: "K8S009", Title: "CAP_SYS_ADMIN in securityContext", Description: "CAP_SYS_ADMIN grants broad privileges. Drop all capabilities and add only needed ones.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangYAML}, Pattern: regexp.MustCompile(`(?i)SYS_ADMIN`)},
		{ID: "K8S010", Title: "Image uses latest tag", Description: "Using :latest in Kubernetes manifests leads to non-reproducible deployments.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangYAML}, Pattern: regexp.MustCompile(`image:\s*\S+:latest\b`)},

		// --- Terraform security rules (TF001-TF010) ---
		{ID: "TF001", Title: "AWS S3 bucket without versioning", Description: "S3 bucket should have versioning enabled for data recovery.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`(?i)aws_s3_bucket\b`)},
		{ID: "TF002", Title: "AWS S3 bucket public ACL", Description: "S3 bucket has a public-read or public-read-write ACL.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`(?i)(public-read|public-read-write|website_endpoint)`)},
		{ID: "TF003", Title: "Security group allows 0.0.0.0/0", Description: "Security group rule allows traffic from anywhere (0.0.0.0/0).", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`0\.0\.0\.0/0`)},
		{ID: "TF004", Title: "Hardcoded credentials in Terraform", Description: "Terraform resource contains hardcoded password or secret key.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`(?i)(password|secret_key|api_key|access_key)\s*=\s*["'][^"']{8,}["']`)},
		{ID: "TF005", Title: "RDS instance publicly accessible", Description: "RDS instance has publicly_accessible = true.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`publicly_accessible\s*=\s*true`)},
		{ID: "TF006", Title: "S3 bucket without encryption", Description: "S3 bucket should have server-side encryption enabled.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`(?i)aws_s3_bucket\b`)},
		{ID: "TF007", Title: "IAM policy with wildcard action", Description: "IAM policy uses Action: * or Resource: *, granting overly broad permissions.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`(?i)(Action|Resource)\s*=\s*["']?\*["']?`)},
		{ID: "TF008", Title: "No TLS for database", Description: "RDS or database resource does not enforce TLS/SSL connections.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceLow, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`(?i)require_ssl\s*=\s*false`)},
		{ID: "TF009", Title: "Lambda with excessive timeout", Description: "Lambda function has timeout > 300 seconds, which can increase cost and complexity.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceLow, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`timeout\s*=\s*(3[0-9]{2}|[4-9][0-9]{2}|[0-9]{4,})`)},
		{ID: "TF010", Title: "EKS cluster endpoint public", Description: "EKS cluster has public endpoint access enabled.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangTerraform}, Pattern: regexp.MustCompile(`(?i)endpoint_public_access\s*=\s*true`)},

		// --- API security rules (API001-API010) ---
		{ID: "API001", Title: "GraphQL introspection enabled in production", Description: "GraphQL introspection can expose the entire schema to attackers.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript, LangPython}, Pattern: regexp.MustCompile(`(?i)introspection:\s*true`)},
		{ID: "API003", Title: "CORS wildcard in API config", Description: "CORS allows all origins (*), which can enable cross-site attacks.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript, LangPython, LangRuby, LangPHP}, Pattern: regexp.MustCompile(`(?i)(origins|origin|Access-Control-Allow-Origin)\s*[=:]\s*["']\*["']`)},
		{ID: "API005", Title: "JWT without expiry", Description: "JWT token does not set an expiration, increasing the risk of token theft.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript, LangPython, LangRuby, LangPHP, LangJava}, Pattern: regexp.MustCompile(`(?i)expiresIn|exp:\s*0|noExpiry|neverExpires`)},
		{ID: "API006", Title: "API key in URL parameter", Description: "API key passed as a URL parameter can be logged in access logs and browser history.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangGeneric}, Pattern: regexp.MustCompile(`(?i)(api_key|apikey|access_token)\s*=\s*[{]?\w+[}]?`)},
		{ID: "API007", Title: "Insecure HTTP for API calls", Description: "API calls over HTTP transmit data unencrypted.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript, LangPython, LangRuby, LangPHP, LangJava}, Pattern: regexp.MustCompile(`http://[a-zA-Z0-9]`)},
		{ID: "API010", Title: "gRPC without TLS", Description: "gRPC server configured without TLS transmits data in plaintext.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangGeneric}, Pattern: regexp.MustCompile(`(?i)useTransportSecurity\s*=\s*false|grpc\.Insecure`)},

		// --- CWE-tagged rules for benchmark recall (CWE-89, CWE-22, CWE-352, CWE-94, CWE-601, CWE-918) ---

		// PHP SQL injection via mysqli_query with variable interpolation (CWE-89)
		{ID: "PHP009", Title: "PHP SQL injection via mysqli_query with variable", Description: "mysqli_query with a query string containing interpolated variables is vulnerable to SQL injection. Use prepared statements with mysqli_stmt_bind_param().", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)mysqli_query\s*\([^,]+,\s*["'].*\$\w+`), CWEID: "CWE-89", SkipQuoteFilter: true},
		{ID: "PHP010", Title: "PHP SQL injection via PDO query with variable", Description: "PDO::query() with a query string containing interpolated variables is vulnerable to SQL injection. Use prepared statements with prepare() and execute().", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)->query\s*\(\s*["'].*\$\w+`), CWEID: "CWE-89", SkipQuoteFilter: true},
		{ID: "PHP011", Title: "PHP SQL injection via string concatenation in query", Description: "SQL query built with string concatenation (.) and user input is vulnerable to SQL injection. Use prepared statements.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b.*["'].*\.\s*\$\w+`), CWEID: "CWE-89", SkipQuoteFilter: true},
		// PHP SQL injection via variable interpolation in query string (CWE-89)
		{ID: "PHP016", Title: "PHP SQL injection via variable interpolation in query", Description: "SQL query string with interpolated PHP variables ($var) is vulnerable to SQL injection. Use prepared statements with parameter binding.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)["'].*\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|INTO)\b.*\$\w+.*["']`), CWEID: "CWE-89", SkipQuoteFilter: true},

		// PHP path traversal via include/require with $_GET/$_POST (CWE-22)
		{ID: "PHP012", Title: "PHP path traversal via include with superglobal", Description: "include/require with $_GET/$_POST/$_REQUEST allows path traversal and LFI/RFI. Use a whitelist of allowed files.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)(include|require)(_once)?\s*\(?\s*\$_(GET|POST|REQUEST|SERVER)`), CWEID: "CWE-22"},
		{ID: "PHP013", Title: "PHP path traversal via file operations with superglobal", Description: "file_get_contents/fopen/readfile with $_GET/$_POST/$_REQUEST allows path traversal. Validate and canonicalize paths.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)(file_get_contents|fopen|readfile|file)\s*\(\s*\$_(GET|POST|REQUEST)`), CWEID: "CWE-22"},

		// PHP CSRF: state-changing GET request with database write (CWE-352)
		{ID: "PHP014", Title: "PHP CSRF via GET request with state change", Description: "State-changing operation (UPDATE/INSERT/DELETE) triggered by $_GET without CSRF token validation. Use POST with CSRF tokens.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)\$_GET\s*\[.*['"]?(Change|Update|Delete|Submit|Action)['"]?\]`), CWEID: "CWE-352"},
		{ID: "PHP015", Title: "PHP CSRF: password change via GET without token", Description: "Password change operation via GET request without CSRF token. Use POST with CSRF token validation.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)\$_GET\s*\[.*password`), CWEID: "CWE-352"},

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

func matchesRule(rule PatternRule, line string, lang Language) bool {
	if isComment(line, lang) && rule.ID != "XLANG002" {
		return false
	}

	matches := rule.Pattern.FindAllStringIndex(line, -1)
	if len(matches) == 0 {
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
	case ".js", ".jsx", ".mjs", ".cjs":
		return LangJavaScript
	case ".ts", ".tsx":
		return LangTypeScript
	case ".rb":
		return LangRuby
	case ".php":
		return LangPHP
	case ".java", ".jsp":
		return LangJava
	case ".cs":
		return LangCSharp
	case ".rs":
		return LangRust
	case ".yml", ".yaml":
		return LangYAML
	case ".tf", ".tfvars":
		return LangTerraform
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
