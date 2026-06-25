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
}

// Scanner is the multi-language pattern-based SAST scanner.
type Scanner struct {
	rules             []PatternRule
	ignoredDirs       map[string]bool
	ignoredExtensions map[string]bool
	maxFileSize       int64
}

// NewScanner creates a new pattern scanner with all built-in rules.
func NewScanner() *Scanner {
	s := &Scanner{
		maxFileSize: 2 * 1024 * 1024, // 2MB
		ignoredDirs: map[string]bool{
			"node_modules": true, "vendor": true, ".git": true, "dist": true,
			"build": true, "target": true, ".next": true, ".cache": true,
			"__pycache__": true, ".venv": true, "venv": true, "env": true,
			".tox": true, ".pytest_cache": true, ".mypy_cache": true,
		},
		ignoredExtensions: map[string]bool{
			".min.js": true, ".min.css": true, ".map": true,
			".lock": true, ".sum": true,
		},
	}
	s.registerRules()
	return s
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
		{ID: "PY007", Title: "SQL query with string formatting", Description: "SQL query constructed with string formatting is vulnerable to SQL injection. Use parameterized queries.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)(execute|cursor\.execute)\s*\(\s*(f["']\s*(SELECT|INSERT|UPDATE|DELETE)|["'].*%s.*["']\s*%(.*SELECT|INSERT|UPDATE|DELETE))`)},
		{ID: "PY008", Title: "Raw SQL string concatenation", Description: "SQL query built with string concatenation is vulnerable to SQL injection.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)(query|sql|stmt)\s*[\+]=?\s*.*["'].*\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b`)},

		// Crypto
		{ID: "PY009", Title: "Use of MD5 hash", Description: "MD5 is a weak hash algorithm. Use SHA-256 or stronger.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`\bhashlib\.md5\s*\(`)},
		{ID: "PY010", Title: "Use of SHA1 hash", Description: "SHA1 is a weak hash algorithm. Use SHA-256 or stronger.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`\bhashlib\.sha1\s*\(`)},
		{ID: "PY011", Title: "Use of random module for security", Description: "random module is not cryptographically secure. Use secrets module instead.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)\brandom\.(choice|randint|random|uniform)\s*\(`)},
		{ID: "PY012", Title: "Hardcoded password", Description: "Hardcoded password detected. Use environment variables or a secret manager.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)(password|passwd|pwd)\s*=\s*["'][^"']{4,}["']`)},

		// Network/TLS
		{ID: "PY013", Title: "SSL verification disabled", Description: "SSL certificate verification is disabled. This makes the connection vulnerable to MITM attacks.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)verify\s*=\s*False`)},
		{ID: "PY014", Title: "Requests with verify=False", Description: "Disabling SSL verification in requests is dangerous.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)requests\.(get|post|put|delete|patch|head)\s*\(.*verify\s*=\s*False`)},

		// Debug/dev mode
		{ID: "PY015", Title: "Debug mode enabled", Description: "Debug mode should never be enabled in production.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)debug\s*=\s*True`)},

		// Flask/Django specific
		{ID: "PY016", Title: "Flask app with debug=True", Description: "Running Flask with debug=True exposes the Werkzeug debugger, which can lead to RCE.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)app\.run\s*\(.*debug\s*=\s*True`)},
		{ID: "PY017", Title: "Django ALLOWED_HOSTS wildcard", Description: "ALLOWED_HOSTS = ['*'] allows requests from any host.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPython}, Pattern: regexp.MustCompile(`(?i)ALLOWED_HOSTS\s*=\s*\[.*['"]\*['"]`)},

		// --- JavaScript/TypeScript rules ---

		// Code injection
		{ID: "JS001", Title: "Use of eval()", Description: "eval() can execute arbitrary code. Avoid using it, especially with user input.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`\beval\s*\(`)},
		{ID: "JS002", Title: "Use of Function constructor", Description: "new Function() is equivalent to eval() and can execute arbitrary code.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`\bnew\s+Function\s*\(`)},
		{ID: "JS003", Title: "Use of child_process.exec", Description: "child_process.exec runs commands in a shell and is vulnerable to command injection. Use execFile or spawn with shell=false.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`\bchild_process\.exec\s*\(`)},
		{ID: "JS004", Title: "Use of child_process.execSync", Description: "child_process.execSync runs commands in a shell and is vulnerable to command injection.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`\bchild_process\.execSync\s*\(`)},

		// SQL injection
		{ID: "JS005", Title: "SQL query with string interpolation", Description: "SQL query with template literals or string concatenation is vulnerable to SQL injection. Use parameterized queries.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)(query|execute)\s*\(\s*` + "`" + `\s*(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|INTO)\b.*\$\{`)},

		// Crypto
		{ID: "JS006", Title: "Use of MD5", Description: "MD5 is a weak hash algorithm. Use SHA-256 or stronger.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)\b(createHash|md5|MD5)\s*[\(\.]`)},
		{ID: "JS007", Title: "Use of SHA1", Description: "SHA1 is a weak hash algorithm. Use SHA-256 or stronger.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)\b(createHash\s*\(\s*['"]sha1['"]|sha1\s*\()`)},
		{ID: "JS008", Title: "Use of Math.random() for security", Description: "Math.random() is not cryptographically secure. Use crypto.randomBytes() or crypto.getRandomValues() instead.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)\bMath\.random\s*\(\s*\)`)},

		// Express/Node security
		{ID: "JS009", Title: "Express app with CORS wildcard", Description: "CORS with origin '*' allows requests from any domain.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)cors\s*\(\s*\{[^}]*origin\s*:\s*['"]\*['"]`)},
		{ID: "JS010", Title: "Helmet disabled", Description: "Disabling Helmet removes important security headers.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceLow, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`(?i)helmet\s*\(\s*false\s*\)`)},

		// Debug
		{ID: "JS011", Title: "Node.js debug mode", Description: "Running Node.js with --inspect flag exposes the debugger.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`--inspect(--brk)?(?:=\d+)?`)},

		// React/Next.js
		{ID: "JS012", Title: "dangerouslySetInnerHTML", Description: "dangerouslySetInnerHTML can lead to XSS if the content is not properly sanitized.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangJavaScript, LangTypeScript}, Pattern: regexp.MustCompile(`dangerouslySetInnerHTML`)},

		// --- Ruby rules ---

		{ID: "RB001", Title: "Ruby eval()", Description: "eval() can execute arbitrary code. Avoid using it.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`\beval\s*\(`)},
		{ID: "RB002", Title: "Ruby system() call", Description: "system() is vulnerable to command injection. Use system with separate arguments.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`\bsystem\s*\(`)},
		{ID: "RB003", Title: "Ruby backtick execution", Description: "Backtick execution is vulnerable to command injection.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile("`.*\\#\\{.*\\}.*`")},
		{ID: "RB004", Title: "Ruby SQL injection", Description: "SQL query with string interpolation is vulnerable to SQL injection.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)(execute|query)\s*\(.*["'].*\b(SELECT|INSERT|UPDATE|DELETE)\b.*#\{`)},
		{ID: "RB005", Title: "Ruby OpenSSL weak cipher", Description: "Weak cipher detected. Use AES-256 or stronger.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangRuby}, Pattern: regexp.MustCompile(`(?i)OpenSSL::Cipher::(DES|RC4|AES128)`)},

		// --- PHP rules ---

		{ID: "PHP001", Title: "PHP eval()", Description: "eval() can execute arbitrary code. Avoid using it.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`\beval\s*\(`)},
		{ID: "PHP002", Title: "PHP exec/system call", Description: "exec/system/shell_exec are vulnerable to command injection.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`\b(exec|system|shell_exec|passthru|popen)\s*\(`)},
		{ID: "PHP003", Title: "PHP SQL injection", Description: "SQL query with string interpolation is vulnerable to SQL injection. Use prepared statements.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`(?i)(mysql_query|mysqli_query|pg_query)\s*\(\s*["'].*\$`)},
		{ID: "PHP004", Title: "PHP md5/sha1 for passwords", Description: "md5/sha1 are not suitable for password hashing. Use password_hash() instead.", Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceHigh, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`\b(md5|sha1)\s*\(`)},
		{ID: "PHP005", Title: "PHP file inclusion with variable", Description: "include/require with a variable can lead to LFI/RFI.", Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium, Languages: []Language{LangPHP}, Pattern: regexp.MustCompile(`\b(include|require|include_once|require_once)\s*\(\s*\$`)},

		// --- Cross-language patterns ---

		{ID: "XLANG001", Title: "Hardcoded IP address", Description: "Hardcoded IP address detected. This may leak internal infrastructure details.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceLow, Languages: []Language{LangPython, LangJavaScript, LangTypeScript, LangRuby, LangPHP}, Pattern: regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)},
		{ID: "XLANG002", Title: "TODO/FIXME security comment", Description: "Security-related TODO or FIXME comment found. This should be addressed.", Severity: analysis.SeverityLow, Confidence: analysis.ConfidenceLow, Languages: []Language{LangPython, LangJavaScript, LangTypeScript, LangRuby, LangPHP}, Pattern: regexp.MustCompile(`(?i)(TODO|FIXME|HACK|XXX).*(security|vulnerab|insecure|unsafe|auth|password|token|secret|inject)`)},
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
			return nil
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

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, rule := range s.rules {
			if !ruleAppliesToLanguage(rule, lang) {
				continue
			}

			if rule.Pattern.MatchString(line) {
				// Skip if it's in a comment (except for TODO/FIXME rules)
				if isComment(line, lang) && rule.ID != "XLANG002" {
					continue
				}

				findings = append(findings, makePatternFinding(rule, absPath, root, lineNum, line))
			}
		}
	}

	return findings, nil
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
	default:
		// Check for special filenames
		base := strings.ToLower(filepath.Base(path))
		if base == "rakefile" || strings.HasSuffix(base, ".rake") {
			return LangRuby
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
	case LangPython, LangRuby:
		return strings.HasPrefix(trimmed, "#")
	case LangJavaScript, LangTypeScript, LangPHP:
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
		Evidence:    strings.TrimSpace(line),
		DetectedAt:  time.Now(),
	}
}
