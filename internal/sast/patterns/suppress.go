package patterns

import (
	"regexp"
	"strings"
)

// suppressJS051 checks whether a JS051 (exec with string literal) match is a
// false positive. The regex matches exec("...") but if the argument is a
// static string with no variable interpolation, it's not command injection.
func suppressJS051(line string) bool {
	// If the line contains variable concatenation (+) or template literals (${...}),
	// it's potentially vulnerable — don't suppress
	if strings.Contains(line, "+") || strings.Contains(line, "${") {
		return false
	}
	// If it's a static string with no concatenation, suppress
	// Check if the exec argument is a pure string literal
	execRe := regexp.MustCompile(`(?i)\bexec\s*\(\s*['"]([^'"]+)['"]\s*\)`)
	if execRe.MatchString(line) {
		return true
	}
	return false
}

// suppressJS044 checks whether a JS044 (innerHTML XSS) match is a false
// positive from known third-party library code. The regex matches any
// `.innerHTML = <variable>` pattern, which produces false positives in:
//   - Calendar widgets: calendar.js, datepicker libraries
//   - DOM utility libraries that use innerHTML for rendering
//   - "Impossible" (secure) variants in benchmark suites
//
// This function checks the line content for known library patterns. A more
// robust solution would pass the file path to SuppressFunc, but that requires
// architectural changes.
func suppressJS044(line string) bool {
	// Calendar library patterns (e.g., DHTML calendar, JSCal2)
	if strings.Contains(line, "Calendar._TT") ||
		strings.Contains(line, "cal.convertNumbers") ||
		strings.Contains(line, "cal.date") ||
		strings.Contains(line, "Calendar._DN") ||
		strings.Contains(line, "cal.minYear") ||
		strings.Contains(line, "cal.maxYear") {
		return true
	}
	// jQuery/plugin patterns that use innerHTML for DOM construction
	if strings.Contains(line, "jQuery") && strings.Contains(line, "innerHTML") {
		return true
	}
	return false
}

// suppressJAVA012 checks whether a JAVA012 (hardcoded password) match is a
// false positive. The regex matches any `password = <value>` pattern, which
// produces false positives on:
//   - Setter assignments: this.password = password
//   - Field declarations: private String password = ""
//   - Empty string defaults: password = ""
//   - Placeholder values: password = "xxx" or password = "changeme"
//   - Variable-to-variable assignments: password = input
//
// Real hardcoded secrets are string literals with meaningful content (4+ chars,
// not a placeholder, not empty, not a variable name).
func suppressJAVA012(line string) bool {
	trimmed := strings.TrimSpace(line)

	// Suppress setter assignments: this.password = password (RHS is a bare identifier)
	// Pattern: this.X = X  or  this.X = y (variable, not literal)
	if regexp.MustCompile(`(?i)this\.\w+\s*=\s*\w+\s*[;{]`).MatchString(trimmed) {
		// Check if RHS is a string literal — if not, it's a variable assignment
		if !strings.Contains(trimmed, "\"") && !strings.Contains(trimmed, "'") {
			return true
		}
	}

	// Suppress field declarations with empty string default
	// Pattern: private/protected/public String password = ""
	if regexp.MustCompile(`(?i)(private|protected|public)\s+.*\b\w+\s*=\s*""\s*;`).MatchString(trimmed) {
		return true
	}

	// Suppress empty string assignments: password = ""
	if regexp.MustCompile(`(?i)\bpassword\s*=\s*""\s*;`).MatchString(trimmed) {
		return true
	}

	// Suppress variable-to-variable assignments: password = someVariable;
	// (no quotes on RHS means it's not a literal)
	rhsMatch := regexp.MustCompile(`(?i)\bpassword\s*=\s*(.+?);`).FindStringSubmatch(trimmed)
	if len(rhsMatch) >= 2 {
		rhs := strings.TrimSpace(rhsMatch[1])
		// If RHS doesn't start with a quote, it's not a string literal
		if !strings.HasPrefix(rhs, "\"") && !strings.HasPrefix(rhs, "'") {
			return true
		}
		// If RHS is an empty string or placeholder, suppress
		rhsVal := strings.Trim(rhs, "\"'")
		if rhsVal == "" || rhsVal == "xxx" || rhsVal == "changeme" ||
			rhsVal == "placeholder" || rhsVal == "todo" || rhsVal == "YOUR_PASSWORD" {
			return true
		}
		// If the value looks like a config key name (all lowercase + underscores), suppress
		if isConfigKeyName(rhsVal) {
			return true
		}
	}

	// Suppress setter method patterns: setPassword(String password) { this.password = password; }
	if regexp.MustCompile(`(?i)setPassword\s*\(`).MatchString(trimmed) {
		return true
	}

	return false
}

// suppressPY045 checks whether a PY045 (hardcoded password/secret) match is a
// false positive. The regex matches any variable whose name contains
// "password"/"secret"/"token" assigned to a string of 4+ chars. This produces
// false positives on:
//   - Config key names: oauthTokenKey = "oauth_token"
//   - URL token names:  reset_url_token = "set-password"
//   - String constants: token = "is not"
//   - SQL templates:    set_password = 'ALTER USER %(user)s ...'
//
// Real secrets have high entropy (hex strings, base64, etc.) or contain digits
// mixed with letters. Config key names are purely [a-z_\- ]+.
func suppressPY045(line string) bool {
	val := extractStringValue(line)
	if val == "" {
		return false
	}

	// Suppress SQL templates with format specifiers
	if strings.Contains(val, "%(") {
		return true
	}

	// Suppress values that are purely lowercase letters, underscores, dashes,
	// and spaces — these are config key names, not secrets.
	// Examples: "oauth_token", "set-password", "is not", "_password_reset_token"
	if isConfigKeyName(val) {
		return true
	}

	return false
}

// suppressPY006 checks whether a PY006 (yaml.load without SafeLoader) match is
// a false positive. The regex matches yaml.load( on any line, but
// yaml.load(stream, Loader=SafeLoader) is safe.
func suppressPY006(line string) bool {
	// If the line contains SafeLoader or safe_load, it's not a vulnerability.
	if strings.Contains(line, "SafeLoader") ||
		strings.Contains(line, "CSafeLoader") ||
		strings.Contains(line, "safe_load") {
		return true
	}
	return false
}

// suppressPY013 checks whether a PY013 (SSL verification disabled) match is a
// false positive. The regex matches (verify|ssl_verify|insecure)=False, but
// insecure=False means verification IS enabled (inverted logic).
func suppressPY013(line string) bool {
	// insecure=False is GOOD — it means secure mode is on.
	// Only insecure=True is a vulnerability.
	if strings.Contains(line, "insecure") {
		if strings.Contains(line, "insecure=False") ||
			strings.Contains(line, "insecure = False") ||
			strings.Contains(line, "insecure= False") ||
			strings.Contains(line, "insecure =False") {
			return true
		}
	}
	return false
}

// suppressPY019 checks whether a PY019 (path traversal via open) match is a
// false positive. The regex matches open(...os.path.join...), but many uses
// are internal file operations (e.g., creating __init__.py files in migration
// directories) that don't involve user input.
func suppressPY019(line string) bool {
	// Internal Python package files — not user input.
	if strings.Contains(line, "__init__.py") ||
		strings.Contains(line, "__pycache__") ||
		strings.Contains(line, "conftest.py") {
		return true
	}
	return false
}

// extractStringValue extracts the first single- or double-quoted string value
// from a line like: varname = "value"  or  varname = 'value'
var stringValueRe = regexp.MustCompile(`['"]([^'"]{4,})['"]`)

func extractStringValue(line string) string {
	m := stringValueRe.FindStringSubmatch(line)
	if len(m) >= 2 {
		return m[1]
	}
	return ""
}

// isConfigKeyName returns true if the value looks like a config key name
// rather than a real secret. Config key names are purely lowercase letters,
// underscores, dashes, and spaces, with no digits and no dots. Dots indicate
// a filename (e.g., "make.bat") or a dotted path, which is not a config key.
var configKeyRe = regexp.MustCompile(`^[a-z_][a-z_\- ]*$`)

func isConfigKeyName(val string) bool {
	// Must be at least 4 chars and purely lowercase letters/underscores/dashes
	if len(val) < 4 {
		return false
	}
	// Contains digits → likely a real secret, not a config key
	if strings.ContainsAny(val, "0123456789") {
		return false
	}
	return configKeyRe.MatchString(val)
}
