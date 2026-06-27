package patterns

import (
	"regexp"
	"strings"
)

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
