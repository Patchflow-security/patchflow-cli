package rules

import "strings"

// RuleMetadata is the unified governance metadata for a single detection rule.
// It is engine-agnostic: every rule from every scanner engine gets a
// RuleMetadata entry in the registry.
type RuleMetadata struct {
	// ID is the unique rule identifier (e.g., "PY001", "G104", "SECRET-aws").
	ID string `json:"id"`

	// Engine is the scanner engine that produces this rule.
	Engine Engine `json:"engine"`

	// Title is the human-readable rule name.
	Title string `json:"title"`

	// Description explains what the rule detects.
	Description string `json:"description,omitempty"`

	// Severity is the rule's severity level (critical, high, medium, low, info).
	Severity string `json:"severity"`

	// Confidence is the rule's confidence level (high, medium, low).
	Confidence string `json:"confidence,omitempty"`

	// Language is the primary language this rule targets (go, python, multi, secrets).
	Language string `json:"language,omitempty"`

	// CWE is the CWE identifier(s) for this rule (e.g., "CWE-95").
	CWE string `json:"cwe,omitempty"`

	// OWASP is the OWASP Top 10 category (e.g., "A03:2021-Injection").
	OWASP string `json:"owasp,omitempty"`

	// Maturity is the governance maturity level.
	Maturity Maturity `json:"maturity"`

	// Profiles lists which scan profiles include this rule.
	Profiles []Profile `json:"profiles"`

	// BlockingEligible indicates whether this rule can contribute to a
	// non-zero exit code in CI mode. A rule is blocking-eligible if it is
	// stable or enterprise maturity AND severity is high or critical.
	BlockingEligible bool `json:"blocking_eligible"`

	// Recommendation is the fix guidance for this rule.
	Recommendation string `json:"recommendation,omitempty"`

	// Category is the security category (injection, crypto, secrets, etc.).
	Category string `json:"category,omitempty"`
}

// IsBlockingEligible computes whether a rule should be eligible to block PRs
// based on its maturity and severity. Stable+ maturity and high+ severity
// are required.
func IsBlockingEligible(maturity Maturity, severity string) bool {
	if !maturity.CanBlock() {
		return false
	}
	s := strings.ToLower(severity)
	return s == "high" || s == "critical"
}

// CategoryFromRuleID infers the security category from a rule ID prefix.
// This is used as a fallback when no explicit category is set.
func CategoryFromRuleID(id string) string {
	switch {
	case strings.HasPrefix(id, "SECRET-"):
		return "secrets"
	case strings.HasPrefix(id, "G701"), strings.HasPrefix(id, "G702"),
		strings.HasPrefix(id, "G703"), strings.HasPrefix(id, "G704"),
		strings.HasPrefix(id, "G705"), strings.HasPrefix(id, "G706"),
		strings.HasPrefix(id, "G707"), strings.HasPrefix(id, "G708"),
		strings.HasPrefix(id, "G709"), strings.HasPrefix(id, "G710"):
		return "injection"
	case strings.HasPrefix(id, "G201"), strings.HasPrefix(id, "G202"):
		return "injection"
	case strings.HasPrefix(id, "G204"):
		return "injection"
	case strings.HasPrefix(id, "G101"):
		return "secrets"
	case strings.HasPrefix(id, "G103"):
		return "unsafe"
	case strings.HasPrefix(id, "G104"):
		return "error-handling"
	case strings.HasPrefix(id, "G108"), strings.HasPrefix(id, "G109"),
		strings.HasPrefix(id, "G110"), strings.HasPrefix(id, "G111"),
		strings.HasPrefix(id, "G112"):
		return "error-handling"
	case strings.HasPrefix(id, "G115"), strings.HasPrefix(id, "G116"),
		strings.HasPrefix(id, "G117"):
		return "crypto"
	case strings.HasPrefix(id, "G301"), strings.HasPrefix(id, "G302"),
		strings.HasPrefix(id, "G306"), strings.HasPrefix(id, "G307"):
		return "file-permissions"
	case strings.HasPrefix(id, "G402"):
		return "tls"
	case strings.HasPrefix(id, "G501"), strings.HasPrefix(id, "G601"),
		strings.HasPrefix(id, "G602"):
		return "crypto"
	case strings.HasPrefix(id, "PY001"), strings.HasPrefix(id, "PY002"),
		strings.HasPrefix(id, "PY003"), strings.HasPrefix(id, "PY004"),
		strings.HasPrefix(id, "PY005"):
		return "injection"
	case strings.HasPrefix(id, "JS001"), strings.HasPrefix(id, "JS002"):
		return "injection"
	case strings.HasPrefix(id, "TP-"):
		return "injection"
	case strings.HasPrefix(id, "TS-"):
		return categoryFromTSPrefix(id)
	default:
		return "general"
	}
}

func categoryFromTSPrefix(id string) string {
	// Tree-sitter rules mirror pattern rule IDs with a TS- prefix.
	// Strip the TS- prefix and reuse the pattern-based categorization.
	if strings.HasPrefix(id, "TS-") {
		return CategoryFromRuleID(strings.TrimPrefix(id, "TS-"))
	}
	return "general"
}

// CWEFromRuleID returns the CWE identifier for a rule based on its ID.
// This is a heuristic mapping based on rule prefixes and categories.
func CWEFromRuleID(id string) string {
	// Strip TS- prefix for tree-sitter rules (they mirror pattern rules).
	normalizedID := strings.TrimPrefix(id, "TS-")

	switch {
	// eval/exec/code injection
	case strings.HasPrefix(normalizedID, "PY001") || strings.HasPrefix(normalizedID, "PY002") ||
		strings.HasPrefix(normalizedID, "JS001") || strings.HasPrefix(normalizedID, "JS002"):
		return "CWE-95"

	// os.system / command injection
	case strings.HasPrefix(normalizedID, "PY003") || strings.HasPrefix(normalizedID, "PY004"):
		return "CWE-78"

	// deserialization
	case strings.HasPrefix(normalizedID, "PY005") || strings.HasPrefix(normalizedID, "G710"):
		return "CWE-502"

	// SQL injection
	case strings.HasPrefix(normalizedID, "G201") || strings.HasPrefix(normalizedID, "G202") ||
		strings.HasPrefix(normalizedID, "G701") || strings.HasPrefix(normalizedID, "TP-PY001") ||
		strings.HasPrefix(normalizedID, "TP-JS001"):
		return "CWE-89"

	// Command injection
	case strings.HasPrefix(normalizedID, "G204") || strings.HasPrefix(normalizedID, "G702") ||
		strings.HasPrefix(normalizedID, "TP-PY002") || strings.HasPrefix(normalizedID, "TP-JS002"):
		return "CWE-78"

	// Path traversal
	case strings.HasPrefix(normalizedID, "G703") || strings.HasPrefix(normalizedID, "G304") ||
		strings.HasPrefix(normalizedID, "TP-PY003") || strings.HasPrefix(normalizedID, "TP-JS004"):
		return "CWE-22"

	// SSRF
	case strings.HasPrefix(normalizedID, "G704") || strings.HasPrefix(normalizedID, "TP-PY004") ||
		strings.HasPrefix(normalizedID, "TP-JS005"):
		return "CWE-918"

	// Open redirect
	case strings.HasPrefix(normalizedID, "G705") || strings.HasPrefix(normalizedID, "TP-JS006"):
		return "CWE-601"

	// XSS
	case strings.HasPrefix(normalizedID, "G709") || strings.HasPrefix(normalizedID, "TP-PY006") ||
		strings.HasPrefix(normalizedID, "TP-JS003"):
		return "CWE-79"

	// SSTI
	case strings.HasPrefix(normalizedID, "G708"):
		return "CWE-1336"

	// Log injection
	case strings.HasPrefix(normalizedID, "G706"):
		return "CWE-117"

	// SMTP header injection
	case strings.HasPrefix(normalizedID, "G707"):
		return "CWE-93"

	// Hardcoded credentials
	case strings.HasPrefix(normalizedID, "G101") || strings.HasPrefix(normalizedID, "SECRET-"):
		return "CWE-798"

	// Weak crypto
	case strings.HasPrefix(normalizedID, "G115") || strings.HasPrefix(normalizedID, "G116") ||
		strings.HasPrefix(normalizedID, "G501") || strings.HasPrefix(normalizedID, "G601"):
		return "CWE-327"

	// Error handling
	case strings.HasPrefix(normalizedID, "G104"):
		return "CWE-755"

	// File permissions
	case strings.HasPrefix(normalizedID, "G301") || strings.HasPrefix(normalizedID, "G302") ||
		strings.HasPrefix(normalizedID, "G306"):
		return "CWE-732"

	// TLS
	case strings.HasPrefix(normalizedID, "G402"):
		return "CWE-295"

	// Prototype pollution
	case strings.HasPrefix(normalizedID, "TP-JS007"):
		return "CWE-1321"

	// Unsafe
	case strings.HasPrefix(normalizedID, "G103"):
		return "CWE-758"
	}

	return ""
}

// OWASPFromCWE maps a CWE identifier to its OWASP Top 10 2021 category.
func OWASPFromCWE(cwe string) string {
	switch cwe {
	case "CWE-89", "CWE-95", "CWE-78", "CWE-93":
		return "A03:2021-Injection"
	case "CWE-79", "CWE-1336":
		return "A03:2021-Injection"
	case "CWE-22", "CWE-601":
		return "A01:2021-Broken Access Control"
	case "CWE-918":
		return "A10:2021-SSRF"
	case "CWE-502":
		return "A08:2021-Software and Data Integrity Failures"
	case "CWE-798":
		return "A07:2021-Identification and Authentication Failures"
	case "CWE-327":
		return "A02:2021-Cryptographic Failures"
	case "CWE-295":
		return "A02:2021-Cryptographic Failures"
	case "CWE-732":
		return "A05:2021-Security Misconfiguration"
	case "CWE-755":
		return "A05:2021-Security Misconfiguration"
	case "CWE-117":
		return "A09:2021-Security Logging and Monitoring Failures"
	case "CWE-1321":
		return "A08:2021-Software and Data Integrity Failures"
	case "CWE-758":
		return "A04:2021-Insecure Design"
	default:
		return ""
	}
}

// RecommendationForRule returns fix guidance for a rule based on its ID/CWE.
func RecommendationForRule(id, cwe string) string {
	normalizedID := strings.TrimPrefix(id, "TS-")

	switch cwe {
	case "CWE-95":
		return "Replace eval/exec with safe parsing (ast.literal_eval) or explicit dispatch."
	case "CWE-78":
		return "Avoid shell=True. Use argument lists (subprocess.run(['cmd', arg])) and validate input."
	case "CWE-89":
		return "Use parameterized queries or prepared statements. Never concatenate user input into SQL."
	case "CWE-22":
		return "Validate and sanitize file paths. Use filepath.Clean and restrict to allowed directories."
	case "CWE-918":
		return "Validate and restrict outbound URLs. Use an allowlist for permitted destinations."
	case "CWE-79":
		return "Escape output before rendering. Use framework auto-escaping (Jinja2 autoescape, React)."
	case "CWE-798":
		return "Move secrets to environment variables or a secrets manager. Never hardcode credentials."
	case "CWE-327":
		return "Use modern crypto algorithms (SHA-256+, AES-GCM). Remove deprecated crypto (MD5, DES, RC4)."
	case "CWE-295":
		return "Enable certificate verification. Do not set InsecureSkipVerify to true."
	case "CWE-502":
		return "Avoid untrusted deserialization. Use safe formats (JSON) and validate input."
	case "CWE-755":
		return "Always check returned errors. Do not ignore error values."
	case "CWE-732":
		return "Restrict file permissions to 0600 for files and 0750 for directories."
	case "CWE-601":
		return "Validate redirect targets against an allowlist. Do not redirect to user-supplied URLs."
	case "CWE-117":
		return "Sanitize log input to prevent log injection. Strip newlines and control characters."
	case "CWE-1321":
		return "Avoid recursive merge of user-controlled objects. Use safe merge utilities."
	case "CWE-758":
		return "Remove unsafe package usage. Audit any use of the unsafe package."
	}

	// Fallback by rule prefix
	switch {
	case strings.HasPrefix(normalizedID, "SECRET-"):
		return "Rotate the exposed secret immediately and remove it from the codebase."
	case strings.HasPrefix(normalizedID, "G104"):
		return "Always check returned errors. Do not ignore error values."
	}

	return "Review the finding and apply the appropriate secure coding fix."
}
