package spring

import (
	"regexp"

	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

// Sanitizers are the Spring functions/patterns that clear taint or render
// output safe. When a sink match line also contains a sanitizer, the matcher
// suppresses the finding.
var Sanitizers = []frameworks.SanitizerPattern{
	// SQL injection sanitizers — parameterized queries use ? or :name
	// placeholders, not string concatenation.
	{Regex: regexp.MustCompile(`\bquery\s*\(\s*["'][^"']*\?[^"']*["']`)},           // jdbcTemplate.query("SELECT ... WHERE id = ?", ...)
	{Regex: regexp.MustCompile(`\bqueryForObject\s*\(\s*["'][^"']*\?[^"']*["']`)}, // queryForObject with ?
	{Regex: regexp.MustCompile(`\bupdate\s*\(\s*["'][^"']*\?[^"']*["']`)},         // update with ?
	{Regex: regexp.MustCompile(`NamedParameterJdbcTemplate`)},                     // named parameter template
	{Regex: regexp.MustCompile(`:createNativeQuery\(\s*["'][^"']*\?[^"']*["']`)},  // parameterized native query
	{FuncName: "PreparedStatement"},
	{FuncName: "prepareStatement"},
	{FuncName: "setParameter"},
	{FuncName: "bind"},
	{FuncName: "NamedQuery"},

	// XXE sanitizers — secure XML processing features
	{FuncName: "setFeature"},
	{Regex: regexp.MustCompile(`disallow-doctype-decl`)},                // FEATURE_DISALLOW_DOCTYPE_DECL
	{Regex: regexp.MustCompile(`external-general-entities.*false`)},    // external-general-entities = false
	{Regex: regexp.MustCompile(`external-parameter-entities.*false`)},  // external-parameter-entities = false
	{FuncName: "XMLConstants.FEATURE_SECURE_PROCESSING"},
	{FuncName: "FEATURE_SECURE_PROCESSING"},
	{FuncName: "setExpandEntityReferences(false)"},
	{FuncName: "ExternalEntityResolver"}, // custom no-op resolver

	// Open redirect sanitizers
	{FuncName: "UriComponentsBuilder"},
	{FuncName: "ServletUriComponentsBuilder"},
	{Regex: regexp.MustCompile(`isLocalUrl|isLocalUrl\(`)}, // local URL check

	// Deserialization sanitizers
	{FuncName: "ObjectInputFilter"},   // JDK 9+ deserialization filter
	{FuncName: "resolveClass"},        // custom resolveClass allowlist
	{Regex: regexp.MustCompile(`XStream.*allowTypes`)},    // XStream allowTypes
	{Regex: regexp.MustCompile(`XStream.*allowTypeHierarchy`)},

	// XSS sanitizers
	{FuncName: "HtmlUtils.htmlEscape"},
	{FuncName: "StringEscapeUtils.escapeHtml"},
	{FuncName: "escapeHtml4"},
	{FuncName: "escapeHtml3"},
	{FuncName: "OWASP HtmlSanitizer"},
	{FuncName: "HtmlSanitizer"},

	// Command injection sanitizers
	{FuncName: "CommandUtils"}, // Spring's command utility (if used for allowlisting)
	{Regex: regexp.MustCompile(`ProcessBuilder\s*\(\s*(?:List\.of|Arrays\.asList|new\s+ArrayList)`)}, // ProcessBuilder with list args (no shell)
}
