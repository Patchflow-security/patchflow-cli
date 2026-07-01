// Package cwe provides CWE (Common Weakness Enumeration) to OWASP Top 10
// mapping, descriptions, attack scenarios, and reference links. This data
// is embedded in the binary so `patchflow explain` works offline.
package cwe

import "sort"

// OWASPCategory represents an OWASP Top 10 (2021) category.
type OWASPCategory struct {
	ID          string // e.g., "A03"
	Name        string // e.g., "Injection"
	Description string
}

// CWEInfo contains metadata about a CWE.
type CWEInfo struct {
	ID             string       // e.g., "CWE-89"
	Name           string       // e.g., "SQL Injection"
	Description    string       // 1-2 sentence description
	OWASP          OWASPCategory // mapped OWASP Top 10 category
	AttackScenario string       // real-world attack scenario
	References     []string      // authoritative URLs
}

// owasp categories (2021 edition)
var (
	OWASP_A01 = OWASPCategory{ID: "A01", Name: "Broken Access Control", Description: "Restrictions on what authenticated users are allowed to do are not properly enforced."}
	OWASP_A02 = OWASPCategory{ID: "A02", Name: "Cryptographic Failures", Description: "Failures related to cryptography that often lead to sensitive data exposure or system compromise."}
	OWASP_A03 = OWASPCategory{ID: "A03", Name: "Injection", Description: "User-supplied data is not validated, filtered, or sanitized, allowing malicious input to be interpreted as code or commands."}
	OWASP_A04 = OWASPCategory{ID: "A04", Name: "Insecure Design", Description: "Flaws in the design and architecture of an application that cannot be fixed by implementation alone."}
	OWASP_A05 = OWASPCategory{ID: "A05", Name: "Security Misconfiguration", Description: "Missing or incorrect security configurations."}
	OWASP_A06 = OWASPCategory{ID: "A06", Name: "Vulnerable and Outdated Components", Description: "Using components with known vulnerabilities."}
	OWASP_A07 = OWASPCategory{ID: "A07", Name: "Identification and Authentication Failures", Description: "Confirmation of the user's identity, authentication, and session management is weak."}
	OWASP_A08 = OWASPCategory{ID: "A08", Name: "Software and Data Integrity Failures", Description: "Code and infrastructure that do not protect against integrity violations."}
	OWASP_A09 = OWASPCategory{ID: "A09", Name: "Security Logging and Monitoring Failures", Description: "Insufficient logging and monitoring, combined with missing or ineffective integration with incident response."}
	OWASP_A10 = OWASPCategory{ID: "A10", Name: "Server-Side Request Forgery (SSRF)", Description: "A web server fetches a remote resource without validating the user-supplied URL."}
)

// database is the embedded CWE database.
var database = map[string]CWEInfo{
	"CWE-22": {
		ID:          "CWE-22",
		Name:        "Path Traversal",
		Description: "The software uses external input to construct a pathname that is intended to identify a file or directory, but it does not properly neutralize sequences such as '..' that can resolve to a parent directory.",
		OWASP:       OWASP_A01,
		AttackScenario: "An attacker supplies '../' sequences in a file parameter (e.g., ?file=../../etc/passwd) to read arbitrary files outside the intended directory, exposing sensitive configuration or credential files.",
		References: []string{
			"https://owasp.org/www-community/attacks/Path_Traversal",
			"https://cwe.mitre.org/data/definitions/22.html",
		},
	},
	"CWE-78": {
		ID:          "CWE-78",
		Name:        "OS Command Injection",
		Description: "The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command.",
		OWASP:       OWASP_A03,
		AttackScenario: "An attacker injects shell metacharacters (e.g., '; rm -rf /') into a parameter that is passed to system() or exec(), causing arbitrary commands to execute on the server with the application's privileges.",
		References: []string{
			"https://owasp.org/www-community/attacks/Command_Injection",
			"https://cwe.mitre.org/data/definitions/78.html",
		},
	},
	"CWE-79": {
		ID:          "CWE-79",
		Name:        "Cross-site Scripting (XSS)",
		Description: "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
		OWASP:       OWASP_A03,
		AttackScenario: "An attacker injects a <script> tag into a comment or profile field. When other users view the page, the script executes in their browser, stealing session cookies or performing actions on their behalf.",
		References: []string{
			"https://owasp.org/www-community/attacks/xss/",
			"https://cwe.mitre.org/data/definitions/79.html",
		},
	},
	"CWE-89": {
		ID:          "CWE-89",
		Name:        "SQL Injection",
		Description: "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command.",
		OWASP:       OWASP_A03,
		AttackScenario: "An attacker inputs ' OR 1=1 -- into a login field. The resulting query becomes SELECT * FROM users WHERE username='' OR 1=1 --', bypassing authentication and returning all user records.",
		References: []string{
			"https://owasp.org/www-community/attacks/SQL_Injection",
			"https://cwe.mitre.org/data/definitions/89.html",
			"https://portswigger.net/web-security/sql-injection",
		},
	},
	"CWE-90": {
		ID:          "CWE-90",
		Name:        "LDAP Injection",
		Description: "The software constructs all or part of an LDAP query using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended LDAP query.",
		OWASP:       OWASP_A03,
		AttackScenario: "An attacker injects LDAP filter metacharacters (e.g., *)(uid=*)) into a search field, modifying the query to return all directory entries or bypass authentication.",
		References: []string{
			"https://owasp.org/www-community/attacks/LDAP_Injection",
			"https://cwe.mitre.org/data/definitions/90.html",
		},
	},
	"CWE-94": {
		ID:          "CWE-94",
		Name:        "Code Injection",
		Description: "The software constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment.",
		OWASP:       OWASP_A03,
		AttackScenario: "An attacker supplies input to eval() or exec() that contains arbitrary code (e.g., __import__('os').system('cat /etc/passwd')), achieving remote code execution on the server.",
		References: []string{
			"https://owasp.org/www-community/attacks/Code_Injection",
			"https://cwe.mitre.org/data/definitions/94.html",
		},
	},
	"CWE-98": {
		ID:          "CWE-98",
		Name:        "PHP File Inclusion",
		Description: "The PHP application receives input from an upstream component, but it does not restrict or incorrectly restricts the input before its use in a require, include, or similar function.",
		OWASP:       OWASP_A03,
		AttackScenario: "An attacker manipulates a page parameter (e.g., ?page=../../uploads/shell.php) to include a malicious file, achieving remote code execution via the included file.",
		References: []string{
			"https://owasp.org/www-community/attacks/PHP_File_Inclusion",
			"https://cwe.mitre.org/data/definitions/98.html",
		},
	},
	"CWE-295": {
		ID:          "CWE-295",
		Name:        "Improper Certificate Validation",
		Description: "The software does not validate, or incorrectly validates, a certificate, causing the software to accept invalid certificates.",
		OWASP:       OWASP_A02,
		AttackScenario: "An attacker performs a man-in-the-middle attack, presenting a self-signed certificate. Because the application disables certificate verification (verify=False), the attacker intercepts all traffic including credentials.",
		References: []string{
			"https://owasp.org/www-community/attacks/SSL_Certificate_Validation",
			"https://cwe.mitre.org/data/definitions/295.html",
		},
	},
	"CWE-327": {
		ID:          "CWE-327",
		Name:        "Use of Broken or Risky Cryptographic Algorithm",
		Description: "The software uses a broken or risky cryptographic algorithm or protocol.",
		OWASP:       OWASP_A02,
		AttackScenario: "An application uses MD5 or SHA1 for password hashing. An attacker who obtains the hash database can crack passwords rapidly using rainbow tables or GPU-accelerated brute force, since these algorithms are designed for speed, not security.",
		References: []string{
			"https://owasp.org/www-community/vulnerabilities/Use_of_cryptographically_weak_pseudo-random_number_generator",
			"https://cwe.mitre.org/data/definitions/327.html",
		},
	},
	"CWE-502": {
		ID:          "CWE-502",
		Name:        "Deserialization of Untrusted Data",
		Description: "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
		OWASP:       OWASP_A08,
		AttackScenario: "An attacker sends a crafted serialized object (e.g., a pickle payload or Java serialized object) that executes arbitrary code during deserialization, achieving remote code execution.",
		References: []string{
			"https://owasp.org/www-community/attacks/Deserialization_of_untrusted_data",
			"https://cwe.mitre.org/data/definitions/502.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
		},
	},
	"CWE-601": {
		ID:          "CWE-601",
		Name:        "Open Redirect",
		Description: "A web application accepts a user-controlled input that specifies a link to an external site, and uses that link in a redirect.",
		OWASP:       OWASP_A01,
		AttackScenario: "An attacker crafts a phishing URL using the legitimate redirect endpoint (e.g., /redirect?url=https://evil.com). Users trust the original domain and are redirected to a credential-harvesting page.",
		References: []string{
			"https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet",
			"https://cwe.mitre.org/data/definitions/601.html",
		},
	},
	"CWE-611": {
		ID:          "CWE-611",
		Name:        "XML External Entity (XXE) Injection",
		Description: "The software processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control, causing the application to embed incorrect documents into the output.",
		OWASP:       OWASP_A05,
		AttackScenario: "An attacker sends an XML payload with a DOCTYPE declaration referencing an external entity (e.g., <!ENTITY xxe SYSTEM 'file:///etc/passwd'>). The parser resolves the entity, exposing the file contents.",
		References: []string{
			"https://owasp.org/www-community/attacks/XML_External_Entity_(XXE)_Processing",
			"https://cwe.mitre.org/data/definitions/611.html",
		},
	},
	"CWE-918": {
		ID:          "CWE-918",
		Name:        "Server-Side Request Forgery (SSRF)",
		Description: "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.",
		OWASP:       OWASP_A10,
		AttackScenario: "An attacker manipulates a URL parameter (e.g., ?url=http://169.254.169.254/latest/meta-data/) to make the server fetch internal cloud metadata endpoints, stealing IAM credentials or accessing internal services.",
		References: []string{
			"https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
			"https://cwe.mitre.org/data/definitions/918.html",
		},
	},
}

// Lookup returns CWE information for a given CWE ID (e.g., "CWE-89").
// Returns ok=false if the CWE is not in the embedded database.
func Lookup(cweID string) (CWEInfo, bool) {
	info, ok := database[cweID]
	return info, ok
}

// OWASPForCWE returns the OWASP Top 10 category for a given CWE ID.
// Returns a zero value if the CWE is not in the database.
func OWASPForCWE(cweID string) OWASPCategory {
	info, ok := database[cweID]
	if !ok {
		return OWASPCategory{}
	}
	return info.OWASP
}

// OWASPCategoryID returns the OWASP category ID (e.g., "A03") for a CWE.
func OWASPCategoryID(cweID string) string {
	cat := OWASPForCWE(cweID)
	return cat.ID
}

// OWASPCategoryLabel returns a human-readable label like "A03: Injection".
func OWASPCategoryLabel(cweID string) string {
	cat := OWASPForCWE(cweID)
	if cat.ID == "" {
		return ""
	}
	return cat.ID + ": " + cat.Name
}

// AllCWEs returns all CWE IDs in the database, sorted.
func AllCWEs() []string {
	var ids []string
	for id := range database {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
