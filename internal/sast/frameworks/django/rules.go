package django

import (
	"regexp"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

var frameworkSourceExclusions = []frameworks.PathPattern{
	{Glob: "django/**", Reason: "Django framework source is a clean corpus target, not application code."},
	{Glob: "docs/**", Reason: "Documentation examples are not application code."},
	{Glob: "tests/**", Reason: "Framework tests are not deployed application routes."},
}

func Rules() []frameworks.FrameworkRule {
	return []frameworks.FrameworkRule{
		{
			ID:             "PF-DJANGO-SQLI-001",
			Framework:      "django",
			Language:       "python",
			CWE:            "CWE-89",
			Title:          "Django SQLi: raw SQL built from request data",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".py"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`(\.raw|cursor\.execute)\s*\(\s*(f["']|["'][^"']*["']\s*(%|\+)|.*request\.(GET|POST))`),
			Sanitizers:     Sanitizers,
			Exclusions:     frameworkSourceExclusions,
			Recommendation: "Use ORM filters or parameterized cursor.execute calls instead of interpolating request data into SQL.",
		},
		{
			ID:             "PF-DJANGO-REDIRECT-001",
			Framework:      "django",
			Language:       "python",
			CWE:            "CWE-601",
			Title:          "Django open redirect: redirect with request input",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".py"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`redirect\s*\(\s*(request\.(GET|POST)\.get|.*\[(["'])(next|redirect|url)["']\])`),
			Sanitizers:     Sanitizers,
			Exclusions:     frameworkSourceExclusions,
			Recommendation: "Validate redirect targets with url_has_allowed_host_and_scheme before redirecting.",
		},
		{
			ID:             "PF-DJANGO-XSS-001",
			Framework:      "django",
			Language:       "python",
			CWE:            "CWE-79",
			Title:          "Django XSS: mark_safe with request data",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".py"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`mark_safe\s*\([^)]*request\.(GET|POST|body|headers)`),
			Sanitizers:     Sanitizers,
			Exclusions:     frameworkSourceExclusions,
			Recommendation: "Avoid mark_safe on user-controlled data. Use format_html or let Django auto-escape templates.",
		},
		{
			ID:             "PF-DJANGO-XSS-002",
			Framework:      "django",
			Language:       "python",
			CWE:            "CWE-79",
			Title:          "Django template XSS: safe filter",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			TemplateTypes:  []string{".html", ".jinja", ".jinja2"},
			MatchMode:      frameworks.MatchTemplate,
			Pattern:        regexp.MustCompile(`\|\s*safe\b`),
			Sanitizers:     Sanitizers,
			Exclusions:     frameworkSourceExclusions,
			Recommendation: "Avoid the safe filter for user-controlled values. Let template auto-escaping handle output.",
		},
		{
			ID:             "PF-DJANGO-DESER-001",
			Framework:      "django",
			Language:       "python",
			CWE:            "CWE-502",
			Title:          "Django unsafe deserialization: pickle.loads on request data",
			Severity:       analysis.SeverityCritical,
			Confidence:     analysis.ConfidenceHigh,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".py"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`pickle\.loads\s*\([^)]*request\.(body|GET|POST)`),
			Exclusions:     frameworkSourceExclusions,
			Recommendation: "Do not deserialize untrusted request data with pickle. Use JSON with schema validation.",
		},

		// === CSRF exemption on state-changing view ===
		{
			ID:             "PF-DJANGO-CSRF-001",
			Framework:      "django",
			Language:       "python",
			CWE:            "CWE-352",
			Title:          "Django CSRF: @csrf_exempt on view",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".py"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`@csrf_exempt`),
			Sanitizers:     Sanitizers,
			Exclusions:     frameworkSourceExclusions,
			SafePatterns: []frameworks.SafePattern{
				{Regex: regexp.MustCompile(`(?i)GET|HEAD|OPTIONS`), Reason: "read-only HTTP methods are not state-changing"},
			},
			Recommendation: "Remove @csrf_exempt. If needed for webhooks, validate the request origin or use a signature-based verification instead.",
		},

		// === SSRF via requests/httpx with user-controlled URL ===
		{
			ID:             "PF-DJANGO-SSRF-001",
			Framework:      "django",
			Language:       "python",
			CWE:            "CWE-918",
			Title:          "Django SSRF: requests.get/httpx.get with user-controlled URL",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".py"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`(requests|httpx)\.(get|post|put|delete|head|patch)\s*\(\s*[^)]*request\.(GET|POST|body|headers|META)`),
			Sanitizers:     Sanitizers,
			Exclusions:     frameworkSourceExclusions,
			Recommendation: "Validate and restrict URLs before making HTTP requests. Use an allow-list of permitted domains and validate the URL scheme.",
		},
	}
}
