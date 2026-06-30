package django

import (
	"regexp"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

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
			Recommendation: "Do not deserialize untrusted request data with pickle. Use JSON with schema validation.",
		},
	}
}
