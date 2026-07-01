package flask

import (
	"regexp"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

var djangoSourceExclusions = []frameworks.PathPattern{
	{Glob: "django/**", Reason: "Do not apply Flask rules to Django framework source."},
	{Glob: "docs/**", Reason: "Documentation examples are not application code."},
	{Glob: "tests/**", Reason: "Framework tests are not deployed application routes."},
}

func Rules() []frameworks.FrameworkRule {
	return []frameworks.FrameworkRule{
		{
			ID:             "PF-FLASK-SQLI-001",
			Framework:      "flask",
			Language:       "python",
			CWE:            "CWE-89",
			Title:          "Flask SQLi: execute with request data",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".py"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`(cursor\.execute|session\.execute)\s*\(\s*(f["']|["'][^"']*["']\s*(%|\+)|.*request\.(args|form|values))`),
			Sanitizers:     Sanitizers,
			Exclusions:     djangoSourceExclusions,
			Recommendation: "Use parameterized queries or ORM filters instead of interpolating Flask request values into SQL.",
		},
		{
			ID:             "PF-FLASK-SSRF-001",
			Framework:      "flask",
			Language:       "python",
			CWE:            "CWE-918",
			Title:          "Flask SSRF: outbound request with request-controlled URL",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".py"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`(requests|httpx)\.(get|post|request)\s*\([^)]*request\.(args|form|values)`),
			Sanitizers:     Sanitizers,
			Exclusions:     djangoSourceExclusions,
			Recommendation: "Validate outbound URLs against an allowlist before using request-controlled values.",
		},
		{
			ID:             "PF-FLASK-REDIRECT-001",
			Framework:      "flask",
			Language:       "python",
			CWE:            "CWE-601",
			Title:          "Flask open redirect: redirect with request input",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".py"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`redirect\s*\(\s*(request\.(args|form|values)\.get|.*\[(["'])(next|redirect|url)["']\])`),
			Sanitizers:     Sanitizers,
			Exclusions:     djangoSourceExclusions,
			Recommendation: "Validate redirect targets before passing them to Flask redirect().",
		},
		{
			ID:             "PF-FLASK-XSS-001",
			Framework:      "flask",
			Language:       "python",
			CWE:            "CWE-79",
			Title:          "Flask template XSS: Jinja safe filter",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			TemplateTypes:  []string{".html", ".jinja", ".jinja2"},
			MatchMode:      frameworks.MatchTemplate,
			Pattern:        regexp.MustCompile(`\|\s*safe\b`),
			Sanitizers:     Sanitizers,
			Exclusions:     djangoSourceExclusions,
			Recommendation: "Avoid Jinja's safe filter on user-controlled values. Let auto-escaping handle output.",
		},
		{
			ID:             "PF-FLASK-SSTI-001",
			Framework:      "flask",
			Language:       "python",
			CWE:            "CWE-94",
			Title:          "Flask SSTI: render_template_string with dynamic template",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".py"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`render_template_string\s*\(\s*[A-Za-z_][A-Za-z0-9_]*`),
			Sanitizers:     Sanitizers,
			Exclusions:     djangoSourceExclusions,
			Recommendation: "Do not render request-controlled template strings. Use render_template with a fixed template file and pass data as context.",
		},
	}
}
