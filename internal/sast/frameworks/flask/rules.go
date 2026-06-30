package flask

import (
	"regexp"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

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
			Recommendation: "Avoid Jinja's safe filter on user-controlled values. Let auto-escaping handle output.",
		},
	}
}
