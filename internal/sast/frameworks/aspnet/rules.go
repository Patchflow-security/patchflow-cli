package aspnet

import (
	"regexp"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

func Rules() []frameworks.FrameworkRule {
	return []frameworks.FrameworkRule{
		{
			ID:             "PF-ASPNET-SQLI-001",
			Framework:      "aspnet",
			Language:       "csharp",
			CWE:            "CWE-89",
			Title:          "ASP.NET Core SQLi: raw SQL built from request data",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".cs"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`(FromSqlRaw|ExecuteSqlRaw|SqlCommand)\s*\([^)]*(Request\.|HttpContext\.Request|\+)`),
			Sanitizers:     Sanitizers,
			Recommendation: "Use parameterized queries, SqlParameter, or interpolated EF APIs that parameterize values.",
		},
		{
			ID:             "PF-ASPNET-REDIRECT-001",
			Framework:      "aspnet",
			Language:       "csharp",
			CWE:            "CWE-601",
			Title:          "ASP.NET Core open redirect: Redirect with request input",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".cs"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`Redirect\s*\(\s*(Request\.Query|HttpContext\.Request\.Query|.*\[(["'])(returnUrl|next|url)["']\])`),
			Sanitizers:     Sanitizers,
			Recommendation: "Use LocalRedirect or validate with Url.IsLocalUrl before redirecting.",
		},
		{
			ID:             "PF-ASPNET-XSS-001",
			Framework:      "aspnet",
			Language:       "csharp",
			CWE:            "CWE-79",
			Title:          "ASP.NET Core XSS: raw HTML response from request data",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".cs"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`(new\s+HtmlString|Content)\s*\([^)]*(Request\.|HttpContext\.Request)`),
			Sanitizers:     Sanitizers,
			Recommendation: "HTML-encode request-controlled values before writing raw HTML responses.",
		},
	}
}
