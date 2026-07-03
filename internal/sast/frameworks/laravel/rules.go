package laravel

import (
	"regexp"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

func Rules() []frameworks.FrameworkRule {
	return []frameworks.FrameworkRule{
		{
			ID:             "PF-LARAVEL-SQLI-001",
			Framework:      "laravel",
			Language:       "php",
			CWE:            "CWE-89",
			Title:          "Laravel SQLi: raw query built from request data",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".php"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`DB::(raw|select|statement)\s*\([^)]*(request\s*\(|\$request->|\$_(GET|POST|REQUEST)|\.)`),
			Sanitizers:     Sanitizers,
			Recommendation: "Use query builder bindings or parameter arrays instead of building raw SQL from request data.",
		},
		{
			ID:             "PF-LARAVEL-REDIRECT-001",
			Framework:      "laravel",
			Language:       "php",
			CWE:            "CWE-601",
			Title:          "Laravel open redirect: away() with request input",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".php"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`redirect\s*\(\s*\)->away\s*\([^)]*(request\s*\(|\$request->|\$_(GET|POST|REQUEST))`),
			Sanitizers:     Sanitizers,
			Recommendation: "Redirect to named routes or validate external targets against an allowlist.",
		},
		{
			ID:             "PF-LARAVEL-XSS-001",
			Framework:      "laravel",
			Language:       "php",
			CWE:            "CWE-79",
			Title:          "Laravel Blade XSS: unescaped output",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			TemplateTypes:  []string{".blade.php"},
			MatchMode:      frameworks.MatchTemplate,
			Pattern:        regexp.MustCompile(`\{!![^!]*(request\s*\(|\$request->|\$_(GET|POST|REQUEST)|\$[A-Za-z_][A-Za-z0-9_]*)[^!]*!!\}`),
			Sanitizers:     Sanitizers,
			Recommendation: "Use escaped Blade output {{ }} instead of {!! !!} for user-controlled values.",
		},
		{
			ID:             "PF-LARAVEL-MASS-001",
			Framework:      "laravel",
			Language:       "php",
			CWE:            "CWE-915",
			Title:          "Laravel mass assignment: create with all request fields",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceHigh,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".php"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`::create\s*\(\s*\$request->all\s*\(\s*\)\s*\)`),
			Recommendation: "Use validated() or an explicit field allowlist before mass assignment.",
		},
		{
			ID:             "PF-LARAVEL-DESER-001",
			Framework:      "laravel",
			Language:       "php",
			CWE:            "CWE-502",
			Title:          "Laravel unsafe deserialization: unserialize() with user input",
			Severity:       analysis.SeverityCritical,
			Confidence:     analysis.ConfidenceHigh,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".php"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`unserialize\s*\(\s*[^)]*(\$request|request\s*\(|Input::get|\$_(GET|POST|COOKIE|REQUEST))`),
			Recommendation: "Avoid unserialize with user input. Use json_decode with schema validation instead.",
		},
		{
			ID:             "PF-LARAVEL-AUTH-001",
			Framework:      "laravel",
			Language:       "php",
			CWE:            "CWE-306",
			Title:          "Laravel missing authentication: sensitive route without auth middleware",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceLow,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".php"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`Route::(get|post|put|delete|patch|any)\s*\(\s*["'][^"']*(admin|delete|update|create|manage)[^"']*["']`),
			SafePatterns: []frameworks.SafePattern{
				{Regex: regexp.MustCompile(`->middleware\(|auth:`), Reason: "auth middleware present on the route"},
			},
			Recommendation: "Add auth middleware to sensitive routes. Use Route::middleware('auth') or ->middleware('auth') on admin/management routes.",
		},
	}
}
