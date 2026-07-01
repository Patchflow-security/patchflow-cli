package symfony

import (
	"regexp"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

func Rules() []frameworks.FrameworkRule {
	return []frameworks.FrameworkRule{
		{
			ID:             "PF-SYMFONY-SQLI-001",
			Framework:      "symfony",
			Language:       "php",
			CWE:            "CWE-89",
			Title:          "Symfony SQLi: Doctrine query built from request data",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".php"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`(createQuery|executeQuery)\s*\([^)]*(\$request->(query|request)->get|\$_(GET|POST|REQUEST))`),
			Sanitizers:     Sanitizers,
			Recommendation: "Use Doctrine parameters via setParameter() instead of concatenating request data into DQL or SQL.",
		},
		{
			ID:             "PF-SYMFONY-REDIRECT-001",
			Framework:      "symfony",
			Language:       "php",
			CWE:            "CWE-601",
			Title:          "Symfony open redirect: RedirectResponse with request input",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".php"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`new\s+RedirectResponse\s*\([^)]*(\$request->(query|request)->get|\$_(GET|POST|REQUEST))`),
			Sanitizers:     Sanitizers,
			Recommendation: "Validate redirect targets or route to named Symfony routes.",
		},
		{
			ID:             "PF-SYMFONY-XSS-001",
			Framework:      "symfony",
			Language:       "php",
			CWE:            "CWE-79",
			Title:          "Symfony Twig XSS: raw filter",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			TemplateTypes:  []string{".twig"},
			MatchMode:      frameworks.MatchTemplate,
			Pattern:        regexp.MustCompile(`\|\s*raw\b`),
			Sanitizers:     Sanitizers,
			Recommendation: "Avoid Twig raw for user-controlled values. Let Twig auto-escaping handle output.",
		},
	}
}
