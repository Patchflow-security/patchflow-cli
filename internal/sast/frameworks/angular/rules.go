package angular

import (
	"regexp"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

func Rules() []frameworks.FrameworkRule {
	return []frameworks.FrameworkRule{
		{
			ID:             "PF-ANGULAR-XSS-001",
			Framework:      "angular",
			Language:       "typescript",
			CWE:            "CWE-79",
			Title:          "Angular XSS: bypassSecurityTrustHtml with route data",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".ts"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`bypassSecurityTrust(Html|Url|ResourceUrl)\s*\([^)]*(queryParams|paramMap|ActivatedRoute|location)`),
			Sanitizers:     Sanitizers,
			Recommendation: "Avoid bypassSecurityTrust* for route-controlled data. Use normal Angular bindings or sanitize explicitly.",
		},
		{
			ID:             "PF-ANGULAR-XSS-002",
			Framework:      "angular",
			Language:       "typescript",
			CWE:            "CWE-79",
			Title:          "Angular template XSS: innerHTML binding",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			TemplateTypes:  []string{".html"},
			MatchMode:      frameworks.MatchTemplate,
			Pattern:        regexp.MustCompile(`\[innerHTML\]\s*=`),
			Sanitizers:     Sanitizers,
			Recommendation: "Avoid binding user-controlled values to innerHTML unless they are sanitized.",
		},
		{
			ID:             "PF-ANGULAR-REDIRECT-001",
			Framework:      "angular",
			Language:       "typescript",
			CWE:            "CWE-601",
			Title:          "Angular open redirect: router navigation with route input",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".ts"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`(navigateByUrl|window\.location)\s*(\(|=)[^;]*(queryParams|paramMap|ActivatedRoute|location)`),
			Sanitizers:     Sanitizers,
			Recommendation: "Validate route-controlled navigation targets before client-side redirects.",
		},
	}
}
