package springsecurity

import (
	"regexp"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

func Rules() []frameworks.FrameworkRule {
	return []frameworks.FrameworkRule{
		{
			ID:             "PF-SPRINGSEC-CSRF-001",
			Framework:      "spring-security",
			Language:       "java",
			CWE:            "CWE-352",
			Title:          "Spring Security CSRF disabled",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceHigh,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".java"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`csrf\s*\(\s*\)\s*\.disable\s*\(|csrf\s*\([^)]*->\s*[^)]*\.disable\s*\(\s*\)`),
			Recommendation: "Keep CSRF protection enabled for browser-authenticated routes. Scope CSRF ignores only to stateless API endpoints.",
		},
		{
			ID:             "PF-SPRINGSEC-AUTH-001",
			Framework:      "spring-security",
			Language:       "java",
			CWE:            "CWE-306",
			Title:          "Spring Security auth bypass: permitAll on sensitive route",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".java"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`(antMatchers|requestMatchers)\s*\([^)]*(admin|manage|internal|api)[^)]*\)[^;]*\.permitAll\s*\(`),
			Sanitizers:     Sanitizers,
			Recommendation: "Use authenticated(), hasRole(), or hasAuthority() for sensitive routes instead of permitAll().",
		},
		{
			ID:             "PF-SPRINGSEC-AUTH-002",
			Framework:      "spring-security",
			Language:       "java",
			CWE:            "CWE-306",
			Title:          "Spring Security bypass: web.ignoring on application route",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".java"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`web\.ignoring\s*\(\s*\)\s*\.(antMatchers|requestMatchers)\s*\([^)]*(admin|api|internal)`),
			Recommendation: "Use authorization rules instead of removing application routes from the security filter chain.",
		},
		{
			ID:             "PF-SPRINGSEC-AUTH-003",
			Framework:      "spring-security",
			Language:       "java",
			CWE:            "CWE-306",
			Title:          "Spring Security auth bypass: @PermitAll annotation",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".java"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`@PermitAll\b`),
			Recommendation: "Reserve @PermitAll for public endpoints and document why the route does not require authentication.",
		},
	}
}
