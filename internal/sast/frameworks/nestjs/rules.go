package nestjs

import (
	"regexp"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

func Rules() []frameworks.FrameworkRule {
	return []frameworks.FrameworkRule{
		{
			ID:             "PF-NESTJS-SQLI-001",
			Framework:      "nestjs",
			Language:       "typescript",
			CWE:            "CWE-89",
			Title:          "NestJS SQLi: query built from controller input",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".ts"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`\.(query|execute)\s*\(\s*(\x60[^\x60]*\$\{|["'][^"']*["']\s*\+|.*(@Query|@Param|@Body|req\.query|req\.body))`),
			Sanitizers:     Sanitizers,
			Recommendation: "Use parameterized queries or ORM query builders instead of concatenating controller input.",
		},
		{
			ID:             "PF-NESTJS-SSRF-001",
			Framework:      "nestjs",
			Language:       "typescript",
			CWE:            "CWE-918",
			Title:          "NestJS SSRF: outbound request with controller input",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".ts"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`(httpService|axios)\.(get|post|request)\s*\([^)]*(@Query|@Param|@Body|req\.query|req\.body|url)`),
			Sanitizers:     Sanitizers,
			Recommendation: "Validate outbound URLs against an allowlist before making server-side requests.",
		},
		{
			ID:             "PF-NESTJS-REDIRECT-001",
			Framework:      "nestjs",
			Language:       "typescript",
			CWE:            "CWE-601",
			Title:          "NestJS open redirect: redirect with controller input",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".ts"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`redirect\s*\([^)]*(@Query|@Param|@Body|req\.query|req\.body|next|url)`),
			Sanitizers:     Sanitizers,
			Recommendation: "Validate redirect targets before redirecting from NestJS controllers.",
		},
	}
}
