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
		{
			ID:             "PF-NESTJS-AUTH-001",
			Framework:      "nestjs",
			Language:       "typescript",
			CWE:            "CWE-862",
			Title:          "NestJS missing authorization: sensitive controller/route without auth guard",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceLow,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".ts"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`@(Get|Post|Put|Delete|Patch)\s*\(\s*["'][^"']*(admin|delete|update|create|manage|user|account|password|settings)[^"']*["']`),
			SafePatterns: []frameworks.SafePattern{
				{Regex: regexp.MustCompile(`@UseGuards|@Roles`), Reason: "Auth guard or role decorator present on the route"},
			},
			Sanitizers:     Sanitizers,
			Recommendation: "Add @UseGuards(AuthGuard) or @Roles() to sensitive controller routes. Consider using a global APP_GUARD for consistent authorization.",
		},
	}
}
