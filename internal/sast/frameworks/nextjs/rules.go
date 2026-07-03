package nextjs

import (
	"regexp"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

func Rules() []frameworks.FrameworkRule {
	return []frameworks.FrameworkRule{
		{
			ID:             "PF-NEXTJS-SSRF-001",
			Framework:      "nextjs",
			Language:       "javascript",
			CWE:            "CWE-918",
			Title:          "Next.js SSRF: fetch with request-controlled URL",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".js", ".jsx", ".ts", ".tsx"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`fetch\s*\(\s*(req\.query|request\.nextUrl\.searchParams|searchParams\.)`),
			Sanitizers:     Sanitizers,
			Recommendation: "Validate server-side fetch URLs against an allowlist before using request-controlled values.",
		},
		{
			ID:             "PF-NEXTJS-REDIRECT-001",
			Framework:      "nextjs",
			Language:       "javascript",
			CWE:            "CWE-601",
			Title:          "Next.js open redirect: redirect with request input",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".js", ".jsx", ".ts", ".tsx"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`(NextResponse\.redirect|(^|[^\w.])redirect|router\.push)\s*\([^)]*(req\.query|request\.nextUrl\.searchParams|searchParams\.)`),
			Sanitizers:     Sanitizers,
			Recommendation: "Constrain redirect targets to known local paths or an allowlist of trusted origins.",
		},
		{
			ID:             "PF-NEXTJS-XSS-001",
			Framework:      "nextjs",
			Language:       "javascript",
			CWE:            "CWE-79",
			Title:          "Next.js XSS: dangerouslySetInnerHTML with request data",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			TemplateTypes:  []string{".jsx", ".tsx"},
			MatchMode:      frameworks.MatchTemplate,
			Pattern:        regexp.MustCompile(`dangerouslySetInnerHTML\s*=\s*\{\{\s*__html:\s*(props|searchParams|params|.*query)`),
			Sanitizers:     Sanitizers,
			Recommendation: "Avoid dangerouslySetInnerHTML for request-controlled data. Render text normally or sanitize with a trusted HTML sanitizer.",
		},
		{
			ID:             "PF-NEXTJS-SECRET-001",
			Framework:      "nextjs",
			Language:       "javascript",
			CWE:            "CWE-200",
			Title:          "Next.js secret exposed to client component or NEXT_PUBLIC misuse",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".js", ".jsx", ".ts", ".tsx"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`process\.env\.NEXT_PUBLIC_\w*(SECRET|PRIVATE_KEY|API_KEY|PASSWORD|TOKEN|JWT)`),
			Sanitizers:     Sanitizers,
			Recommendation: "Do not use NEXT_PUBLIC_ prefix for secret values. NEXT_PUBLIC_ variables are inlined into client-side JavaScript and visible to users. Use server-only environment variables for secrets.",
		},
	}
}
