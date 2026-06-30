package react

import (
	"regexp"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

func Rules() []frameworks.FrameworkRule {
	return []frameworks.FrameworkRule{
		{
			ID:             "PF-REACT-XSS-001",
			Framework:      "react",
			Language:       "javascript",
			CWE:            "CWE-79",
			Title:          "React XSS: dangerouslySetInnerHTML with user-controlled data",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			TemplateTypes:  []string{".jsx", ".tsx"},
			MatchMode:      frameworks.MatchTemplate,
			Pattern:        regexp.MustCompile(`dangerouslySetInnerHTML\s*=\s*\{\{\s*__html:\s*(props|state|location|searchParams|.*query)`),
			Sanitizers:     Sanitizers,
			Recommendation: "Avoid dangerouslySetInnerHTML for user-controlled data. Use normal JSX text rendering or a trusted sanitizer.",
		},
		{
			ID:             "PF-REACT-REDIRECT-001",
			Framework:      "react",
			Language:       "javascript",
			CWE:            "CWE-601",
			Title:          "React open redirect: navigation with user-controlled URL",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".jsx", ".tsx"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`(window\.location|router\.push|navigate)\s*(=|\()\s*(props|state|location|searchParams|.*query)`),
			Sanitizers:     Sanitizers,
			Recommendation: "Validate navigation targets before assigning them to location or client-side routing APIs.",
		},
	}
}
