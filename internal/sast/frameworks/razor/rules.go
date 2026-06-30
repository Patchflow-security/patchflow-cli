package razor

import (
	"regexp"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

func Rules() []frameworks.FrameworkRule {
	return []frameworks.FrameworkRule{
		{
			ID:             "PF-RAZOR-XSS-001",
			Framework:      "razor",
			Language:       "csharp",
			CWE:            "CWE-79",
			Title:          "Razor XSS: Html.Raw with user-controlled data",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			TemplateTypes:  []string{".cshtml", ".razor"},
			MatchMode:      frameworks.MatchTemplate,
			Pattern:        regexp.MustCompile(`@?Html\.Raw\s*\([^)]*(Request\.|Model\.|ViewBag\.|ViewData)`),
			Sanitizers:     Sanitizers,
			Recommendation: "Avoid Html.Raw for user-controlled data. Razor encodes normal @ output automatically.",
		},
		{
			ID:             "PF-RAZOR-XSS-002",
			Framework:      "razor",
			Language:       "csharp",
			CWE:            "CWE-79",
			Title:          "Razor XSS: MarkupString with user-controlled data",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			TemplateTypes:  []string{".razor"},
			MatchMode:      frameworks.MatchTemplate,
			Pattern:        regexp.MustCompile(`new\s+MarkupString\s*\([^)]*(Request\.|Model\.|ViewBag\.|ViewData)`),
			Sanitizers:     Sanitizers,
			Recommendation: "Avoid MarkupString for user-controlled values unless the HTML was sanitized by a trusted sanitizer.",
		},
	}
}
