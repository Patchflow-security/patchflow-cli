package echo

import (
	"regexp"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

func Rules() []frameworks.FrameworkRule {
	return []frameworks.FrameworkRule{
		{
			ID:             "PF-ECHO-SQLI-001",
			Framework:      "echo",
			Language:       "go",
			CWE:            "CWE-89",
			Title:          "Echo SQLi: database query built from request data",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".go"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`db\.(Raw|Exec|Query)\s*\([^)]*(c\.(QueryParam|Param|FormValue)|\+)`),
			Sanitizers:     Sanitizers,
			Recommendation: "Use parameterized queries and pass Echo request values as bound arguments.",
		},
		{
			ID:             "PF-ECHO-REDIRECT-001",
			Framework:      "echo",
			Language:       "go",
			CWE:            "CWE-601",
			Title:          "Echo open redirect: c.Redirect with request input",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".go"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`c\.Redirect\s*\([^,]+,\s*c\.(QueryParam|Param|FormValue)\s*\(`),
			Sanitizers:     Sanitizers,
			Recommendation: "Validate redirect targets or redirect only to known local paths.",
		},
		{
			ID:             "PF-ECHO-XSS-001",
			Framework:      "echo",
			Language:       "go",
			CWE:            "CWE-79",
			Title:          "Echo XSS: c.HTML with request input",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".go"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`c\.HTML\s*\([^,]+,\s*c\.(QueryParam|Param|FormValue)\s*\(`),
			Sanitizers:     Sanitizers,
			Recommendation: "Escape request-controlled values before writing HTML responses.",
		},
	}
}
