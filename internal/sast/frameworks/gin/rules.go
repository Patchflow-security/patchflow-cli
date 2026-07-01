package gin

import (
	"regexp"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

func Rules() []frameworks.FrameworkRule {
	return []frameworks.FrameworkRule{
		{
			ID:             "PF-GIN-SQLI-001",
			Framework:      "gin",
			Language:       "go",
			CWE:            "CWE-89",
			Title:          "Gin SQLi: database query built from request data",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".go"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`db\.(Raw|Exec|Query)\s*\([^)]*(c\.(Query|Param|PostForm)|\+)`),
			Sanitizers:     Sanitizers,
			Recommendation: "Use parameterized queries and pass Gin request values as bound arguments.",
		},
		{
			ID:             "PF-GIN-REDIRECT-001",
			Framework:      "gin",
			Language:       "go",
			CWE:            "CWE-601",
			Title:          "Gin open redirect: c.Redirect with request input",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".go"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`c\.Redirect\s*\([^,]+,\s*c\.(Query|Param|PostForm)\s*\(`),
			Sanitizers:     Sanitizers,
			Recommendation: "Validate redirect targets or redirect only to known local paths.",
		},
		{
			ID:             "PF-GIN-XSS-001",
			Framework:      "gin",
			Language:       "go",
			CWE:            "CWE-79",
			Title:          "Gin XSS: c.String with request input",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".go"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`c\.String\s*\([^,]+,\s*c\.(Query|Param|PostForm)\s*\(`),
			Sanitizers:     Sanitizers,
			Recommendation: "Escape request-controlled values before writing HTML or render through html/template.",
		},
		{
			ID:             "PF-GIN-CMDI-001",
			Framework:      "gin",
			Language:       "go",
			CWE:            "CWE-78",
			Title:          "Gin command injection: exec.Command with request data",
			Severity:       analysis.SeverityCritical,
			Confidence:     analysis.ConfidenceHigh,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".go"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`exec\.Command\s*\([^)]*c\.(Query|Param|PostForm)\s*\(`),
			Recommendation: "Do not pass request-controlled values into commands without strict allowlisting.",
		},
	}
}
