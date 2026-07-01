package frameworks

import (
	"github.com/Patchflow-security/patchflow-cli/internal/sast/taintpatterns"
)

// ToTaintRules converts a framework pack's MatchTaint rules into the
// taintpatterns engine's Rule format, so the engine can track the
// framework's sources/sinks using its existing intra/inter-procedural
// taint tracking.
//
// Sanitizers are not modeled by the taintpatterns engine directly; the
// framework matcher applies sanitizer checks for pattern/template rules.
// Taint-rule sanitizer suppression is handled by the matcher's safe-pattern
// path when a taint finding is later reconciled. For the foundation, taint
// rules carry sources and sinks; sanitizer-aware taint suppression is a
// follow-on once the taint engine grows a sanitizer step.
func ToTaintRules(rules []FrameworkRule) []taintpatterns.Rule {
	var out []taintpatterns.Rule
	for _, r := range rules {
		if r.MatchMode != MatchTaint {
			continue
		}
		out = append(out, taintpatterns.Rule{
			ID:          r.ID,
			Title:       r.Title,
			Description: r.Recommendation,
			Severity:    r.Severity,
			Confidence:  r.Confidence,
			Language:    taintLanguage(r.Language),
			CWEID:       r.CWE,
			Sources:     toTaintSources(r.Sources),
			Sinks:       toTaintSinks(r.Sinks),
		})
	}
	return out
}

func toTaintSources(srcs []SourcePattern) []taintpatterns.SourcePattern {
	out := make([]taintpatterns.SourcePattern, 0, len(srcs))
	for _, s := range srcs {
		out = append(out, taintpatterns.SourcePattern{
			FuncName:    s.FuncName,
			IsSubscript: s.IsSubscript,
		})
	}
	return out
}

func toTaintSinks(sinks []SinkPattern) []taintpatterns.SinkPattern {
	out := make([]taintpatterns.SinkPattern, 0, len(sinks))
	for _, s := range sinks {
		out = append(out, taintpatterns.SinkPattern{
			FuncName: s.FuncName,
			ArgIndex: s.ArgIndex,
		})
	}
	return out
}

// taintLanguage maps framework language names to the taint engine's language
// identifiers. The taint engine uses "c_sharp" for C#.
func taintLanguage(lang string) string {
	switch lang {
	case "csharp":
		return "c_sharp"
	default:
		return lang
	}
}
