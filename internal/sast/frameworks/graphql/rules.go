package graphql

import (
	"regexp"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

var frameworkSourceExclusions = []frameworks.PathPattern{
	{Glob: "django/**", Reason: "Do not apply GraphQL rules to Django framework source."},
	{Glob: "flask/**", Reason: "Do not apply GraphQL rules to Flask framework source."},
	{Glob: "graphene/**", Reason: "Do not apply GraphQL rules to Graphene library source."},
	{Glob: "ariadne/**", Reason: "Do not apply GraphQL rules to Ariadne library source."},
	{Glob: "tests/**", Reason: "Framework tests are not deployed application code."},
	{Glob: "docs/**", Reason: "Documentation examples are not application code."},
}

func Rules() []frameworks.FrameworkRule {
	return []frameworks.FrameworkRule{
		// === MatchTaint: source→sink taint tracking ===
		{
			ID:             "PF-GRAPHQL-SQLI-001",
			Framework:      "graphql",
			Language:       "python",
			CWE:            "CWE-89",
			Title:          "GraphQL SQLi: resolver args flow to raw SQL (text/execute)",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".py"},
			MatchMode:      frameworks.MatchTaint,
			Sources:        Sources,
			Sinks: []frameworks.SinkPattern{
				{FuncName: "text", ArgIndex: 0},
				{FuncName: "execute", ArgIndex: 0},
				{FuncName: "session.execute", ArgIndex: 0},
				{FuncName: "db.session.execute", ArgIndex: 0},
			},
			Sanitizers:     Sanitizers,
			SafePatterns: []frameworks.SafePattern{
				{Regex: regexp.MustCompile(`:\w+`), Reason: "Named parameter placeholder (e.g., :id) indicates bound parameters."},
				{Regex: regexp.MustCompile(`bindparam`), Reason: "SQLAlchemy bindparam() indicates bound parameters."},
			},
			Recommendation: "GraphQL resolver arguments are user-controlled. Use parameterized queries or ORM filters instead of string interpolation into SQL.",
		},
		{
			ID:             "PF-GRAPHQL-SSRF-001",
			Framework:      "graphql",
			Language:       "python",
			CWE:            "CWE-918",
			Title:          "GraphQL SSRF: resolver args flow to outbound HTTP request",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".py"},
			MatchMode:      frameworks.MatchTaint,
			Sources:        Sources,
			Sinks: []frameworks.SinkPattern{
				{FuncName: "requests.get", ArgIndex: 0},
				{FuncName: "requests.post", ArgIndex: 0},
				{FuncName: "httpx.get", ArgIndex: 0},
				{FuncName: "httpx.post", ArgIndex: 0},
			},
			Sanitizers:     Sanitizers,
			Recommendation: "Validate outbound URLs against an allowlist before using resolver-controlled values in HTTP requests.",
		},
		{
			ID:             "PF-GRAPHQL-PATH-001",
			Framework:      "graphql",
			Language:       "python",
			CWE:            "CWE-22",
			Title:          "GraphQL path traversal: resolver args flow to file operations",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".py"},
			MatchMode:      frameworks.MatchTaint,
			Sources:        Sources,
			Sinks: []frameworks.SinkPattern{
				{FuncName: "open", ArgIndex: 0},
				{FuncName: "send_file", ArgIndex: 0},
				{FuncName: "send_from_directory", ArgIndex: 0},
			},
			Sanitizers:     Sanitizers,
			Recommendation: "Validate and sanitize file paths from resolver arguments. Use secure_filename and restrict to an allowed directory.",
		},

		// === MatchPattern: structural patterns ===
		{
			ID:             "PF-GRAPHQL-AUTH-001",
			Framework:      "graphql",
			Language:       "python",
			CWE:            "CWE-639",
			Title:          "GraphQL authorization: resolver fetches object by id without ownership check",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceLow,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".py"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`(filter_by|filter|get|query)\s*\(\s*[^)]*id\s*=\s*(id|obj_id|object_id|item_id)`),
			Sanitizers:     Sanitizers,
			Exclusions:     frameworkSourceExclusions,
			SafePatterns: []frameworks.SafePattern{
				{Regex: regexp.MustCompile(`(current_user|owner|user_id|auth|permission|authorize)`), Reason: "Ownership or authorization check present on same line."},
			},
			Recommendation: "Verify object ownership before returning data fetched by resolver-supplied id. Use IDOR-safe patterns: filter by current_user or check permissions.",
		},
		{
			ID:             "PF-GRAPHQL-DOS-001",
			Framework:      "graphql",
			Language:       "python",
			CWE:            "CWE-400",
			Title:          "GraphQL DoS: missing depth/complexity limit configuration",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceLow,
			Maturity:       frameworks.MaturityExperimental,
			FileTypes:      []string{".py"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`(build_schema|make_executable_schema|Schema|GraphQLSchema)\s*\(`),
			Sanitizers:     Sanitizers,
			Exclusions:     frameworkSourceExclusions,
			SafePatterns: []frameworks.SafePattern{
				{Regex: regexp.MustCompile(`(depth_limit|complexity|cost_analysis|DepthLimit|CostAnalysis|validation_rules)`), Reason: "Depth limit or complexity analysis configured."},
			},
			Recommendation: "Configure query depth limits and complexity analysis to prevent resource exhaustion via deeply nested or expensive GraphQL queries.",
		},
	}
}
