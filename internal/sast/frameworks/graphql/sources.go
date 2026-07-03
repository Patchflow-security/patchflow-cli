package graphql

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

// Sources defines GraphQL-specific taint entry points.
//
// The taint engine's seedGraphQLResolverParams() already pre-taints
// resolver args (parameters after root/parent/self and info in resolve_*
// and mutate functions). These source patterns supplement that by
// matching explicit property accesses on the info object and context.
var Sources = []frameworks.SourcePattern{
	// GraphQL info context — request data accessible via info.context
	{FuncName: "info.context", IsSubscript: true},
	{FuncName: "context.request", IsSubscript: true},
	{FuncName: "context.args", IsSubscript: true},

	// Graphene/Ariadne resolver argument patterns
	{FuncName: "info.variable_values", IsSubscript: true},
	{FuncName: "info.field_asts", IsSubscript: true},

	// Generic resolver argument access (matched via string containment)
	{FuncName: "kwargs", IsSubscript: true},
}
