package taintpatterns

import (
	"fmt"
	"strings"

	"github.com/odvcencio/gotreesitter"
)

// CallGraph represents a file-level call graph mapping caller functions to
// their callees. It also records each function's parameters (for taint
// passthrough tracking) and which functions return tainted data or consume
// tainted parameters.
type CallGraph struct {
	// Functions maps function name → FunctionInfo for every function defined
	// in the file.
	Functions map[string]*FunctionInfo

	// Edges maps caller function name → list of callee names called within
	// that function's body.
	Edges map[string][]CallEdge
}

// FunctionInfo holds per-function metadata for inter-procedural analysis.
type FunctionInfo struct {
	Name       string
	Params     []string // parameter names (for taint passthrough)
	Node       *gotreesitter.Node
	// TaintedParams is set during Pass 1: indices of params that receive
	// tainted data at a call site (populated in Pass 2).
	TaintedParams map[int]bool
	// ReturnsTainted is set during Pass 1: does this function return a value
	// derived from a taint source?
	ReturnsTainted bool
	// ConsumesTainted is set during Pass 1: does this function pass a
	// parameter to a sink?
	ConsumesTaintedParam []int // param indices that flow to a sink
}

// CallEdge represents a call from one function to another, with the argument
// expressions so Pass 2 can determine which arguments are tainted.
type CallEdge struct {
	Callee    string
	CallNode  *gotreesitter.Node
	ArgNodes  []*gotreesitter.Node
	ArgTexts  []string
	LineStart int
}

// BuildCallGraph walks the AST of a parsed file and constructs a file-level
// call graph. For each function definition it records:
//   - The function name and parameter names
//   - All call sites within the function body (callee name + argument nodes)
//
// The graph is used by the inter-procedural taint analyzer to propagate
// taint across function boundaries.
func BuildCallGraph(rootNode *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string, src []byte) *CallGraph {
	cg := &CallGraph{
		Functions: make(map[string]*FunctionInfo),
		Edges:     make(map[string][]CallEdge),
	}

	collectFunctions(rootNode, bt, lang, cg)
	collectCallEdges(rootNode, bt, lang, cg)
	return cg
}

// collectFunctions walks the AST and registers every function definition.
func collectFunctions(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string, cg *CallGraph) {
	if node == nil {
		return
	}
	nt := bt.NodeType(node)
	if isFunctionDef(nt, lang) {
		name := getFunctionName(node, bt, lang)
		if name == "" {
			// Anonymous function (arrow function, function expression) —
			// generate a synthetic name based on position so it's still
			// registered in the call graph and analyzed in Pass 2.
			name = fmt.Sprintf("__anon_%d_%d", node.StartPoint().Row, node.StartPoint().Column)
		}
		params := getFunctionParams(node, bt, lang)
		if existing, ok := cg.Functions[name]; ok {
			// Keep the first definition; merge params if empty.
			if len(existing.Params) == 0 && len(params) > 0 {
				existing.Params = params
			}
		} else {
			cg.Functions[name] = &FunctionInfo{
				Name:          name,
				Params:        params,
				Node:          node,
				TaintedParams: make(map[int]bool),
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectFunctions(node.Child(i), bt, lang, cg)
	}
}

// collectCallEdges walks the AST and, for each function definition, records
// all call sites within its body.
func collectCallEdges(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string, cg *CallGraph) {
	if node == nil {
		return
	}
	nt := bt.NodeType(node)
	if isFunctionDef(nt, lang) {
		callerName := getFunctionName(node, bt, lang)
		if callerName == "" {
			callerName = fmt.Sprintf("__anon_%d_%d", node.StartPoint().Row, node.StartPoint().Column)
		}
		if callerName != "" {
			bodyNode := getFunctionBody(node, bt, lang)
			if bodyNode != nil {
				collectCallsInBody(bodyNode, bt, lang, cg, callerName)
			}
		}
	}
	// PHP top-level code
	if nt == "program" && lang == "php" {
		collectCallsInBody(node, bt, lang, cg, "__top_level__")
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectCallEdges(node.Child(i), bt, lang, cg)
	}
}

// collectCallsInBody walks a function body and records every call expression
// as a CallEdge in the call graph.
func collectCallsInBody(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string, cg *CallGraph, caller string) {
	if node == nil {
		return
	}
	nt := bt.NodeType(node)

	// Detect call nodes (same set as walkFunctionBody uses for sinks)
	if isCallNode(nt) {
		calleeName := extractCallName(node, bt, lang)
		if calleeName != "" {
			edge := CallEdge{
				Callee:    calleeName,
				CallNode:  node,
				LineStart: int(node.StartPoint().Row) + 1,
			}
			// Extract argument nodes
			argsNode := extractCallArgs(node, bt, lang)
			if argsNode != nil {
				for i := 0; i < int(argsNode.ChildCount()); i++ {
					arg := argsNode.Child(i)
					if arg == nil || isPunctuation(bt.NodeType(arg)) {
						continue
					}
					edge.ArgNodes = append(edge.ArgNodes, arg)
					edge.ArgTexts = append(edge.ArgTexts, bt.NodeText(arg))
				}
			}
			cg.Edges[caller] = append(cg.Edges[caller], edge)
		}
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		collectCallsInBody(node.Child(i), bt, lang, cg, caller)
	}
}

// isCallNode returns true if the node type represents a function/method call.
func isCallNode(nt string) bool {
	return nt == "call" || nt == "call_expression" ||
		nt == "function_call_expression" || nt == "method_invocation" ||
		nt == "invocation_expression" || nt == "object_creation_expression"
}

// getFunctionName extracts the name of a function definition node.
func getFunctionName(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) string {
	// Python: function_definition has "name" field
	if nameNode := bt.ChildByField(node, "name"); nameNode != nil {
		return bt.NodeText(nameNode)
	}
	// JS/TS: function_declaration has "name" field; method_definition has "name"
	// (already covered above)
	// Ruby: method has "name" field
	// PHP: function_definition has "name" field
	// Java/C#: method_declaration has "name" field

	// Fallback: look for the first identifier child
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		ct := bt.NodeType(child)
		if ct == "identifier" || ct == "property_identifier" {
			return bt.NodeText(child)
		}
	}
	return ""
}

// getFunctionBody returns the body node of a function definition.
func getFunctionBody(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) *gotreesitter.Node {
	// Most languages use "body" field
	if body := bt.ChildByField(node, "body"); body != nil {
		return body
	}
	// Fallback: look for block / function_body / statement_block child
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		ct := bt.NodeType(child)
		if ct == "block" || ct == "function_body" || ct == "statement_block" ||
			ct == "compound_statement" || ct == "block_statement" {
			return child
		}
	}
	return nil
}

// getFunctionParams extracts parameter names from a function definition.
func getFunctionParams(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) []string {
	// Most languages use "parameters" field
	if paramsNode := bt.ChildByField(node, "parameters"); paramsNode != nil {
		return extractParamNames(paramsNode, bt)
	}
	// Fallback: look for "parameter_list", "formal_parameters", "parameter_list" child
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		ct := bt.NodeType(child)
		if ct == "parameters" || ct == "parameter_list" || ct == "formal_parameters" ||
			ct == "parameter_list_clause" {
			return extractParamNames(child, bt)
		}
	}
	return nil
}

// extractParamNames walks a parameters node and extracts parameter names.
func extractParamNames(paramsNode *gotreesitter.Node, bt *gotreesitter.BoundTree) []string {
	var params []string
	for i := 0; i < int(paramsNode.ChildCount()); i++ {
		child := paramsNode.Child(i)
		if child == nil {
			continue
		}
		ct := bt.NodeType(child)
		// Skip punctuation
		if isPunctuation(ct) {
			continue
		}
		// Direct identifier or variable_name (PHP $var)
		if ct == "identifier" || ct == "variable_name" || ct == "variable_declaration" {
			params = append(params, bt.NodeText(child))
			continue
		}
		// Typed parameters: Python "default_parameter", "typed_parameter";
		// JS "formal_parameter"; Java "formal_parameter"; C# "parameter"
		// These have a "name" or "pattern" field
		if nameNode := bt.ChildByField(child, "name"); nameNode != nil {
			params = append(params, bt.NodeText(nameNode))
			continue
		}
		if patternNode := bt.ChildByField(child, "pattern"); patternNode != nil {
			params = append(params, bt.NodeText(patternNode))
			continue
		}
		// Ruby "method_parameters" → "identifier" children
		// Try first identifier child
		for j := 0; j < int(child.ChildCount()); j++ {
			grandchild := child.Child(j)
			if grandchild == nil {
				continue
			}
			gct := bt.NodeType(grandchild)
			if gct == "identifier" || gct == "variable_name" {
				params = append(params, bt.NodeText(grandchild))
				break
			}
		}
	}
	return params
}

// GetCallees returns all functions called from the given caller.
func (cg *CallGraph) GetCallees(caller string) []CallEdge {
	return cg.Edges[caller]
}

// GetFunction returns the FunctionInfo for a given name, or nil if not found.
func (cg *CallGraph) GetFunction(name string) *FunctionInfo {
	return cg.Functions[name]
}

// HasFunction returns true if the call graph contains a function with the
// given name.
func (cg *CallGraph) HasFunction(name string) bool {
	_, ok := cg.Functions[name]
	return ok
}

// IsKnownFunction checks if a callee name matches any function defined in
// this file. Handles both simple names and dotted names (e.g., "self.helper"
// → "helper").
func (cg *CallGraph) IsKnownFunction(callee string) bool {
	if cg.HasFunction(callee) {
		return true
	}
	// Try the last component of a dotted name
	if idx := strings.LastIndex(callee, "."); idx >= 0 {
		return cg.HasFunction(callee[idx+1:])
	}
	return false
}

// ResolveFunction looks up a callee name, handling dotted names by falling
// back to the last component.
func (cg *CallGraph) ResolveFunction(callee string) *FunctionInfo {
	if fn := cg.Functions[callee]; fn != nil {
		return fn
	}
	if idx := strings.LastIndex(callee, "."); idx >= 0 {
		return cg.Functions[callee[idx+1:]]
	}
	return nil
}
