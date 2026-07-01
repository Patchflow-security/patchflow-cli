// Package taintpatterns — inter-procedural taint analysis.
//
// This file implements two-pass inter-procedural taint propagation on top of
// the existing intra-procedural analysis. It catches the remaining 20% of
// injection vulnerabilities where the taint source and sink are in different
// functions — the gap vs semgrep.
//
// Pass 1 (intra): Run the existing per-function taint analysis. For each
// function, record:
//   - ReturnsTainted: does the function return data derived from a taint source?
//   - ConsumesTaintedParam: which parameter indices flow to a sink?
//
// Pass 2 (inter): For each call site:
//   - If calling a ReturnsTainted function, mark the return value as tainted
//     in the caller and continue intra-procedural analysis.
//   - If calling a ConsumesTaintedParam function with a tainted argument,
//     fire the sink rule with an inter-procedural rule ID (ConfidenceHigh).
//
// Depth is limited to 3 call hops (configurable) to avoid path explosion.
// Each function boundary crossed in the taint path adds 1 to the depth.
// Recursion is guarded by a visited set.
package taintpatterns

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/odvcencio/gotreesitter"
	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
)

// DefaultTaintDepth is the default maximum call-hop depth for inter-procedural
// taint propagation.
const DefaultTaintDepth = 3

// InterproceduralAnalyzer performs inter-procedural taint analysis on a
// single file using a pre-built call graph.
type InterproceduralAnalyzer struct {
	rules      []Rule
	taintDepth int
}

// NewInterproceduralAnalyzer creates an inter-procedural analyzer that uses
// the same rules as the intra-procedural analyzer.
func NewInterproceduralAnalyzer(rules []Rule, depth int) *InterproceduralAnalyzer {
	if depth <= 0 {
		depth = DefaultTaintDepth
	}
	return &InterproceduralAnalyzer{rules: rules, taintDepth: depth}
}

// Analyze performs the two-pass inter-procedural taint analysis on a file.
//
// Parameters:
//   - rootNode: the root AST node of the parsed file
//   - bt: the bound tree for field/text access
//   - lang: language name ("python", "javascript", etc.)
//   - absPath: absolute file path
//   - root: repository root (for relative path computation)
//   - src: raw source bytes
//
// Returns inter-procedural findings (rule IDs suffixed with "-IP").
func (ia *InterproceduralAnalyzer) Analyze(
	rootNode *gotreesitter.Node,
	bt *gotreesitter.BoundTree,
	lang, absPath, root string,
	src []byte,
) []analysis.Finding {
	cg := BuildCallGraph(rootNode, bt, lang, src)

	// Pass 1: Analyze each function in isolation to determine:
	//   - ReturnsTainted: does it return data from a taint source?
	//   - ConsumesTaintedParam: which params flow to sinks?
	ia.pass1Intra(cg, bt, lang, absPath, root, src)

	// Pass 2: Propagate taint across function boundaries.
	findings := ia.pass2Inter(cg, bt, lang, absPath, root, src)
	return findings
}

// pass1Intra runs the existing intra-procedural analysis on each function
// and records taint summaries in the call graph.
func (ia *InterproceduralAnalyzer) pass1Intra(
	cg *CallGraph,
	bt *gotreesitter.BoundTree,
	lang, absPath, root string,
	src []byte,
) {
	for name, fnInfo := range cg.Functions {
		if fnInfo.Node == nil {
			continue
		}
		// Run intra-procedural analysis to collect tainted vars
		taintedVars := make(map[string]bool)
		varDepth := make(map[string]int)
		var intraFindings []analysis.Finding
		ia.walkFunctionBodyIP(fnInfo.Node, bt, lang, absPath, root, src, taintedVars, varDepth, &intraFindings, cg, name, map[string]bool{})

		// Check if the function returns tainted data
		fnInfo.ReturnsTainted = ia.returnsTaintedData(fnInfo.Node, bt, taintedVars)

		// Check which parameters flow to sinks: for each param, mark only that
		// param as tainted and see if any sink finding fires.
		if len(fnInfo.Params) > 0 {
			for i, p := range fnInfo.Params {
				singleTainted := map[string]bool{p: true}
				singleDepth := map[string]int{p: 0}
				var sinkFindings []analysis.Finding
				ia.walkFunctionBodyIP(fnInfo.Node, bt, lang, absPath, root, src, singleTainted, singleDepth, &sinkFindings, cg, name, map[string]bool{})
				if len(sinkFindings) > 0 {
					fnInfo.ConsumesTaintedParam = append(fnInfo.ConsumesTaintedParam, i)
				}
			}
		}
	}
}

// pass2Inter propagates taint across function boundaries and fires
// inter-procedural findings.
func (ia *InterproceduralAnalyzer) pass2Inter(
	cg *CallGraph,
	bt *gotreesitter.BoundTree,
	lang, absPath, root string,
	src []byte,
) []analysis.Finding {
	var findings []analysis.Finding

	for callerName, fnInfo := range cg.Functions {
		if fnInfo.Node == nil {
			continue
		}
		// Re-run intra analysis with inter-procedural taint propagation
		taintedVars := make(map[string]bool)
		varDepth := make(map[string]int)
		ia.walkFunctionBodyIP(fnInfo.Node, bt, lang, absPath, root, src, taintedVars, varDepth, &findings, cg, callerName, map[string]bool{callerName: true})
	}

	return findings
}

// walkFunctionBodyIP is the inter-procedural version of walkFunctionBody.
// It extends the intra-procedural walk with:
//   - When a call to a ReturnsTainted function is encountered, the LHS
//     variable is marked as tainted.
//   - When a call to a ConsumesTaintedParam function is encountered with a
//     tainted argument, an inter-procedural finding is fired.
//   - Depth limiting and recursion guards prevent path explosion.
//
// varDepth tracks the taint path length per variable (number of function
// boundaries crossed). A direct source has depth 0; each function call in
// the chain adds 1.
func (ia *InterproceduralAnalyzer) walkFunctionBodyIP(
	fnNode *gotreesitter.Node,
	bt *gotreesitter.BoundTree,
	lang, absPath, root string,
	src []byte,
	taintedVars map[string]bool,
	varDepth map[string]int,
	findings *[]analysis.Finding,
	cg *CallGraph,
	currentFn string,
	visited map[string]bool,
) {
	bodyNode := getFunctionBody(fnNode, bt, lang)
	if bodyNode == nil {
		return
	}
	ia.walkNodeIP(bodyNode, bt, lang, absPath, root, src, taintedVars, varDepth, findings, cg, currentFn, visited)
}

// walkNodeIP recursively walks a subtree performing inter-procedural taint
// tracking.
func (ia *InterproceduralAnalyzer) walkNodeIP(
	node *gotreesitter.Node,
	bt *gotreesitter.BoundTree,
	lang, absPath, root string,
	src []byte,
	taintedVars map[string]bool,
	varDepth map[string]int,
	findings *[]analysis.Finding,
	cg *CallGraph,
	currentFn string,
	visited map[string]bool,
) {
	if node == nil {
		return
	}
	nt := bt.NodeType(node)

	// Handle assignments
	if nt == "assignment" || nt == "assignment_expression" || nt == "variable_declarator" ||
		nt == "lexical_declaration" || nt == "variable_declaration" ||
		nt == "operator_assignment" || nt == "simple_assignment" ||
		nt == "local_variable_declaration" || nt == "local_declaration_statement" {
		ia.checkAssignmentIP(node, bt, lang, absPath, root, src, taintedVars, varDepth, cg, currentFn, visited)
	}

	// Handle calls (sinks + inter-procedural propagation)
	if isCallNode(nt) {
		ia.checkCallIP(node, bt, lang, absPath, root, src, taintedVars, varDepth, findings, cg, currentFn, visited)
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		ia.walkNodeIP(node.Child(i), bt, lang, absPath, root, src, taintedVars, varDepth, findings, cg, currentFn, visited)
	}
}

// checkAssignmentIP extends checkAssignment with inter-procedural taint
// propagation: if the RHS is a call to a ReturnsTainted function, the LHS
// is marked as tainted with depth = max(arg depths) + 1.
func (ia *InterproceduralAnalyzer) checkAssignmentIP(
	node *gotreesitter.Node,
	bt *gotreesitter.BoundTree,
	lang, absPath, root string,
	src []byte,
	taintedVars map[string]bool,
	varDepth map[string]int,
	cg *CallGraph,
	currentFn string,
	visited map[string]bool,
) {
	// First, run the standard intra-procedural check (marks vars from sources
	// and from references to existing tainted vars).
	ia.checkAssignmentIntra(node, bt, lang, src, taintedVars, varDepth)

	// Then check if the RHS is a call to a ReturnsTainted function.
	nt := bt.NodeType(node)
	var rhsNode *gotreesitter.Node
	var lhsNode *gotreesitter.Node

	if nt == "assignment" || nt == "operator_assignment" || nt == "simple_assignment" {
		lhsNode = bt.ChildByField(node, "left")
		rhsNode = bt.ChildByField(node, "right")
	} else if nt == "variable_declarator" {
		lhsNode = bt.ChildByField(node, "name")
		rhsNode = bt.ChildByField(node, "value")
		if rhsNode == nil {
			for i := int(node.ChildCount()) - 1; i >= 0; i-- {
				child := node.Child(i)
				if child == nil || isPunctuation(bt.NodeType(child)) {
					continue
				}
				if child == lhsNode {
					break
				}
				rhsNode = child
				break
			}
		}
	} else if nt == "assignment_expression" {
		lhsNode = bt.ChildByField(node, "left")
		rhsNode = bt.ChildByField(node, "right")
		if rhsNode == nil {
			for i := int(node.ChildCount()) - 1; i >= 0; i-- {
				child := node.Child(i)
				if child == nil || isPunctuation(bt.NodeType(child)) {
					continue
				}
				if child == lhsNode {
					break
				}
				rhsNode = child
				break
			}
		}
	} else {
		// Declaration wrappers — their variable_declarator children are
		// already handled by the recursive walk.
		return
	}

	if rhsNode == nil || lhsNode == nil {
		return
	}

	// Check if RHS is a call to a taint-returning function
	rhsType := bt.NodeType(rhsNode)
	if !isCallNode(rhsType) {
		return
	}

	calleeName := extractCallName(rhsNode, bt, lang)
	if calleeName == "" {
		return
	}

	calleeFn := cg.ResolveFunction(calleeName)
	if calleeFn == nil {
		return
	}

	varName := bt.NodeText(lhsNode)
	if varName == "" {
		return
	}

	// Compute the max taint depth of the arguments (-1 if no tainted args)
	argDepth := ia.getMaxArgDepth(rhsNode, bt, taintedVars, varDepth)

	// The new depth for this variable = max(argDepth, 0) + 1
	// (crossing the callee boundary adds 1; if the callee has its own source
	// and no tainted args, argDepth is -1 but the call itself is 1 hop)
	newDepth := argDepth + 1
	if argDepth < 0 {
		newDepth = 1
	}

	// Check depth limit
	if newDepth > ia.taintDepth {
		return
	}

	// Recursion guard
	if visited[calleeFn.Name] {
		// Use Pass 1 result for return taint
		if calleeFn.ReturnsTainted {
			taintedVars[varName] = true
			varDepth[varName] = newDepth
		}
		return
	}

	// Check if the callee returns tainted data, propagating tainted args
	isTaintedReturn := ia.isReturnTaintedInterprocedural(calleeFn, cg, bt, lang, absPath, root, src, rhsNode, taintedVars, varDepth, visited)
	if isTaintedReturn {
		taintedVars[varName] = true
		varDepth[varName] = newDepth
	}
}

// getMaxArgDepth computes the maximum taint depth among the arguments of a
// call node. Returns -1 if no arguments are tainted.
func (ia *InterproceduralAnalyzer) getMaxArgDepth(
	callNode *gotreesitter.Node,
	bt *gotreesitter.BoundTree,
	taintedVars map[string]bool,
	varDepth map[string]int,
) int {
	argsNode := extractCallArgs(callNode, bt, "")
	if argsNode == nil {
		return -1
	}
	maxDepth := -1
	for i := 0; i < int(argsNode.ChildCount()); i++ {
		arg := argsNode.Child(i)
		if arg == nil || isPunctuation(bt.NodeType(arg)) {
			continue
		}
		if isArgTainted(arg, bt, taintedVars) {
			d := ia.getExprDepth(arg, bt, varDepth)
			if d > maxDepth {
				maxDepth = d
			}
		}
	}
	return maxDepth
}

// getExprDepth returns the taint depth of an expression node. For identifiers,
// it looks up varDepth. For compound expressions, it finds the max depth of
// any tainted identifier within.
func (ia *InterproceduralAnalyzer) getExprDepth(node *gotreesitter.Node, bt *gotreesitter.BoundTree, varDepth map[string]int) int {
	if node == nil {
		return 0
	}
	nt := bt.NodeType(node)
	if nt == "identifier" || nt == "variable_name" {
		name := bt.NodeText(node)
		if d, ok := varDepth[name]; ok {
			return d
		}
		return 0
	}
	maxDepth := 0
	for i := 0; i < int(node.ChildCount()); i++ {
		d := ia.getExprDepth(node.Child(i), bt, varDepth)
		if d > maxDepth {
			maxDepth = d
		}
	}
	return maxDepth
}

// checkAssignmentIntra is the standard intra-procedural assignment check,
// reused from the base analyzer logic. It also updates varDepth for direct
// source assignments (depth = 0).
func (ia *InterproceduralAnalyzer) checkAssignmentIntra(
	node *gotreesitter.Node,
	bt *gotreesitter.BoundTree,
	lang string,
	src []byte,
	taintedVars map[string]bool,
	varDepth map[string]int,
) {
	nt := bt.NodeType(node)

	if nt == "lexical_declaration" || nt == "variable_declaration" || nt == "local_variable_declaration" ||
		nt == "local_declaration_statement" {
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child == nil {
				continue
			}
			childType := bt.NodeType(child)
			if childType == "variable_declarator" {
				ia.checkAssignmentIntra(child, bt, lang, src, taintedVars, varDepth)
			}
			if childType == "variable_declaration" {
				ia.checkAssignmentIntra(child, bt, lang, src, taintedVars, varDepth)
			}
		}
		return
	}

	var lhsNode, rhsNode *gotreesitter.Node
	if nt == "assignment" || nt == "operator_assignment" || nt == "simple_assignment" {
		lhsNode = bt.ChildByField(node, "left")
		rhsNode = bt.ChildByField(node, "right")
	} else if nt == "variable_declarator" {
		lhsNode = bt.ChildByField(node, "name")
		rhsNode = bt.ChildByField(node, "value")
		if rhsNode == nil {
			for i := int(node.ChildCount()) - 1; i >= 0; i-- {
				child := node.Child(i)
				if child == nil || isPunctuation(bt.NodeType(child)) {
					continue
				}
				if child == lhsNode {
					break
				}
				rhsNode = child
				break
			}
		}
	} else if nt == "assignment_expression" {
		lhsNode = bt.ChildByField(node, "left")
		rhsNode = bt.ChildByField(node, "right")
		if rhsNode == nil {
			for i := int(node.ChildCount()) - 1; i >= 0; i-- {
				child := node.Child(i)
				if child == nil || isPunctuation(bt.NodeType(child)) {
					continue
				}
				if child == lhsNode {
					break
				}
				rhsNode = child
				break
			}
		}
	}

	if lhsNode == nil || rhsNode == nil {
		return
	}

	varName := bt.NodeText(lhsNode)
	if varName == "" {
		return
	}

	for _, rule := range ia.rules {
		if rule.Language != lang {
			continue
		}
		for _, source := range rule.Sources {
			if matchesSource(rhsNode, bt, src, source) {
				taintedVars[varName] = true
				varDepth[varName] = 0 // direct source = depth 0
				return
			}
		}
	}

	if referencesTaintedVar(rhsNode, bt, taintedVars) {
		taintedVars[varName] = true
		// Inherit the max depth from referenced tainted vars
		varDepth[varName] = ia.getExprDepth(rhsNode, bt, varDepth)
	}
}

// checkCallIP checks a call node for both intra-procedural sinks and
// inter-procedural taint consumption.
func (ia *InterproceduralAnalyzer) checkCallIP(
	node *gotreesitter.Node,
	bt *gotreesitter.BoundTree,
	lang, absPath, root string,
	src []byte,
	taintedVars map[string]bool,
	varDepth map[string]int,
	findings *[]analysis.Finding,
	cg *CallGraph,
	currentFn string,
	visited map[string]bool,
) {
	funcName := extractCallName(node, bt, lang)
	if funcName == "" {
		return
	}

	argsNode := extractCallArgs(node, bt, lang)
	if argsNode == nil {
		return
	}

	// Collect argument nodes
	var argNodes []*gotreesitter.Node
	var argTexts []string
	for i := 0; i < int(argsNode.ChildCount()); i++ {
		arg := argsNode.Child(i)
		if arg == nil || isPunctuation(bt.NodeType(arg)) {
			continue
		}
		argNodes = append(argNodes, arg)
		argTexts = append(argTexts, bt.NodeText(arg))
	}

	// 1. Check standard sinks (intra-procedural)
	for _, rule := range ia.rules {
		if rule.Language != lang {
			continue
		}
		for _, sink := range rule.Sinks {
			if !sinkMatches(funcName, sink.FuncName) {
				continue
			}
			for idx, arg := range argNodes {
				if sink.ArgIndex >= 0 && idx != sink.ArgIndex {
					continue
				}
				if isArgTainted(arg, bt, taintedVars) {
					f := ia.makeIPFinding(rule, node, bt, absPath, root, funcName, argTexts[idx])
					*findings = append(*findings, f)
					break
				}
			}
		}
	}

	// 2. Inter-procedural: check if calling a function that consumes tainted params
	calleeFn := cg.ResolveFunction(funcName)
	if calleeFn == nil || len(calleeFn.ConsumesTaintedParam) == 0 {
		return
	}

	// Recursion guard
	if visited[calleeFn.Name] {
		return
	}

	// Check if any of the consumed params have tainted arguments at this call site
	for _, paramIdx := range calleeFn.ConsumesTaintedParam {
		if paramIdx >= len(argNodes) {
			continue
		}
		arg := argNodes[paramIdx]
		if !isArgTainted(arg, bt, taintedVars) {
			continue
		}

		argD := ia.getExprDepth(arg, bt, varDepth)
		totalDepth := argD + 1 // +1 for crossing into the callee

		// Check depth limit
		if totalDepth > ia.taintDepth {
			continue
		}

		// Fire inter-procedural finding for each matching rule
		for _, rule := range ia.rules {
			if rule.Language != lang {
				continue
			}
			for _, sink := range rule.Sinks {
				if !sinkMatches(funcName, sink.FuncName) {
					continue
				}
				f := ia.makeIPFinding(rule, node, bt, absPath, root, funcName, argTexts[paramIdx])
				*findings = append(*findings, f)
			}
		}

		// Recursively analyze the callee to find deeper sinks
		newVisited := copyVisited(visited)
		newVisited[calleeFn.Name] = true

		// Propagate taint into callee's parameter
		calleeTainted := make(map[string]bool)
		calleeDepth := make(map[string]int)
		if paramIdx < len(calleeFn.Params) {
			calleeTainted[calleeFn.Params[paramIdx]] = true
			calleeDepth[calleeFn.Params[paramIdx]] = totalDepth
		}

		var subFindings []analysis.Finding
		bodyNode := getFunctionBody(calleeFn.Node, bt, lang)
		if bodyNode != nil {
			ia.walkNodeIP(bodyNode, bt, lang, absPath, root, src,
				calleeTainted, calleeDepth, &subFindings, cg, calleeFn.Name, newVisited)
		}
		*findings = append(*findings, subFindings...)
		break // one tainted arg is enough
	}
}

// isReturnTaintedInterprocedural checks if a function returns tainted data,
// considering inter-procedural calls within it. It propagates the tainted
// arguments from the call site into the callee's parameters.
func (ia *InterproceduralAnalyzer) isReturnTaintedInterprocedural(
	fnInfo *FunctionInfo,
	cg *CallGraph,
	bt *gotreesitter.BoundTree,
	lang, absPath, root string,
	src []byte,
	callNode *gotreesitter.Node,
	callerTaintedVars map[string]bool,
	callerVarDepth map[string]int,
	visited map[string]bool,
) bool {
	// Quick check: if Pass 1 already determined this function returns tainted
	// (from a direct source), return true.
	if fnInfo.ReturnsTainted {
		return true
	}

	// Propagate tainted arguments from the call site into the callee's params
	calleeTainted := make(map[string]bool)
	calleeDepth := make(map[string]int)

	argsNode := extractCallArgs(callNode, bt, lang)
	if argsNode != nil && len(fnInfo.Params) > 0 {
		argIdx := 0
		for i := 0; i < int(argsNode.ChildCount()); i++ {
			arg := argsNode.Child(i)
			if arg == nil || isPunctuation(bt.NodeType(arg)) {
				continue
			}
			if argIdx < len(fnInfo.Params) && isArgTainted(arg, bt, callerTaintedVars) {
				calleeTainted[fnInfo.Params[argIdx]] = true
				calleeDepth[fnInfo.Params[argIdx]] = ia.getExprDepth(arg, bt, callerVarDepth)
			}
			argIdx++
		}
	}

	// If no args were tainted, the function can't return tainted data
	// (unless it has its own internal sources, which Pass 1 would have caught)
	if len(calleeTainted) == 0 {
		return false
	}

	// Recursion guard
	if visited[fnInfo.Name] {
		return false
	}
	newVisited := copyVisited(visited)
	newVisited[fnInfo.Name] = true

	// Re-analyze the function with propagated taint
	var dummyFindings []analysis.Finding
	bodyNode := getFunctionBody(fnInfo.Node, bt, lang)
	if bodyNode == nil {
		return false
	}
	ia.walkNodeIP(bodyNode, bt, lang, absPath, root, src,
		calleeTainted, calleeDepth, &dummyFindings, cg, fnInfo.Name, newVisited)

	return ia.returnsTaintedData(fnInfo.Node, bt, calleeTainted)
}

// returnsTaintedData checks if a function has a return statement that
// returns a tainted variable or directly references a taint source.
func (ia *InterproceduralAnalyzer) returnsTaintedData(fnNode *gotreesitter.Node, bt *gotreesitter.BoundTree, taintedVars map[string]bool) bool {
	bodyNode := getFunctionBody(fnNode, bt, "")
	if bodyNode == nil {
		bodyNode = fnNode
	}
	return ia.findTaintedReturn(bodyNode, bt, taintedVars)
}

// findTaintedReturn recursively searches for return statements that reference
// tainted variables or directly match a taint source pattern.
func (ia *InterproceduralAnalyzer) findTaintedReturn(node *gotreesitter.Node, bt *gotreesitter.BoundTree, taintedVars map[string]bool) bool {
	if node == nil {
		return false
	}
	nt := bt.NodeType(node)
	if nt == "return_statement" || nt == "return" {
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child == nil {
				continue
			}
			ct := bt.NodeType(child)
			// Skip the "return" keyword itself
			if ct == "return" {
				continue
			}
			// Check if the return value references a tainted variable
			if ct == "identifier" || ct == "variable_name" {
				if taintedVars[bt.NodeText(child)] {
					return true
				}
			}
			if referencesTaintedVar(child, bt, taintedVars) {
				return true
			}
			// Check if the return value directly matches a source pattern
			// (e.g., return req.query.cmd — no assignment, direct source in return)
			if ia.matchesAnySource(child, bt) {
				return true
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		if ia.findTaintedReturn(node.Child(i), bt, taintedVars) {
			return true
		}
	}
	return false
}

// matchesAnySource checks if a node matches any taint source pattern across
// all rules (any language).
func (ia *InterproceduralAnalyzer) matchesAnySource(node *gotreesitter.Node, bt *gotreesitter.BoundTree) bool {
	text := bt.NodeText(node)
	for _, rule := range ia.rules {
		for _, source := range rule.Sources {
			if source.IsSubscript {
				if strings.Contains(text, source.FuncName) {
					return true
				}
			} else if strings.HasPrefix(text, source.FuncName) || text == source.FuncName {
				return true
			} else if strings.Contains(text, source.FuncName+"(") {
				return true
			}
		}
	}
	return false
}

// makeIPFinding creates an inter-procedural finding with the "-IP" rule ID
// suffix and ConfidenceHigh.
func (ia *InterproceduralAnalyzer) makeIPFinding(rule Rule, node *gotreesitter.Node, bt *gotreesitter.BoundTree, absPath, root, sinkFunc, argText string) analysis.Finding {
	startPoint := node.StartPoint()
	lineStart := int(startPoint.Row) + 1
	lineEnd := int(node.EndPoint().Row) + 1

	relPath, err := filepath.Rel(root, absPath)
	if err != nil {
		relPath = absPath
	}

	evidence := strings.TrimSpace(argText)
	if len(evidence) > 100 {
		evidence = evidence[:97] + "..."
	}

	// Build the inter-procedural rule ID
	ipRuleID := rule.ID + "-IP"

	return analysis.Finding{
		ID:             fmt.Sprintf("taint-ip-%s-%s-%d", ipRuleID, filepath.Base(relPath), lineStart),
		Type:           analysis.TypeSAST,
		Analyzer:       "taint-patterns",
		Severity:       rule.Severity,
		Confidence:     analysis.ConfidenceHigh, // Inter-procedural = higher confidence
		Title:          rule.Title + " (inter-procedural)",
		Description:    rule.Description + " Data flow confirmed across function boundaries.",
		FilePath:       relPath,
		LineStart:      lineStart,
		LineEnd:        lineEnd,
		RuleID:         ipRuleID,
		CWEID:          rule.CWEID,
		Evidence:       evidence,
		Recommendation: fmt.Sprintf("Ensure user input flowing into %s is sanitized/validated. Taint propagated across function calls.", sinkFunc),
		DetectedAt:     time.Now(),
	}
}

// copyVisited creates a copy of the visited set to avoid mutating the parent's
// set during recursive exploration.
func copyVisited(visited map[string]bool) map[string]bool {
	c := make(map[string]bool, len(visited))
	for k, v := range visited {
		c[k] = v
	}
	return c
}
