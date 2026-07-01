package taintpatterns

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
)

// === Inter-procedural taint analysis tests ===
//
// These tests verify the Phase 4 inter-procedural taint engine:
//   - Multi-function source→sink detection (the differentiator vs semgrep)
//   - Depth-limit enforcement (3 hops fires, 4 hops doesn't)
//   - Recursion guard (self-calling function doesn't loop forever)
//   - ConfidenceHigh for IP findings, ConfidenceMedium for intra findings

// --- Helper ---

func scanPythonCodeWithDepth(t *testing.T, code string, depth int) []analysis.Finding {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.py")
	if err := os.WriteFile(path, []byte(code), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	a := NewAnalyzer()
	a.SetTaintDepth(depth)
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	return findings
}

func hasRuleWithConfidence(findings []analysis.Finding, ruleID string, conf analysis.Confidence) bool {
	for _, f := range findings {
		if f.RuleID == ruleID && f.Confidence == conf {
			return true
		}
	}
	return false
}

func hasAnyRule(findings []analysis.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

// --- Tests ---

// TestInterproceduralPythonSQLInjection tests the core differentiator:
// source and sink are in different functions. The intra-procedural analyzer
// alone would miss this; the inter-procedural pass catches it.
func TestInterproceduralPythonSQLInjection(t *testing.T) {
	code := `import flask
from flask import request
import sqlite3

def get_user_input():
    user_id = request.args.get("id")
    return user_id

@app.route("/users")
def get_user():
    uid = get_user_input()
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + uid)
    return str(cursor.fetchall())
`
	findings := scanPythonCodeWithDepth(t, code, 3)
	// Should fire the inter-procedural variant with ConfidenceHigh
	if !hasRuleWithConfidence(findings, "TP-PY001-IP", analysis.ConfidenceHigh) {
		t.Errorf("expected TP-PY001-IP (inter-procedural SQL injection) with ConfidenceHigh, got: %v", ruleIDs(findings))
	}
}

// TestInterproceduralPythonTaintedParamToSink tests the case where a tainted
// argument is passed to a function that forwards it to a sink.
func TestInterproceduralPythonTaintedParamToSink(t *testing.T) {
	code := `import flask
from flask import request
import sqlite3

def run_query(query):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + query)
    return str(cursor.fetchall())

@app.route("/users")
def get_user():
    user_id = request.args.get("id")
    return run_query(user_id)
`
	findings := scanPythonCodeWithDepth(t, code, 3)
	if !hasRuleWithConfidence(findings, "TP-PY001-IP", analysis.ConfidenceHigh) {
		t.Errorf("expected TP-PY001-IP (inter-procedural, tainted param to sink), got: %v", ruleIDs(findings))
	}
}

// TestInterproceduralDepthLimit3HopsFires tests that 3 call hops (the default
// depth limit) successfully detects the vulnerability.
//
// Chain: handler → get_source → transform → pass_to_sink
// This is 3 hops and should fire.
func TestInterproceduralDepthLimit3HopsFires(t *testing.T) {
	code := `from flask import request
import sqlite3

def level1_get():
    return request.args.get("id")

def level2_transform(val):
    return "prefix_" + val

def level3_sink(val):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + val)
    return str(cursor.fetchall())

@app.route("/users")
def handler():
    raw = level1_get()
    transformed = level2_transform(raw)
    return level3_sink(transformed)
`
	findings := scanPythonCodeWithDepth(t, code, 3)
	if !hasAnyRule(findings, "TP-PY001-IP") {
		t.Errorf("expected TP-PY001-IP at depth 3 (3 hops), got: %v", ruleIDs(findings))
	}
}

// TestInterproceduralDepthLimit4HopsDoesNotFire tests that 4 call hops
// exceeds the default depth limit of 3 and does NOT fire.
//
// Chain: handler → hop1 → hop2 → hop3 → hop4_sink
// With depth=3, this should NOT fire (4 hops exceeds the limit).
func TestInterproceduralDepthLimit4HopsDoesNotFire(t *testing.T) {
	code := `from flask import request
import sqlite3

def hop1(val):
    return val

def hop2(val):
    return val

def hop3(val):
    return val

def hop4_sink(val):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + val)
    return str(cursor.fetchall())

@app.route("/users")
def handler():
    raw = request.args.get("id")
    v1 = hop1(raw)
    v2 = hop2(v1)
    v3 = hop3(v2)
    return hop4_sink(v3)
`
	findings := scanPythonCodeWithDepth(t, code, 3)
	if hasAnyRule(findings, "TP-PY001-IP") {
		t.Errorf("TP-PY001-IP should NOT fire at depth 3 with 4 hops, got: %v", ruleIDs(findings))
	}
}

// TestInterproceduralDepthLimit4HopsFiresAtDepth4 tests that the same 4-hop
// chain fires when the depth is increased to 4.
func TestInterproceduralDepthLimit4HopsFiresAtDepth4(t *testing.T) {
	code := `from flask import request
import sqlite3

def hop1(val):
    return val

def hop2(val):
    return val

def hop3(val):
    return val

def hop4_sink(val):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + val)
    return str(cursor.fetchall())

@app.route("/users")
def handler():
    raw = request.args.get("id")
    v1 = hop1(raw)
    v2 = hop2(v1)
    v3 = hop3(v2)
    return hop4_sink(v3)
`
	findings := scanPythonCodeWithDepth(t, code, 4)
	if !hasAnyRule(findings, "TP-PY001-IP") {
		t.Errorf("expected TP-PY001-IP at depth 4 (4 hops), got: %v", ruleIDs(findings))
	}
}

// TestInterproceduralRecursionGuard tests that a function calling itself
// does not cause infinite recursion or a panic.
func TestInterproceduralRecursionGuard(t *testing.T) {
	code := `from flask import request
import sqlite3

def recursive_query(val, depth):
    if depth <= 0:
        conn = sqlite3.connect("db.sqlite")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = " + val)
        return str(cursor.fetchall())
    return recursive_query(val, depth - 1)

@app.route("/users")
def handler():
    user_id = request.args.get("id")
    return recursive_query(user_id, 5)
`
	// This should complete without hanging or panicking
	findings := scanPythonCodeWithDepth(t, code, 3)
	// We may or may not get a finding, but the key is no hang/panic
	_ = findings
}

// TestInterproceduralNoFalsePositiveHardcoded tests that inter-procedural
// analysis does not fire on hardcoded (non-tainted) data flowing through
// functions.
func TestInterproceduralNoFalsePositiveHardcoded(t *testing.T) {
	code := `import sqlite3

def get_constant():
    return "42"

def run_query(q):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + q)
    return str(cursor.fetchall())

def handler():
    val = get_constant()
    return run_query(val)
`
	findings := scanPythonCodeWithDepth(t, code, 3)
	if hasAnyRule(findings, "TP-PY001-IP") {
		t.Errorf("TP-PY001-IP should NOT fire for hardcoded (non-tainted) data, got: %v", ruleIDs(findings))
	}
}

// TestInterproceduralDisabledAtDepth0 tests that setting taint-depth to 0
// disables inter-procedural analysis entirely.
func TestInterproceduralDisabledAtDepth0(t *testing.T) {
	code := `from flask import request
import sqlite3

def get_input():
    return request.args.get("id")

def handler():
    uid = get_input()
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + uid)
    return str(cursor.fetchall())
`
	findings := scanPythonCodeWithDepth(t, code, 0)
	if hasAnyRule(findings, "TP-PY001-IP") {
		t.Errorf("TP-PY001-IP should NOT fire when taint-depth=0, got: %v", ruleIDs(findings))
	}
}

// TestInterproceduralJSCommandInjection tests inter-procedural detection
// for JavaScript command injection.
func TestInterproceduralJSCommandInjection(t *testing.T) {
	code := `const { exec } = require('child_process');
const express = require('express');
const app = express();

function getUserCmd(req) {
    return req.query.cmd;
}

app.get('/run', (req, res) => {
    const cmd = getUserCmd(req);
    exec('ls ' + cmd, (err, stdout) => {
        res.send(stdout);
    });
});
`
	dir := t.TempDir()
	path := filepath.Join(dir, "test.js")
	if err := os.WriteFile(path, []byte(code), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	a := NewAnalyzer()
	a.SetTaintDepth(3)
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if !hasAnyRule(findings, "TP-JS002-IP") {
		t.Errorf("expected TP-JS002-IP (inter-procedural JS command injection), got: %v", ruleIDs(findings))
	}
}

// TestInterproceduralConfidenceLevels tests that intra-procedural findings
// have ConfidenceMedium while inter-procedural findings have ConfidenceHigh.
func TestInterproceduralConfidenceLevels(t *testing.T) {
	// This code has BOTH an intra-procedural finding (direct source→sink
	// in handler2) and an inter-procedural finding (source→sink across
	// functions in handler1).
	code := `from flask import request
import sqlite3

def get_input():
    return request.args.get("id")

@app.route("/users1")
def handler1():
    uid = get_input()
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + uid)
    return str(cursor.fetchall())

@app.route("/users2")
def handler2():
    uid = request.args.get("id")
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + uid)
    return str(cursor.fetchall())
`
	findings := scanPythonCodeWithDepth(t, code, 3)

	// Intra-procedural finding should have ConfidenceMedium
	hasIntraMedium := false
	for _, f := range findings {
		if f.RuleID == "TP-PY001" && f.Confidence == analysis.ConfidenceMedium {
			hasIntraMedium = true
			break
		}
	}
	if !hasIntraMedium {
		t.Errorf("expected TP-PY001 (intra) with ConfidenceMedium, got: %v", ruleIDs(findings))
	}

	// Inter-procedural finding should have ConfidenceHigh
	hasIPHigh := false
	for _, f := range findings {
		if f.RuleID == "TP-PY001-IP" && f.Confidence == analysis.ConfidenceHigh {
			hasIPHigh = true
			break
		}
	}
	if !hasIPHigh {
		t.Errorf("expected TP-PY001-IP (inter) with ConfidenceHigh, got: %v", ruleIDs(findings))
	}
}

// TestCallGraphConstruction tests that the call graph is correctly built
// from a Python file with multiple functions.
func TestCallGraphConstruction(t *testing.T) {
	code := `def helper(x):
    return x + 1

def caller(y):
    return helper(y)

def main():
    return caller(42)
`
	dir := t.TempDir()
	path := filepath.Join(dir, "test.py")
	if err := os.WriteFile(path, []byte(code), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	src, _ := os.ReadFile(path)
	entry := grammars.DetectLanguage(path)
	if entry == nil {
		t.Fatal("failed to detect language")
	}

	parser := gotreesitter.NewParser(entry.Language())
	if parser == nil {
		t.Fatal("failed to create parser")
	}
	tree, err := parser.Parse(src)
	if err != nil || tree == nil {
		t.Fatalf("parse failed: %v", err)
	}
	defer tree.Release()

	bt := gotreesitter.Bind(tree)
	rootNode := bt.RootNode()

	cg := BuildCallGraph(rootNode, bt, "python", src)

	// Should have 3 functions
	if len(cg.Functions) != 3 {
		t.Errorf("expected 3 functions, got %d: %v", len(cg.Functions), funcNames(cg))
	}

	// main should call caller
	callees := cg.GetCallees("main")
	if !containsCallee(callees, "caller") {
		t.Errorf("expected main to call caller, got: %v", calleeNames(callees))
	}

	// caller should call helper
	callees = cg.GetCallees("caller")
	if !containsCallee(callees, "helper") {
		t.Errorf("expected caller to call helper, got: %v", calleeNames(callees))
	}

	// helper should have 1 parameter
	helperFn := cg.GetFunction("helper")
	if helperFn == nil {
		t.Fatal("expected helper function in call graph")
	}
	if len(helperFn.Params) != 1 || helperFn.Params[0] != "x" {
		t.Errorf("expected helper to have param 'x', got: %v", helperFn.Params)
	}
}

// --- Call graph test helpers ---

func funcNames(cg *CallGraph) []string {
	var names []string
	for name := range cg.Functions {
		names = append(names, name)
	}
	return names
}

func calleeNames(edges []CallEdge) []string {
	var names []string
	for _, e := range edges {
		names = append(names, e.Callee)
	}
	return names
}

func containsCallee(edges []CallEdge, name string) bool {
	for _, e := range edges {
		if e.Callee == name {
			return true
		}
	}
	return false
}
