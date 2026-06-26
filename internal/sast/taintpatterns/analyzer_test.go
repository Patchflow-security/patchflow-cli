package taintpatterns

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/patchflow/patchflow-cli/internal/analysis"
)

func TestPythonSQLInjection(t *testing.T) {
	code := `import flask
from flask import request
import sqlite3

@app.route("/users")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return str(cursor.fetchall())
`
	findings := scanPythonCode(t, code)
	if !hasRule(findings, "TP-PY001") {
		t.Errorf("expected TP-PY001 (SQL injection) finding, got: %v", ruleIDs(findings))
	}
}

func TestPythonCommandInjection(t *testing.T) {
	code := `import os
from flask import request

@app.route("/run")
def run_cmd():
    cmd = request.args.get("cmd")
    os.system("ls " + cmd)
`
	findings := scanPythonCode(t, code)
	if !hasRule(findings, "TP-PY002") {
		t.Errorf("expected TP-PY002 (command injection) finding, got: %v", ruleIDs(findings))
	}
}

func TestPythonPathTraversal(t *testing.T) {
	code := `from flask import request

@app.route("/file")
def get_file():
    filename = request.args.get("file")
    f = open("/tmp/" + filename)
    return f.read()
`
	findings := scanPythonCode(t, code)
	if !hasRule(findings, "TP-PY003") {
		t.Errorf("expected TP-PY003 (path traversal) finding, got: %v", ruleIDs(findings))
	}
}

func TestPythonCodeInjection(t *testing.T) {
	code := `from flask import request

@app.route("/eval")
def eval_expr():
    expr = request.args.get("expr")
    result = eval(expr)
    return str(result)
`
	findings := scanPythonCode(t, code)
	if !hasRule(findings, "TP-PY005") {
		t.Errorf("expected TP-PY005 (code injection) finding, got: %v", ruleIDs(findings))
	}
}

func TestPythonNoFalsePositive(t *testing.T) {
	// Parameterized query should NOT trigger
	code := `from flask import request
import sqlite3

@app.route("/users")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return str(cursor.fetchall())
`
	findings := scanPythonCode(t, code)
	if hasRule(findings, "TP-PY001") {
		t.Errorf("parameterized query should not trigger TP-PY001, got: %v", ruleIDs(findings))
	}
}

func TestJSSQLInjection(t *testing.T) {
	code := `app.get("/users", (req, res) => {
    const userId = req.query.id;
    db.query("SELECT * FROM users WHERE id = " + userId);
});
`
	findings := scanJSCode(t, code)
	if !hasRule(findings, "TP-JS001") {
		t.Errorf("expected TP-JS001 (SQL injection) finding, got: %v", ruleIDs(findings))
	}
}

func TestJSCommandInjection(t *testing.T) {
	code := `const { exec } = require("child_process");
app.get("/run", (req, res) => {
    const cmd = req.query.cmd;
    exec("ls " + cmd);
});
`
	findings := scanJSCode(t, code)
	if !hasRule(findings, "TP-JS002") {
		t.Errorf("expected TP-JS002 (command injection) finding, got: %v", ruleIDs(findings))
	}
}

func TestJSXSS(t *testing.T) {
	code := `app.get("/hello", (req, res) => {
    const name = req.query.name;
    res.send("<h1>Hello " + name + "</h1>");
});
`
	findings := scanJSCode(t, code)
	if !hasRule(findings, "TP-JS003") {
		t.Errorf("expected TP-JS003 (XSS) finding, got: %v", ruleIDs(findings))
	}
}

func TestJSPathTraversal(t *testing.T) {
	code := `const fs = require("fs");
app.get("/file", (req, res) => {
    const filename = req.query.file;
    const content = fs.readFileSync("/tmp/" + filename);
    res.send(content);
});
`
	findings := scanJSCode(t, code)
	if !hasRule(findings, "TP-JS004") {
		t.Errorf("expected TP-JS004 (path traversal) finding, got: %v", ruleIDs(findings))
	}
}

func TestJSCodeInjection(t *testing.T) {
	code := `app.get("/eval", (req, res) => {
    const expr = req.query.expr;
    const result = eval(expr);
    res.send(String(result));
});
`
	findings := scanJSCode(t, code)
	if !hasRule(findings, "TP-JS006") {
		t.Errorf("expected TP-JS006 (code injection) finding, got: %v", ruleIDs(findings))
	}
}

func TestJSOpenRedirect(t *testing.T) {
	code := `app.get("/redirect", (req, res) => {
    const url = req.query.url;
    res.redirect(url);
});
`
	findings := scanJSCode(t, code)
	if !hasRule(findings, "TP-JS007") {
		t.Errorf("expected TP-JS007 (open redirect) finding, got: %v", ruleIDs(findings))
	}
}

func TestJSNoFalsePositive(t *testing.T) {
	// Parameterized query should NOT trigger
	code := `app.get("/users", (req, res) => {
    const userId = req.query.id;
    db.query("SELECT * FROM users WHERE id = $1", [userId]);
});
`
	findings := scanJSCode(t, code)
	if hasRule(findings, "TP-JS001") {
		t.Errorf("parameterized query should not trigger TP-JS001, got: %v", ruleIDs(findings))
	}
}

func TestRulesCount(t *testing.T) {
	a := NewAnalyzer()
	rules := a.Rules()
	if len(rules) != 13 {
		t.Errorf("expected 13 taint pattern rules, got %d", len(rules))
	}
}

// --- Helpers ---

func scanPythonCode(t *testing.T, code string) []analysis.Finding {
	t.Helper()
	return scanCode(t, "test.py", code)
}

func scanJSCode(t *testing.T, code string) []analysis.Finding {
	t.Helper()
	return scanCode(t, "test.js", code)
}

func scanCode(t *testing.T, filename, code string) []analysis.Finding {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, []byte(code), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	return findings
}

func hasRule(findings []analysis.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

func ruleIDs(findings []analysis.Finding) []string {
	var ids []string
	for _, f := range findings {
		ids = append(ids, f.RuleID)
	}
	return ids
}
