package taintpatterns

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
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

// === Ruby taint tests ===

func TestRubySQLInjection(t *testing.T) {
	code := `class UsersController < ApplicationController
  def show
    user_id = params[:id]
    User.where("id = " + user_id)
  end
end
`
	findings := scanRubyCode(t, code)
	if !hasRule(findings, "TP-RB001") {
		t.Errorf("expected TP-RB001 (SQL injection) finding, got: %v", ruleIDs(findings))
	}
}

func TestRubyCommandInjection(t *testing.T) {
	code := `class CmdController < ApplicationController
  def run
    cmd = params[:cmd]
    system("ls " + cmd)
  end
end
`
	findings := scanRubyCode(t, code)
	if !hasRule(findings, "TP-RB002") {
		t.Errorf("expected TP-RB002 (command injection) finding, got: %v", ruleIDs(findings))
	}
}

func TestRubyPathTraversal(t *testing.T) {
	code := `class FileController < ApplicationController
  def read
    filename = params[:file]
    File.open("/tmp/" + filename)
  end
end
`
	findings := scanRubyCode(t, code)
	if !hasRule(findings, "TP-RB003") {
		t.Errorf("expected TP-RB003 (path traversal) finding, got: %v", ruleIDs(findings))
	}
}

func TestRubyOpenRedirect(t *testing.T) {
	code := `class RedirectController < ApplicationController
  def redirect
    url = params[:url]
    redirect_to url
  end
end
`
	findings := scanRubyCode(t, code)
	if !hasRule(findings, "TP-RB008") {
		t.Errorf("expected TP-RB008 (open redirect) finding, got: %v", ruleIDs(findings))
	}
}

func TestRubyNoFalsePositive(t *testing.T) {
	// Hardcoded value should NOT trigger
	code := `class UsersController < ApplicationController
  def show
    User.where("id = 1")
  end
end
`
	findings := scanRubyCode(t, code)
	if hasRule(findings, "TP-RB001") {
		t.Errorf("hardcoded query should not trigger TP-RB001, got: %v", ruleIDs(findings))
	}
}

// === PHP taint tests ===

func TestPHPSQLInjection(t *testing.T) {
	code := `<?php
function get_user() {
    $id = $_GET["id"];
    mysql_query("SELECT * FROM users WHERE id = " . $id);
}
?>
`
	findings := scanPHPCode(t, code)
	if !hasRule(findings, "TP-PHP001") {
		t.Errorf("expected TP-PHP001 (SQL injection) finding, got: %v", ruleIDs(findings))
	}
}

func TestPHPCommandInjection(t *testing.T) {
	code := `<?php
function run_cmd() {
    $cmd = $_GET["cmd"];
    system("ls " . $cmd);
}
?>
`
	findings := scanPHPCode(t, code)
	if !hasRule(findings, "TP-PHP002") {
		t.Errorf("expected TP-PHP002 (command injection) finding, got: %v", ruleIDs(findings))
	}
}

func TestPHPPathTraversal(t *testing.T) {
	code := `<?php
function get_file() {
    $filename = $_GET["file"];
    fopen("/tmp/" . $filename, "r");
}
?>
`
	findings := scanPHPCode(t, code)
	if !hasRule(findings, "TP-PHP004") {
		t.Errorf("expected TP-PHP004 (path traversal) finding, got: %v", ruleIDs(findings))
	}
}

func TestPHPDeserialization(t *testing.T) {
	code := `<?php
function process() {
    $data = $_COOKIE["data"];
    unserialize($data);
}
?>
`
	findings := scanPHPCode(t, code)
	if !hasRule(findings, "TP-PHP006") {
		t.Errorf("expected TP-PHP006 (deserialization) finding, got: %v", ruleIDs(findings))
	}
}

func TestPHPNoFalsePositive(t *testing.T) {
	// Hardcoded value should NOT trigger
	code := `<?php
function get_user() {
    mysql_query("SELECT * FROM users WHERE id = 1");
}
?>
`
	findings := scanPHPCode(t, code)
	if hasRule(findings, "TP-PHP001") {
		t.Errorf("hardcoded query should not trigger TP-PHP001, got: %v", ruleIDs(findings))
	}
}

// === Java taint tests ===

func TestJavaSQLInjection(t *testing.T) {
	code := `import java.sql.*;
import javax.servlet.http.*;

public class UserController extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String userId = request.getParameter("id");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
    }
}
`
	findings := scanJavaCode(t, code)
	if !hasRule(findings, "TP-JAVA001") {
		t.Errorf("expected TP-JAVA001 (SQL injection) finding, got: %v", ruleIDs(findings))
	}
}

func TestJavaCommandInjection(t *testing.T) {
	code := `import javax.servlet.http.*;

public class CmdController extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String cmd = request.getParameter("cmd");
        Runtime.getRuntime().exec("ls " + cmd);
    }
}
`
	findings := scanJavaCode(t, code)
	if !hasRule(findings, "TP-JAVA002") {
		t.Errorf("expected TP-JAVA002 (command injection) finding, got: %v", ruleIDs(findings))
	}
}

func TestJavaPathTraversal(t *testing.T) {
	code := `import javax.servlet.http.*;
import java.io.*;

public class FileController extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String filename = request.getParameter("file");
        FileInputStream fis = new FileInputStream("/tmp/" + filename);
    }
}
`
	findings := scanJavaCode(t, code)
	if !hasRule(findings, "TP-JAVA003") {
		t.Errorf("expected TP-JAVA003 (path traversal) finding, got: %v", ruleIDs(findings))
	}
}

func TestJavaOpenRedirect(t *testing.T) {
	code := `import javax.servlet.http.*;

public class RedirectController extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String url = request.getParameter("url");
        response.sendRedirect(url);
    }
}
`
	findings := scanJavaCode(t, code)
	if !hasRule(findings, "TP-JAVA008") {
		t.Errorf("expected TP-JAVA008 (open redirect) finding, got: %v", ruleIDs(findings))
	}
}

func TestJavaNoFalsePositive(t *testing.T) {
	// Hardcoded value should NOT trigger
	code := `import java.sql.*;

public class UserController {
    public void getUser() {
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE id = 1");
    }
}
`
	findings := scanJavaCode(t, code)
	if hasRule(findings, "TP-JAVA001") {
		t.Errorf("hardcoded query should not trigger TP-JAVA001, got: %v", ruleIDs(findings))
	}
}

// === C# taint tests ===

func TestCSharpSQLInjection(t *testing.T) {
	code := `using System;
using System.Data.SqlClient;
using System.Web;

public class UserController : System.Web.UI.Page {
    public void PageLoad() {
        string userId = Request.QueryString["id"];
        SqlCommand cmd = new SqlCommand("SELECT * FROM users WHERE id = " + userId);
    }
}
`
	findings := scanCSharpCode(t, code)
	if !hasRule(findings, "TP-CS001") {
		t.Errorf("expected TP-CS001 (SQL injection) finding, got: %v", ruleIDs(findings))
	}
}

func TestCSharpPathTraversal(t *testing.T) {
	code := `using System;
using System.IO;
using System.Web;

public class FileController : System.Web.UI.Page {
    public void PageLoad() {
        string filename = Request.QueryString["file"];
        string content = File.ReadAllText("/tmp/" + filename);
    }
}
`
	findings := scanCSharpCode(t, code)
	if !hasRule(findings, "TP-CS003") {
		t.Errorf("expected TP-CS003 (path traversal) finding, got: %v", ruleIDs(findings))
	}
}

func TestCSharpOpenRedirect(t *testing.T) {
	code := `using System;
using System.Web;

public class RedirectController : System.Web.UI.Page {
    public void PageLoad() {
        string url = Request.QueryString["url"];
        Response.Redirect(url);
    }
}
`
	findings := scanCSharpCode(t, code)
	if !hasRule(findings, "TP-CS007") {
		t.Errorf("expected TP-CS007 (open redirect) finding, got: %v", ruleIDs(findings))
	}
}

func TestCSharpNoFalsePositive(t *testing.T) {
	// Hardcoded value should NOT trigger
	code := `using System;
using System.Data.SqlClient;

public class UserController {
    public void getUser() {
        SqlCommand cmd = new SqlCommand("SELECT * FROM users WHERE id = 1");
        cmd.ExecuteNonQuery();
    }
}
`
	findings := scanCSharpCode(t, code)
	if hasRule(findings, "TP-CS001") {
		t.Errorf("hardcoded query should not trigger TP-CS001, got: %v", ruleIDs(findings))
	}
}

func TestRulesCount(t *testing.T) {
	a := NewAnalyzer()
	rules := a.Rules()
	if len(rules) != 47 {
		t.Errorf("expected 47 taint pattern rules, got %d", len(rules))
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

func scanRubyCode(t *testing.T, code string) []analysis.Finding {
	t.Helper()
	return scanCode(t, "test.rb", code)
}

func scanPHPCode(t *testing.T, code string) []analysis.Finding {
	t.Helper()
	return scanCode(t, "test.php", code)
}

func scanJavaCode(t *testing.T, code string) []analysis.Finding {
	t.Helper()
	return scanCode(t, "Test.java", code)
}

func scanCSharpCode(t *testing.T, code string) []analysis.Finding {
	t.Helper()
	return scanCode(t, "Test.cs", code)
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
