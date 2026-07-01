// Package fixsnippet provides language-specific fix code snippets for
// vulnerability rules. Unlike the fix engine (which generates actual patches),
// these are display-only snippets shown in `patchflow explain` and in
// `--suggest-fixes` report output to guide developers.
package fixsnippet

import (
	"fmt"
	"strings"
)

// FixSnippet is a code snippet that shows the secure alternative for a rule.
type FixSnippet struct {
	RuleID    string // e.g., "TP-PY001"
	Language  string // e.g., "python"
	Title     string // short description
	Vulnerable string // vulnerable code pattern
	Fixed      string // fixed code pattern
	Explanation string // why the fix works
}

// database maps rule IDs to fix snippets.
var database = map[string]FixSnippet{
	// === Python taint patterns ===
	"TP-PY001": {
		RuleID:   "TP-PY001",
		Language: "python",
		Title:    "Use parameterized queries instead of string formatting",
		Vulnerable: `# VULNERABLE: string formatting in SQL
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
# or
cursor.execute("SELECT * FROM users WHERE id = " + user_id)`,
		Fixed: `# FIXED: parameterized query
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
# SQLAlchemy
session.query(User).filter(User.id == user_id).first()`,
		Explanation: "Parameterized queries separate SQL code from data. The database driver escapes the parameter automatically, making SQL injection impossible.",
	},
	"TP-PY002": {
		RuleID:   "TP-PY002",
		Language: "python",
		Title:    "Use subprocess with shell=False and argument lists",
		Vulnerable: `# VULNERABLE: shell=True with user input
subprocess.run(f"ls {user_input}", shell=True)
# or
os.system("ls " + user_input)`,
		Fixed: `# FIXED: argument list, no shell
subprocess.run(["ls", user_input], shell=False)
# or with shlex for complex cases
import shlex
subprocess.run(shlex.split(f"ls {user_input}"), shell=False)`,
		Explanation: "Passing arguments as a list with shell=False prevents the shell from interpreting metacharacters like ; | & $() in user input.",
	},
	"TP-PY003": {
		RuleID:   "TP-PY003",
		Language: "python",
		Title:    "Validate file paths against a base directory",
		Vulnerable: `# VULNERABLE: user-controlled path
with open(user_path) as f:
    data = f.read()`,
		Fixed: `# FIXED: resolve and validate against base
import os
base = os.path.abspath("/app/data")
real_path = os.path.abspath(os.path.join(base, user_path))
if not real_path.startswith(base + os.sep):
    raise ValueError("Path traversal detected")
with open(real_path) as f:
    data = f.read()`,
		Explanation: "Resolving the path with os.path.abspath() and checking it starts with the base directory prevents ../ traversal attacks.",
	},
	"TP-PY004": {
		RuleID:   "TP-PY004",
		Language: "python",
		Title:    "Validate URLs against an allowlist of hosts",
		Vulnerable: `# VULNERABLE: arbitrary URL from user input
import requests
resp = requests.get(user_url)`,
		Fixed: `# FIXED: validate host against allowlist
from urllib.parse import urlparse
allowed_hosts = {"api.example.com", "cdn.example.com"}
parsed = urlparse(user_url)
if parsed.hostname not in allowed_hosts:
    raise ValueError(f"Host {parsed.hostname} not allowed")
resp = requests.get(user_url)`,
		Explanation: "Validating the URL hostname against an allowlist prevents SSRF attacks targeting internal services (e.g., 169.254.169.254).",
	},
	"TP-PY005": {
		RuleID:   "TP-PY005",
		Language: "python",
		Title:    "Avoid eval()/exec() with untrusted input",
		Vulnerable: `# VULNERABLE: eval with user input
result = eval(user_input)
# or
exec(user_code)`,
		Fixed: `# FIXED: use ast.literal_eval for literals
import ast
result = ast.literal_eval(user_input)  # only parses dicts, lists, numbers, strings
# or use a proper parser for structured data
import json
result = json.loads(user_input)`,
		Explanation: "ast.literal_eval() only evaluates Python literal expressions (strings, numbers, tuples, lists, dicts, booleans, None) — it cannot execute arbitrary code.",
	},
	"TP-PY006": {
		RuleID:   "TP-PY006",
		Language: "python",
		Title:    "Enable auto-escaping in templates",
		Vulnerable: `# VULNERABLE: unescaped output in Jinja2
{{ user_input | safe }}
# or in manual string building
return f"<div>{user_input}</div>"`,
		Fixed: `# FIXED: let Jinja2 auto-escape
{{ user_input }}  # auto-escaped when autoescape=True
# or explicitly escape
from markupsafe import escape
return f"<div>{escape(user_input)}</div>"`,
		Explanation: "Auto-escaping converts <, >, &, \" to HTML entities, preventing the browser from interpreting user input as executable script tags.",
	},
	// === JS/TS taint patterns ===
	"TP-JS001": {
		RuleID:   "TP-JS001",
		Language: "javascript",
		Title:    "Use parameterized queries with placeholder syntax",
		Vulnerable: `// VULNERABLE: string concatenation in SQL
db.query("SELECT * FROM users WHERE id = " + userId);`,
		Fixed: `// FIXED: parameterized query (pg)
db.query("SELECT * FROM users WHERE id = $1", [userId]);
// MySQL
db.query("SELECT * FROM users WHERE id = ?", [userId]);
// Sequelize
User.findAll({ where: { id: userId } });`,
		Explanation: "Parameterized queries use placeholders ($1, ?) that the database driver binds safely, preventing SQL injection.",
	},
	"TP-JS002": {
		RuleID:   "TP-JS002",
		Language: "javascript",
		Title:    "Use execFile with argument arrays instead of exec",
		Vulnerable: `// VULNERABLE: exec with shell string
const { exec } = require('child_process');
exec("ls " + userInput, (err, stdout) => { ... });`,
		Fixed: `// FIXED: execFile with argument list (no shell)
const { execFile } = require('child_process');
execFile('ls', [userInput], (err, stdout) => { ... });`,
		Explanation: "execFile() does not invoke a shell, so metacharacters like ; | & $() in user input are treated as literal characters, not shell operators.",
	},
	"TP-JS003": {
		RuleID:   "TP-JS003",
		Language: "javascript",
		Title:    "Use proper output encoding for HTML",
		Vulnerable: `// VULNERABLE: string concatenation in HTML response
res.send('<div>' + userInput + '</div>');`,
		Fixed: `// FIXED: use a template engine with auto-escaping
res.render('page', { data: userInput });  // EJS/Pug auto-escape
// or manually escape
const escapeHtml = (s) => s.replace(/[&<>"']/g, c => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[c]));
res.send('<div>' + escapeHtml(userInput) + '</div>');`,
		Explanation: "HTML-encoding special characters prevents the browser from interpreting user input as script tags or HTML markup.",
	},
	"TP-JS004": {
		RuleID:   "TP-JS004",
		Language: "javascript",
		Title:    "Use path.resolve and validate against base directory",
		Vulnerable: `// VULNERABLE: user-controlled file path
const data = fs.readFileSync(userPath, 'utf8');`,
		Fixed: `// FIXED: resolve and validate
const path = require('path');
const base = path.resolve('/app/data');
const realPath = path.resolve(base, userPath);
if (!realPath.startsWith(base + path.sep)) {
  throw new Error('Path traversal detected');
}
const data = fs.readFileSync(realPath, 'utf8');`,
		Explanation: "path.resolve() normalizes the path, and the startsWith() check ensures it stays within the allowed base directory.",
	},
	"TP-JS005": {
		RuleID:   "TP-JS005",
		Language: "javascript",
		Title:    "Validate URLs against an allowlist of hosts",
		Vulnerable: `// VULNERABLE: arbitrary URL from user input
const resp = await axios.get(userUrl);`,
		Fixed: `// FIXED: validate host against allowlist
const url = new URL(userUrl);
const allowedHosts = ['api.example.com', 'cdn.example.com'];
if (!allowedHosts.includes(url.hostname)) {
  throw new Error("Host " + url.hostname + " not allowed");
}
const resp = await axios.get(userUrl);`,
		Explanation: "Parsing the URL and checking the hostname against an allowlist prevents SSRF attacks against internal services.",
	},
	"TP-JS006": {
		RuleID:   "TP-JS006",
		Language: "javascript",
		Title:    "Avoid eval() and new Function() with untrusted input",
		Vulnerable: `// VULNERABLE: eval with user input
const result = eval(userInput);
// or
const fn = new Function(userInput);`,
		Fixed: `// FIXED: use JSON.parse for data
const result = JSON.parse(userInput);
// or use a sandboxed evaluator like vm2 for code
const { VM } = require('vm2');
const vm = new VM({ sandbox: {} });
const result = vm.run(userInput);`,
		Explanation: "JSON.parse() only parses data, not code. For untrusted code, use a sandboxed VM with restricted access to globals.",
	},
	"TP-JS007": {
		RuleID:   "TP-JS007",
		Language: "javascript",
		Title:    "Validate redirect URLs against an allowlist",
		Vulnerable: `// VULNERABLE: open redirect
res.redirect(req.query.returnUrl);`,
		Fixed: `// FIXED: only allow relative paths or known hosts
const returnUrl = req.query.returnUrl;
if (returnUrl && returnUrl.startsWith('/') && !returnUrl.startsWith('//')) {
  res.redirect(returnUrl);
} else {
  res.redirect('/');
}`,
		Explanation: "Checking that the redirect URL starts with a single / (not //, which is a protocol-relative URL) prevents redirects to external domains.",
	},
	// === Ruby taint patterns ===
	"TP-RB001": {
		RuleID:   "TP-RB001",
		Language: "ruby",
		Title:    "Use parameterized queries in ActiveRecord",
		Vulnerable: `# VULNERABLE: string interpolation in SQL
User.where("name = '#{params[:name]}'")`,
		Fixed: `# FIXED: parameterized query
User.where(name: params[:name])
# or
User.where("name = ?", params[:name])`,
		Explanation: "ActiveRecord parameterized queries automatically escape user input, preventing SQL injection.",
	},
	// === PHP taint patterns ===
	"TP-PHP001": {
		RuleID:   "TP-PHP001",
		Language: "php",
		Title:    "Use PDO prepared statements",
		Vulnerable: `// VULNERABLE: string concatenation in SQL
$sql = "SELECT * FROM users WHERE id = " . $_GET['id'];
$db->query($sql);`,
		Fixed: `// FIXED: PDO prepared statement
$stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);
$result = $stmt->fetch();`,
		Explanation: "PDO prepared statements separate SQL code from data. The database engine handles escaping, making SQL injection impossible.",
	},
	// === Java taint patterns ===
	"TP-JAVA001": {
		RuleID:   "TP-JAVA001",
		Language: "java",
		Title:    "Use PreparedStatement with parameterized queries",
		Vulnerable: `// VULNERABLE: string concatenation in SQL
String sql = "SELECT * FROM users WHERE id = " + request.getParameter("id");
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(sql);`,
		Fixed: `// FIXED: PreparedStatement with placeholders
String sql = "SELECT * FROM users WHERE id = ?";
PreparedStatement stmt = conn.prepareStatement(sql);
stmt.setString(1, request.getParameter("id"));
ResultSet rs = stmt.executeQuery();`,
		Explanation: "PreparedStatement uses ? placeholders that are bound safely by the JDBC driver, preventing SQL injection.",
	},
	"TP-JAVA002": {
		RuleID:   "TP-JAVA002",
		Language: "java",
		Title:    "Use ProcessBuilder with argument lists",
		Vulnerable: `// VULNERABLE: Runtime.exec with shell string
Runtime.getRuntime().exec("ls " + userInput);`,
		Fixed: `// FIXED: ProcessBuilder with argument list
ProcessBuilder pb = new ProcessBuilder("ls", userInput);
Process p = pb.start();`,
		Explanation: "ProcessBuilder takes arguments as a list, not a shell string. Metacharacters in user input are treated as literal characters.",
	},
	// === C# taint patterns ===
	"TP-CS001": {
		RuleID:   "TP-CS001",
		Language: "csharp",
		Title:    "Use parameterized queries with SqlCommand",
		Vulnerable: `// VULNERABLE: string concatenation in SQL
string sql = "SELECT * FROM users WHERE id = " + userId;
var cmd = new SqlCommand(sql, conn);`,
		Fixed: `// FIXED: parameterized query
string sql = "SELECT * FROM users WHERE id = @id";
var cmd = new SqlCommand(sql, conn);
cmd.Parameters.AddWithValue("@id", userId);`,
		Explanation: "SqlCommand parameters are typed and escaped by the .NET SQL provider, preventing SQL injection.",
	},
	// === Embedded pattern rules ===
	"PY013": {
		RuleID:   "PY013",
		Language: "python",
		Title:    "Enable SSL certificate verification",
		Vulnerable: `# VULNERABLE: SSL verification disabled
requests.get(url, verify=False)`,
		Fixed: `# FIXED: enable verification (default)
requests.get(url, verify=True)
# or remove the verify parameter entirely
requests.get(url)`,
		Explanation: "verify=True (the default) ensures the server's SSL certificate is validated against trusted CAs, preventing man-in-the-middle attacks.",
	},
	"PY005": {
		RuleID:   "PY005",
		Language: "python",
		Title:    "Use parameterized queries with cursor.execute",
		Vulnerable: `# VULNERABLE: string formatting in SQL
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`,
		Fixed: `# FIXED: parameterized query
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))`,
		Explanation: "The ? placeholder is bound safely by the database driver, which escapes special characters automatically.",
	},
	"PY011": {
		RuleID:   "PY011",
		Language: "python",
		Title:    "Use yaml.safe_load instead of yaml.load",
		Vulnerable: `# VULNERABLE: yaml.load can execute arbitrary Python
import yaml
data = yaml.load(user_input)`,
		Fixed: `# FIXED: safe_load only parses YAML, not Python objects
import yaml
data = yaml.safe_load(user_input)`,
		Explanation: "yaml.safe_load() only constructs basic Python types (dict, list, str, int, float, bool, None). yaml.load() can construct arbitrary Python objects, enabling code execution.",
	},
}

// Lookup returns a fix snippet for a given rule ID.
func Lookup(ruleID string) (FixSnippet, bool) {
	snippet, ok := database[ruleID]
	return snippet, ok
}

// ForRule returns the fix snippet for a rule ID, or an empty FixSnippet if not found.
func ForRule(ruleID string) *FixSnippet {
	if s, ok := database[ruleID]; ok {
		return &s
	}
	return nil
}

// FormatMarkdown returns the fix snippet formatted as markdown.
func (s FixSnippet) FormatMarkdown() string {
	var sb strings.Builder
	sb.WriteString("#### Fix Suggestion\n\n")
	sb.WriteString(fmt.Sprintf("**%s**\n\n", s.Title))
	sb.WriteString("Vulnerable code:\n")
	sb.WriteString(fmt.Sprintf("```%s\n%s\n```\n\n", s.Language, s.Vulnerable))
	sb.WriteString("Fixed code:\n")
	sb.WriteString(fmt.Sprintf("```%s\n%s\n```\n\n", s.Language, s.Fixed))
	sb.WriteString(fmt.Sprintf("**Why:** %s\n", s.Explanation))
	return sb.String()
}

// FormatTerminal returns the fix snippet formatted for terminal output.
func (s FixSnippet) FormatTerminal() string {
	var sb strings.Builder
	sb.WriteString(s.Title + "\n")
	sb.WriteString("  Vulnerable:\n")
	for _, line := range strings.Split(s.Vulnerable, "\n") {
		sb.WriteString("    " + line + "\n")
	}
	sb.WriteString("  Fixed:\n")
	for _, line := range strings.Split(s.Fixed, "\n") {
		sb.WriteString("    " + line + "\n")
	}
	sb.WriteString("  Why: " + s.Explanation + "\n")
	return sb.String()
}
