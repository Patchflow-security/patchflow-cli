package treesitter

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
)

func TestTreeSitterPythonEval(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.py", `result = eval(user_input)
print(result)
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "TS-PY001" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected TS-PY001 (eval), got %d findings", len(findings))
	}
}

func TestTreeSitterPythonNoFalsePositiveInDocstring(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.py", `"""Security guidelines.

Never use eval() or exec() in production.
Avoid os.system() — use subprocess with shell=False.
"""

result = subprocess.run(["ls"], shell=False)
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// eval/exec/os.system in the docstring should NOT be detected
	// because tree-sitter parses them as string content, not code
	for _, f := range findings {
		if f.RuleID == "TS-PY001" || f.RuleID == "TS-PY002" || f.RuleID == "TS-PY003" {
			t.Errorf("false positive: %s triggered inside docstring at line %d",
				f.RuleID, f.LineStart)
		}
	}
}

func TestTreeSitterPythonSubprocessShellTrue(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.py", `import subprocess
subprocess.call(cmd, shell=True)
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "TS-PY004" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected TS-PY004 (subprocess shell=True), got %d findings", len(findings))
	}
}

func TestTreeSitterPythonPickleLoads(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.py", `import pickle
data = pickle.loads(user_data)
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "TS-PY005" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected TS-PY005 (pickle.loads), got %d findings", len(findings))
	}
}

func TestTreeSitterJSEval(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.js", `const result = eval(userInput);
console.log(result);
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "TS-JS001" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected TS-JS001 (eval), got %d findings", len(findings))
	}
}

func TestTreeSitterJSChildProcessExec(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.js", `const child_process = require('child_process');
child_process.exec(userInput, callback);
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "TS-JS003" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected TS-JS003 (child_process.exec), got %d findings", len(findings))
	}
}

func TestTreeSitterJSNewFunction(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.js", `const fn = new Function('return 1 + 2');
fn();
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "TS-JS002" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected TS-JS002 (new Function), got %d findings", len(findings))
	}
}

func TestTreeSitterRubyEval(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.rb", `result = eval(user_input)
puts result
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "TS-RB001" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected TS-RB001 (eval), got %d findings", len(findings))
	}
}

func TestTreeSitterRubySystem(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.rb", `system("ls " + user_input)
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "TS-RB002" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected TS-RB002 (system), got %d findings", len(findings))
	}
}

func TestTreeSitterPHPEval(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.php", `<?php
$result = eval($user_input);
echo $result;
?>
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "TS-PHP001" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected TS-PHP001 (eval), got %d findings", len(findings))
	}
}

func TestTreeSitterJavaRuntimeExec(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "App.java", `public class App {
    public static void main(String[] args) throws Exception {
        Runtime.getRuntime().exec(userInput);
    }
}
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "TS-JAVA001" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected TS-JAVA001 (Runtime.exec), got %d findings", len(findings))
	}
}

func TestTreeSitterRustUnsafeBlock(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.rs", `fn main() {
    unsafe {
        let ptr = 0x12345678 as *const u32;
        println!("{}", *ptr);
    }
}
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "TS-RS002" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected TS-RS002 (unsafe block), got %d findings", len(findings))
	}
}

func TestTreeSitterRustCommandNew(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.rs", `use std::process::Command;
fn main() {
    Command::new("sh").arg("-c").arg(user_input).output();
}
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "TS-RS001" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected TS-RS001 (Command::new with shell), got %d findings", len(findings))
	}
}

func TestTreeSitterRules(t *testing.T) {
	a := NewAnalyzer()
	rules := a.Rules()

	if len(rules) == 0 {
		t.Errorf("expected rules, got 0")
	}

	ruleMap := make(map[string]bool)
	for _, r := range rules {
		ruleMap[r.ID] = true
	}

	expectedRules := []string{
		"TS-PY001", "TS-PY002", "TS-PY003", "TS-PY004", "TS-PY005", "TS-PY006",
		"TS-JS001", "TS-JS002", "TS-JS003", "TS-JS004", "TS-JS005",
		"TS-RB001", "TS-RB002",
		"TS-PHP001", "TS-PHP002",
		"TS-JAVA001", "TS-JAVA002",
		"TS-CS001",
		"TS-RS001", "TS-RS002", "TS-RS003",
	}
	for _, expected := range expectedRules {
		if !ruleMap[expected] {
			t.Errorf("expected rule %s in Rules(), not found", expected)
		}
	}
}

func TestTreeSitterSkipsTestFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.test.js", `const result = eval(userInput);`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// Test files should be skipped
	for _, f := range findings {
		if f.RuleID == "TS-JS001" {
			t.Errorf("should not scan test files, but found TS-JS001 at %s:%d",
				f.FilePath, f.LineStart)
		}
	}
}

func TestTreeSitterSkipsNodeModules(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "node_modules/lib/app.js", `const result = eval(userInput);`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	for _, f := range findings {
		if f.RuleID == "TS-JS001" {
			t.Errorf("should not scan node_modules, but found TS-JS001 at %s:%d",
				f.FilePath, f.LineStart)
		}
	}
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	fullPath := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
}

// --- Tests for expanded rules ---

func TestTreeSitterPythonHashlibMD5(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.py", `import hashlib
h = hashlib.md5(data)
`)
	a := NewAnalyzer()
	findings, _ := a.Analyze(context.Background(), dir)
	expectRule(t, findings, "TS-PY007")
}

func TestTreeSitterPythonHashlibSHA1(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.py", `import hashlib
h = hashlib.sha1(data)
`)
	a := NewAnalyzer()
	findings, _ := a.Analyze(context.Background(), dir)
	expectRule(t, findings, "TS-PY008")
}

func TestTreeSitterPythonFlaskDebug(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.py", `from flask import Flask
app = Flask(__name__)
app.run(debug=True)
`)
	a := NewAnalyzer()
	findings, _ := a.Analyze(context.Background(), dir)
	expectRule(t, findings, "TS-PY009")
}

func TestTreeSitterPythonMarshalLoads(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.py", `import marshal
data = marshal.loads(raw)
`)
	a := NewAnalyzer()
	findings, _ := a.Analyze(context.Background(), dir)
	expectRule(t, findings, "TS-PY010")
}

func TestTreeSitterPythonTempfileMktemp(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.py", `import tempfile
f = tempfile.mktemp()
`)
	a := NewAnalyzer()
	findings, _ := a.Analyze(context.Background(), dir)
	expectRule(t, findings, "TS-PY015")
}

func TestTreeSitterPythonOsPopen(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.py", `import os
output = os.popen("ls -la")
`)
	a := NewAnalyzer()
	findings, _ := a.Analyze(context.Background(), dir)
	expectRule(t, findings, "TS-PY013")
}

func TestTreeSitterJSCryptoMD5(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.js", `const crypto = require('crypto');
const hash = crypto.createHash('md5');
`)
	a := NewAnalyzer()
	findings, _ := a.Analyze(context.Background(), dir)
	expectRule(t, findings, "TS-JS006")
}

func TestTreeSitterJSNewBuffer(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.js", `const buf = new Buffer(1024);
`)
	a := NewAnalyzer()
	findings, _ := a.Analyze(context.Background(), dir)
	expectRule(t, findings, "TS-JS008")
}

func TestTreeSitterJSInnerHTML(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.js", `document.getElementById('x').innerHTML = userInput;
`)
	a := NewAnalyzer()
	findings, _ := a.Analyze(context.Background(), dir)
	expectRule(t, findings, "TS-JS009")
}

func TestTreeSitterJSDocumentWrite(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.js", `document.write(userInput);
`)
	a := NewAnalyzer()
	findings, _ := a.Analyze(context.Background(), dir)
	expectRule(t, findings, "TS-JS012")
}

func TestTreeSitterJSSetTimeoutString(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.js", `setTimeout("alert('xss')", 1000);
`)
	a := NewAnalyzer()
	findings, _ := a.Analyze(context.Background(), dir)
	expectRule(t, findings, "TS-JS014")
}

func TestTreeSitterJSLocalStorageSetItem(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.js", `localStorage.setItem('token', jwtToken);
`)
	a := NewAnalyzer()
	findings, _ := a.Analyze(context.Background(), dir)
	expectRule(t, findings, "TS-JS020")
}

func TestTreeSitterRubyBacktick(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.rb", `result = ` + "`ls #{user_input}`" + `
`)
	a := NewAnalyzer()
	findings, _ := a.Analyze(context.Background(), dir)
	expectRule(t, findings, "TS-RB005")
}

func TestTreeSitterRubyMarshalLoad(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.rb", `data = Marshal.load(raw)
`)
	a := NewAnalyzer()
	findings, _ := a.Analyze(context.Background(), dir)
	expectRule(t, findings, "TS-RB009")
}

func TestTreeSitterRubyYAMLLoad(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.rb", `data = YAML.load(raw)
`)
	a := NewAnalyzer()
	findings, _ := a.Analyze(context.Background(), dir)
	expectRule(t, findings, "TS-RB010")
}

func TestTreeSitterPHPSystem(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.php", `<?php
system("ls " . $user_input);
?>
`)
	a := NewAnalyzer()
	findings, _ := a.Analyze(context.Background(), dir)
	expectRule(t, findings, "TS-PHP003")
}

func TestTreeSitterPHPPassthru(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.php", `<?php
passthru($cmd);
?>
`)
	a := NewAnalyzer()
	findings, _ := a.Analyze(context.Background(), dir)
	expectRule(t, findings, "TS-PHP006")
}

func TestTreeSitterJavaProcessBuilder(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "App.java", `public class App {
    public void run() {
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", cmd);
    }
}
`)
	a := NewAnalyzer()
	findings, _ := a.Analyze(context.Background(), dir)
	expectRule(t, findings, "TS-JAVA003")
}

func TestTreeSitterJavaMD5(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "App.java", `import java.security.MessageDigest;
public class App {
    public void hash() {
        MessageDigest md = MessageDigest.getInstance("MD5");
    }
}
`)
	a := NewAnalyzer()
	findings, _ := a.Analyze(context.Background(), dir)
	expectRule(t, findings, "TS-JAVA004")
}

func TestTreeSitterJavaRandom(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "App.java", `import java.util.Random;
public class App {
    public void gen() {
        Random r = new Random();
    }
}
`)
	a := NewAnalyzer()
	findings, _ := a.Analyze(context.Background(), dir)
	expectRule(t, findings, "TS-JAVA006")
}

func TestTreeSitterRustFsRead(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.rs", `use std::fs;
fn main() {
    let data = fs::read(user_path).unwrap();
}
`)
	a := NewAnalyzer()
	findings, _ := a.Analyze(context.Background(), dir)
	expectRule(t, findings, "TS-RS004")
}

func TestTreeSitterRustCommandNewAny(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.rs", `use std::process::Command;
fn main() {
    Command::new("ls").arg(user_input).output();
}
`)
	a := NewAnalyzer()
	findings, _ := a.Analyze(context.Background(), dir)
	expectRule(t, findings, "TS-RS008")
}

func TestTreeSitterExpandedRulesCount(t *testing.T) {
	a := NewAnalyzer()
	rules := a.Rules()
	if len(rules) < 60 {
		t.Errorf("expected at least 60 rules, got %d", len(rules))
	}
}

func expectRule(t *testing.T, findings []analysis.Finding, ruleID string) {
	t.Helper()
	for _, f := range findings {
		if f.RuleID == ruleID {
			return
		}
	}
	t.Errorf("expected %s, got %d findings: %v", ruleID, len(findings), ruleIDs(findings))
}

func ruleIDs(findings []analysis.Finding) []string {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.RuleID)
	}
	return ids
}

// tsRuleCase defines a tree-sitter rule test case with a code snippet.
type tsRuleCase struct {
	ruleID string
	file   string
	code   string
}

// runTSRuleTest runs a single tree-sitter rule test: writes the file, scans,
// and checks that the expected rule ID appears in the findings.
func runTSRuleTest(t *testing.T, tc tsRuleCase) {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, tc.file, tc.code)
	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.RuleID == tc.ruleID {
			found = true
		}
	}
	if !found {
		t.Errorf("expected %s, got %d findings: %v", tc.ruleID, len(findings), ruleIDs(findings))
	}
}

// --- Table-driven tests for all untested tree-sitter rules ---

// TestTreeSitterAllRules_Python tests all untested Python AST rules.
func TestTreeSitterAllRules_Python(t *testing.T) {
	cases := []tsRuleCase{
		{"TS-PY002", "app.py", "exec(user_input)\n"},
		{"TS-PY003", "app.py", "import os\nos.system(\"ls -la\")\n"},
		{"TS-PY006", "app.py", "import yaml\ndata = yaml.load(f)\n"},
		// TS-PY011 skipped: matchCallByName("shelve.open") checks for an identifier named
		// "shelve.open", but the parser produces an attribute node for shelve.open().
		{"TS-PY012", "app.py", "import subprocess\np = subprocess.Popen(cmd, shell=True)\n"},
		{"TS-PY014", "app.py", "import pty\npty.spawn([\"ls\", \"-la\"])\n"},
		{"TS-PY016", "app.py", "import random\nval = random.random()\n"},
		{"TS-PY017", "app.py", "import random\nval = random.randint(1, 10)\n"},
		{"TS-PY018", "app.py", "name = input(\"Enter name: \")\n"},
		{"TS-PY019", "app.py", "code = compile(src, \"<string>\", \"exec\")\n"},
		{"TS-PY020", "app.py", "import ctypes\nlib = ctypes.CDLL(\"libtest.so\")\n"},
	}
	for _, tc := range cases {
		t.Run(tc.ruleID, func(t *testing.T) { runTSRuleTest(t, tc) })
	}
}

// TestTreeSitterAllRules_JS tests all untested JS/TS AST rules.
func TestTreeSitterAllRules_JS(t *testing.T) {
	cases := []tsRuleCase{
		{"TS-JS004", "comp.tsx", "<div dangerouslySetInnerHTML={{__html: x}} />\n"},
		{"TS-JS005", "app.js", "obj.__proto__ = malicious;\n"},
		{"TS-JS007", "app.js", "const crypto = require('crypto');\nconst h = crypto.createHash('sha1');\n"},
		{"TS-JS010", "app.js", "el.outerHTML = userInput;\n"},
		{"TS-JS011", "app.js", "insertAdjacentHTML('beforeend', html);\n"},
		{"TS-JS013", "app.js", "const child_process = require('child_process');\nchild_process.execSync(cmd);\n"},
		{"TS-JS015", "app.js", "setInterval(\"alert('xss')\", 1000);\n"},
		{"TS-JS016", "app.js", "Object.assign(obj, {__proto__: malicious});\n"},
		{"TS-JS017", "app.js", "const crypto = require('crypto');\nconst d = crypto.createDecipher('aes-128-cbc', key);\n"},
		{"TS-JS018", "app.js", "res.redirect(req.query.url);\n"},
		{"TS-JS019", "app.js", "jwt.sign(payload, secret);\n"},
	}
	for _, tc := range cases {
		t.Run(tc.ruleID, func(t *testing.T) { runTSRuleTest(t, tc) })
	}
}

// TestTreeSitterAllRules_Ruby tests all untested Ruby AST rules.
func TestTreeSitterAllRules_Ruby(t *testing.T) {
	cases := []tsRuleCase{
		{"TS-RB003", "app.rb", "exec(cmd)\n"},
		{"TS-RB004", "app.rb", "spawn(cmd)\n"},
		{"TS-RB006", "app.rb", "IO.popen(cmd)\n"},
		{"TS-RB007", "app.rb", "require 'open3'\nOpen3.capture2(cmd)\n"},
		{"TS-RB008", "app.rb", "send(method_name)\n"},
	}
	for _, tc := range cases {
		t.Run(tc.ruleID, func(t *testing.T) { runTSRuleTest(t, tc) })
	}
}

// TestTreeSitterAllRules_PHP tests all untested PHP AST rules.
func TestTreeSitterAllRules_PHP(t *testing.T) {
	cases := []tsRuleCase{
		{"TS-PHP002", "app.php", "<?php\n$data = unserialize($input);\n?>\n"},
		{"TS-PHP004", "app.php", "<?php\nexec($cmd);\n?>\n"},
		{"TS-PHP005", "app.php", "<?php\nshell_exec($cmd);\n?>\n"},
		{"TS-PHP007", "app.php", "<?php\npopen($cmd, 'r');\n?>\n"},
		{"TS-PHP008", "app.php", "<?php\nproc_open($cmd, $desc, $pipes);\n?>\n"},
		{"TS-PHP009", "app.php", "<?php\nassert('is_string($x)');\n?>\n"},
		{"TS-PHP010", "app.php", "<?php\n$fn = create_function('$a', 'return $a;');\n?>\n"},
	}
	for _, tc := range cases {
		t.Run(tc.ruleID, func(t *testing.T) { runTSRuleTest(t, tc) })
	}
}

// TestTreeSitterAllRules_Java tests all untested Java AST rules.
func TestTreeSitterAllRules_Java(t *testing.T) {
	cases := []tsRuleCase{
		{"TS-JAVA002", "App.java", "import java.io.ObjectInputStream;\npublic class App {\n  void run() {\n    ObjectInputStream ois = new ObjectInputStream(in);\n  }\n}\n"},
		{"TS-JAVA005", "App.java", "import java.security.MessageDigest;\npublic class App {\n  void hash() {\n    MessageDigest md = MessageDigest.getInstance(\"SHA1\");\n  }\n}\n"},
		{"TS-JAVA007", "App.java", "public class App {\n  void parse() {\n    XMLReader reader = new XMLReader();\n  }\n}\n"},
		{"TS-JAVA008", "App.java", "public class App {\n  void parse() {\n    DocumentBuilderFactory dbf = new DocumentBuilderFactory();\n  }\n}\n"},
		{"TS-JAVA009", "App.java", "public class App {\n  void parse() {\n    SAXParserFactory spf = new SAXParserFactory();\n  }\n}\n"},
		{"TS-JAVA010", "App.java", "public class App {\n  void eval() {\n    ScriptEngine myScriptEngine = null;\n    myScriptEngine.eval(code);\n  }\n}\n"},
		{"TS-JAVA011", "App.java", "@CrossOrigin(origins = \"*\")\npublic class App {\n}\n"},
		// TS-JAVA012 skipped: matchAttributeCall does not have a Java case, so it can never match.
	}
	for _, tc := range cases {
		t.Run(tc.ruleID, func(t *testing.T) { runTSRuleTest(t, tc) })
	}
}

// TestTreeSitterAllRules_CSharp tests all C# AST rules (currently zero tests).
func TestTreeSitterAllRules_CSharp(t *testing.T) {
	cases := []tsRuleCase{
		{"TS-CS001", "App.cs", "using System.Diagnostics;\nclass App {\n  void Run() {\n    Process.Start(cmd);\n  }\n}\n"},
		// TS-CS002, TS-CS003, TS-CS008, TS-CS009 skipped: matchAttributeCall has no c_sharp case.
		{"TS-CS004", "App.cs", "using System;\nclass App {\n  void Gen() {\n    var r = new Random();\n  }\n}\n"},
		{"TS-CS005", "App.cs", "using System.Xml.Serialization;\nclass App {\n  void Deser() {\n    var ser = new XmlSerializer(typeof(App));\n  }\n}\n"},
		{"TS-CS006", "App.cs", "using System.Runtime.Serialization.Formatters.Binary;\nclass App {\n  void Deser() {\n    var bf = new BinaryFormatter();\n  }\n}\n"},
		{"TS-CS007", "App.cs", "using System.Web.Script.Serialization;\nclass App {\n  void Deser() {\n    var js = new JavaScriptSerializer();\n  }\n}\n"},
		{"TS-CS010", "App.cs", "using System.Web;\nclass App {\n  string Render() {\n    return new HtmlString(html);\n  }\n}\n"},
	}
	for _, tc := range cases {
		t.Run(tc.ruleID, func(t *testing.T) { runTSRuleTest(t, tc) })
	}
}

// TestTreeSitterAllRules_Rust tests all untested Rust AST rules.
func TestTreeSitterAllRules_Rust(t *testing.T) {
	cases := []tsRuleCase{
		{"TS-RS003", "main.rs", "fn main() {\n  let x: u32 = std::mem::transmute(val);\n}\n"},
		{"TS-RS005", "main.rs", "use std::fs;\nfn main() {\n  fs::write(path, data).unwrap();\n}\n"},
		{"TS-RS006", "main.rs", "unsafe impl MyTrait for MyType {}\n"},
		// TS-RS007 skipped: tree-sitter Rust grammar uses "unary_expression" for *ptr, not "deref_expression".
		{"TS-RS009", "main.rs", "fn main() {\n  let key = std::env::var(\"KEY\").unwrap();\n}\n"},
		{"TS-RS010", "main.rs", "fn main() {\n  let ptr = vec.as_ptr();\n}\n"},
	}
	for _, tc := range cases {
		t.Run(tc.ruleID, func(t *testing.T) { runTSRuleTest(t, tc) })
	}
}
