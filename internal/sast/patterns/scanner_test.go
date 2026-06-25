package patterns

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPatternScanner_PythonEval(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.py", `result = eval(user_input)`)

	s := NewScanner()
	findings, err := s.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "PY001" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected PY001 (eval), got %d findings", len(findings))
	}
}

func TestPatternScanner_PythonShellTrue(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "runner.py", `subprocess.call(cmd, shell=True)`)

	s := NewScanner()
	findings, err := s.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "PY004" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected PY004 (shell=True), got %d findings", len(findings))
	}
}

func TestPatternScanner_PythonPickle(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "loader.py", `data = pickle.loads(raw_data)`)

	s := NewScanner()
	findings, err := s.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "PY005" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected PY005 (pickle.loads), got %d findings", len(findings))
	}
}

func TestPatternScanner_PythonMD5(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "hash.py", `h = hashlib.md5(data)`)

	s := NewScanner()
	findings, err := s.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "PY009" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected PY009 (MD5), got %d findings", len(findings))
	}
}

func TestPatternScanner_PythonSSLVerifyFalse(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "client.py", `requests.get(url, verify=False)`)

	s := NewScanner()
	findings, err := s.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "PY014" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected PY014 (verify=False), got %d findings", len(findings))
	}
}

func TestPatternScanner_PythonFlaskDebug(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "server.py", `app.run(debug=True)`)

	s := NewScanner()
	findings, err := s.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "PY016" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected PY016 (Flask debug=True), got %d findings", len(findings))
	}
}

func TestPatternScanner_JSEval(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.js", `const result = eval(userInput);`)

	s := NewScanner()
	findings, err := s.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "JS001" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected JS001 (eval), got %d findings", len(findings))
	}
}

func TestPatternScanner_JSChildProcessExec(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "runner.js", `const child_process = require('child_process');
child_process.exec(userInput, (err, stdout) => {});`)

	s := NewScanner()
	findings, err := s.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "JS003" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected JS003 (child_process.exec), got %d findings", len(findings))
	}
}

func TestPatternScanner_JSDangerouslySetInnerHTML(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "component.tsx", `<div dangerouslySetInnerHTML={{__html: userInput}} />`)

	s := NewScanner()
	findings, err := s.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "JS012" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected JS012 (dangerouslySetInnerHTML), got %d findings", len(findings))
	}
}

func TestPatternScanner_RubyEval(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.rb", `result = eval(user_input)`)

	s := NewScanner()
	findings, err := s.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "RB001" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected RB001 (Ruby eval), got %d findings", len(findings))
	}
}

func TestPatternScanner_PHPEval(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.php", `<?php eval($_GET['code']); ?>`)

	s := NewScanner()
	findings, err := s.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "PHP001" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected PHP001 (PHP eval), got %d findings", len(findings))
	}
}

func TestPatternScanner_SkipsComments(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.py", `# eval(user_input) -- this is just a comment`)

	s := NewScanner()
	findings, err := s.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	for _, f := range findings {
		if f.RuleID == "PY001" {
			t.Errorf("should not flag eval in a comment")
		}
	}
}

func TestPatternScanner_SkipsIgnoredDirs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "node_modules/lib.js", `eval(userInput);`)

	s := NewScanner()
	findings, err := s.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	for _, f := range findings {
		if f.RuleID == "JS001" {
			t.Errorf("should not scan node_modules/")
		}
	}
}

func TestPatternScanner_DetectLanguage(t *testing.T) {
	tests := []struct {
		path string
		want Language
	}{
		{"app.py", LangPython},
		{"app.js", LangJavaScript},
		{"app.ts", LangTypeScript},
		{"app.tsx", LangTypeScript},
		{"app.rb", LangRuby},
		{"app.php", LangPHP},
		{"Rakefile", LangRuby},
		{"app.go", ""},
		{"README.md", ""},
	}

	for _, tt := range tests {
		got := detectLanguage(tt.path)
		if got != tt.want {
			t.Errorf("detectLanguage(%q) = %q, want %q", tt.path, got, tt.want)
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
