package customrules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromBytes_ValidRules(t *testing.T) {
	yamlData := []byte(`
rules:
  - id: CUSTOM-001
    title: No console.log in production
    description: console.log should not be used in production code
    languages: [javascript, typescript]
    pattern: 'console\.log\s*\('
    severity: low
    confidence: high

  - id: CUSTOM-002
    title: Raw SQL with string interpolation
    description: SQL injection risk via string formatting
    languages: [python]
    pattern: 'cursor\.execute\(.*%.*'
    severity: high
    confidence: medium
`)

	rules, err := LoadFromBytes(yamlData)
	if err != nil {
		t.Fatalf("LoadFromBytes failed: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}

	if rules[0].ID != "CUSTOM-001" {
		t.Errorf("rule[0] ID = %q, want CUSTOM-001", rules[0].ID)
	}
	if rules[0].Title != "No console.log in production" {
		t.Errorf("rule[0] Title = %q", rules[0].Title)
	}
	if len(rules[0].Languages) != 2 {
		t.Errorf("rule[0] Languages len = %d, want 2", len(rules[0].Languages))
	}
	if rules[0].Pattern == nil {
		t.Errorf("rule[0] Pattern should be compiled")
	}

	if rules[1].ID != "CUSTOM-002" {
		t.Errorf("rule[1] ID = %q, want CUSTOM-002", rules[1].ID)
	}
}

func TestLoadFromBytes_MissingID(t *testing.T) {
	yamlData := []byte(`
rules:
  - title: Missing ID
    pattern: 'something'
    languages: [python]
`)
	_, err := LoadFromBytes(yamlData)
	if err == nil {
		t.Fatal("expected error for missing id")
	}
}

func TestLoadFromBytes_MissingPattern(t *testing.T) {
	yamlData := []byte(`
rules:
  - id: CUSTOM-003
    title: No pattern
    languages: [python]
`)
	_, err := LoadFromBytes(yamlData)
	if err == nil {
		t.Fatal("expected error for missing pattern")
	}
}

func TestLoadFromBytes_InvalidRegex(t *testing.T) {
	yamlData := []byte(`
rules:
  - id: CUSTOM-004
    title: Bad regex
    pattern: '[invalid('
    languages: [python]
`)
	_, err := LoadFromBytes(yamlData)
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

func TestLoadFromBytes_UnsupportedLanguage(t *testing.T) {
	yamlData := []byte(`
rules:
  - id: CUSTOM-005
    title: Bad language
    pattern: 'something'
    languages: [cobol]
`)
	_, err := LoadFromBytes(yamlData)
	if err == nil {
		t.Fatal("expected error for unsupported language")
	}
}

func TestLoadFromBytes_NoLanguages(t *testing.T) {
	yamlData := []byte(`
rules:
  - id: CUSTOM-006
    title: No languages
    pattern: 'something'
`)
	_, err := LoadFromBytes(yamlData)
	if err == nil {
		t.Fatal("expected error for missing languages")
	}
}

func TestLoadFromBytes_DefaultSeverity(t *testing.T) {
	yamlData := []byte(`
rules:
  - id: CUSTOM-007
    title: Default severity
    pattern: 'something'
    languages: [python]
`)
	rules, err := LoadFromBytes(yamlData)
	if err != nil {
		t.Fatalf("LoadFromBytes failed: %v", err)
	}
	// Default severity should be medium
	if rules[0].Severity != "medium" {
		t.Errorf("default severity = %q, want medium", rules[0].Severity)
	}
}

func TestLoadFromDir_FileExists(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, ".patchflow")
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	rulesPath := filepath.Join(rulesDir, "rules.yaml")
	yamlData := []byte(`
rules:
  - id: CUSTOM-001
    title: Test rule
    pattern: 'test'
    languages: [python]
`)
	if err := os.WriteFile(rulesPath, yamlData, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	rules, err := LoadFromDir(dir)
	if err != nil {
		t.Fatalf("LoadFromDir failed: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
}

func TestLoadFromDir_FileNotExists(t *testing.T) {
	dir := t.TempDir()
	rules, err := LoadFromDir(dir)
	if err != nil {
		t.Fatalf("LoadFromDir should not error when file doesn't exist: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(rules))
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.yaml")
	yamlData := []byte(`
rules:
  - id: CUSTOM-001
    title: File test
    pattern: 'test'
    languages: [ruby]
`)
	if err := os.WriteFile(path, yamlData, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	rules, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Languages[0] != "ruby" {
		t.Errorf("language = %q, want ruby", rules[0].Languages[0])
	}
}

func TestParseLanguage_AllLanguages(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"python", "python"},
		{"py", "python"},
		{"javascript", "javascript"},
		{"js", "javascript"},
		{"typescript", "typescript"},
		{"ts", "typescript"},
		{"ruby", "ruby"},
		{"rb", "ruby"},
		{"php", "php"},
	}
	for _, tt := range tests {
		got, err := parseLanguage(tt.input)
		if err != nil {
			t.Errorf("parseLanguage(%q) error: %v", tt.input, err)
		}
		if string(got) != tt.want {
			t.Errorf("parseLanguage(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
