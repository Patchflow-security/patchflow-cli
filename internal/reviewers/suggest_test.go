package reviewers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseCodeownersContent(t *testing.T) {
	content := `# This is a comment
* @global-owner

# Backend files
/backend/ @backend-team @alice

# Frontend
*.js @frontend-team

# Specific file
/README.md @docs-owner
`
	rules := parseCodeownersContent(content)

	if len(rules) != 4 {
		t.Fatalf("expected 4 rules, got %d", len(rules))
	}

	if rules[0].Pattern != "*" {
		t.Errorf("expected first pattern=*, got %s", rules[0].Pattern)
	}
	if len(rules[0].Owners) != 1 || rules[0].Owners[0] != "@global-owner" {
		t.Errorf("unexpected owners: %v", rules[0].Owners)
	}

	if rules[1].Pattern != "/backend/" {
		t.Errorf("expected /backend/, got %s", rules[1].Pattern)
	}
	if len(rules[1].Owners) != 2 {
		t.Errorf("expected 2 owners for backend, got %d", len(rules[1].Owners))
	}
}

func TestMatchCodeowners(t *testing.T) {
	rules := []CodeownerRule{
		{Pattern: "*", Owners: []string{"@global"}},
		{Pattern: "/backend/", Owners: []string{"@backend-team"}},
		{Pattern: "*.js", Owners: []string{"@frontend"}},
		{Pattern: "/README.md", Owners: []string{"@docs"}},
	}

	tests := []struct {
		path     string
		wantLen  int
		wantAny  string
	}{
		{"backend/handler.go", 2, "@backend-team"},
		{"frontend/app.js", 2, "@frontend"},
		{"README.md", 2, "@docs"},
		{"config.yml", 1, "@global"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			owners := matchCodeowners(tt.path, rules)
			if len(owners) < tt.wantLen {
				t.Errorf("expected at least %d owners, got %d: %v", tt.wantLen, len(owners), owners)
			}
			found := false
			for _, o := range owners {
				if o == cleanOwner(tt.wantAny) {
					found = true
				}
			}
			if !found {
				t.Errorf("expected to find %s in owners: %v", tt.wantAny, owners)
			}
		})
	}
}

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"/backend/", "backend/handler.go", true},
		{"/backend/", "backend", true},
		{"/backend/", "frontend/app.js", false},
		{"*.js", "app.js", true},
		{"*.js", "app.ts", false},
		{"/README.md", "README.md", true},
		{"/README.md", "docs/README.md", false},
		{"*", "anything.go", true},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.path, func(t *testing.T) {
			got := matchPattern(tt.pattern, tt.path)
			if got != tt.want {
				t.Errorf("matchPattern(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
			}
		})
	}
}

func TestCleanOwner(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"@alice", "alice"},
		{"@org/team", "team"},
		{"bob", "bob"},
		{"@user@example.com", "user@example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := cleanOwner(tt.input)
			if got != tt.want {
				t.Errorf("cleanOwner(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestDetectExpertise(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"main.go", "go"},
		{"app.py", "python"},
		{"index.js", "javascript"},
		{"App.java", "java"},
		{"Gemfile", ""},
		{".github/workflows/ci.yml", "ci-cd"},
		{"auth/login.go", "security"},
		{"tests/main_test.go", "testing"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := detectExpertise(tt.path)
			if got != tt.want {
				t.Errorf("detectExpertise(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestSuggestWithCodeowners(t *testing.T) {
	tmpDir := t.TempDir()

	// Create .github/CODEOWNERS
	githubDir := filepath.Join(tmpDir, ".github")
	if err := os.MkdirAll(githubDir, 0755); err != nil {
		t.Fatal(err)
	}
	codeownersContent := `* @global-owner
/app.js @app-owner
/backend/ @backend-team
`
	if err := os.WriteFile(filepath.Join(githubDir, "CODEOWNERS"), []byte(codeownersContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a test file
	if err := os.WriteFile(filepath.Join(tmpDir, "app.js"), []byte("console.log('test');"), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := Suggest(SuggestOptions{
		RepoRoot:      tmpDir,
		ChangedFiles:  []string{"app.js"},
		MaxReviewers:  5,
		UseBlame:      false,
		UseCodeowners: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if !result.CodeownersFound {
		t.Error("expected CODEOWNERS to be found")
	}
	if len(result.Reviewers) == 0 {
		t.Fatal("expected at least 1 reviewer")
	}

	// Should find @global-owner and @app-owner
	found := make(map[string]bool)
	for _, rev := range result.Reviewers {
		found[rev.Username] = true
	}
	if !found["global-owner"] {
		t.Error("expected to find global-owner")
	}
	if !found["app-owner"] {
		t.Error("expected to find app-owner")
	}
}

func TestSuggestNoCodeowners(t *testing.T) {
	tmpDir := t.TempDir()

	result, err := Suggest(SuggestOptions{
		RepoRoot:      tmpDir,
		ChangedFiles:  []string{"app.js"},
		MaxReviewers:  5,
		UseBlame:      false,
		UseCodeowners: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.CodeownersFound {
		t.Error("expected no CODEOWNERS found")
	}
	if len(result.Reviewers) != 0 {
		t.Errorf("expected 0 reviewers without codeowners or blame, got %d", len(result.Reviewers))
	}
}

func TestRenderMarkdown(t *testing.T) {
	result := &SuggestionResult{
		CodeownersFound: true,
		Reviewers: []Reviewer{
			{
				Username: "alice",
				Score:    20,
				IsOwner:  true,
				Reasons:  []string{"CODEOWNERS match"},
				Files:    []string{"app.js", "db.js"},
			},
			{
				Username: "bob",
				Score:    10,
				Reasons:  []string{"Authored 5 lines in app.js"},
				Files:    []string{"app.js"},
			},
		},
	}

	md := RenderMarkdown(result)
	if !strings.Contains(md, "Suggested Reviewers") {
		t.Error("should contain header")
	}
	if !strings.Contains(md, "@alice") {
		t.Error("should contain alice")
	}
	if !strings.Contains(md, "CODEOWNER") {
		t.Error("should contain CODEOWNER badge")
	}
	if !strings.Contains(md, "20 pts") {
		t.Error("should contain score")
	}
}

func TestRenderMarkdownEmpty(t *testing.T) {
	result := &SuggestionResult{}
	md := RenderMarkdown(result)
	if md != "" {
		t.Errorf("expected empty string for no reviewers, got %s", md)
	}
}

func TestAppendUnique(t *testing.T) {
	slice := []string{"a", "b"}
	slice = appendUnique(slice, "a") // should not add
	if len(slice) != 2 {
		t.Errorf("expected 2 items, got %d", len(slice))
	}
	slice = appendUnique(slice, "c")
	if len(slice) != 3 {
		t.Errorf("expected 3 items, got %d", len(slice))
	}
}
