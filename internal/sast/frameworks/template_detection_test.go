package frameworks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
)

func TestDetectTemplateExtension(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"app/views/show.html.erb", ".erb"},
		{"resources/views/home.blade.php", ".blade.php"},
		{"src/main/resources/templates/index.thymeleaf.html", ".thymeleaf.html"},
		{"templates/base.jinja2", ".jinja2"},
		{"views/page.razor", ".razor"},
		{"views/page.haml", ".haml"},
		{"views/page.slim", ".slim"},
	}

	for _, tt := range tests {
		if got := DetectTemplateExtension(tt.path); got != tt.want {
			t.Errorf("DetectTemplateExtension(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestMatcherMatchesCompoundTemplateExtension(t *testing.T) {
	rule := FrameworkRule{
		ID:            "PF-TEMPLATE-TEST",
		Framework:     "spring",
		Language:      "java",
		Severity:      analysis.SeverityHigh,
		Confidence:    analysis.ConfidenceHigh,
		MatchMode:     MatchTemplate,
		TemplateTypes: []string{".thymeleaf.html"},
		Pattern:       CompileRegex(`th:utext`),
	}
	matcher := NewMatcher([]FrameworkRule{rule})

	root := t.TempDir()
	target := filepath.Join(root, "index.thymeleaf.html")
	if err := os.WriteFile(target, []byte(`<div th:utext="${userInput}"></div>`), 0o644); err != nil {
		t.Fatal(err)
	}

	findings, err := matcher.ScanFile(target, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}
