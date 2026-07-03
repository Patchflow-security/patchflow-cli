package graphql

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

func scanFixture(t *testing.T, name, content string) []analysis.Finding {
	t.Helper()
	root := t.TempDir()
	target := filepath.Join(root, name)
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := frameworks.NewMatcher(New().Rules()).ScanFile(target, root)
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

func hasFinding(findings []analysis.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

func TestGraphQLPackContract(t *testing.T) {
	pack := New()
	if pack.Name() != "graphql" || pack.Language() != "python" {
		t.Fatalf("unexpected pack identity: %s/%s", pack.Name(), pack.Language())
	}
	if len(pack.Rules()) == 0 || len(pack.Sources()) == 0 || len(pack.Sinks()) == 0 {
		t.Fatal("pack contract should expose rules, sources, and sinks")
	}
}

func TestGraphQLRuleCount(t *testing.T) {
	rules := New().Rules()
	if len(rules) != 5 {
		t.Fatalf("expected 5 rules, got %d", len(rules))
	}
}

func TestGraphQLRuleIDs(t *testing.T) {
	expected := []string{
		"PF-GRAPHQL-SQLI-001",
		"PF-GRAPHQL-SSRF-001",
		"PF-GRAPHQL-PATH-001",
		"PF-GRAPHQL-AUTH-001",
		"PF-GRAPHQL-DOS-001",
	}
	rules := New().Rules()
	for _, exp := range expected {
		found := false
		for _, r := range rules {
			if r.ID == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing rule: %s", exp)
		}
	}
}

func TestGraphQLTaintRuleCount(t *testing.T) {
	pack := New()
	taintCount := 0
	for _, rule := range pack.Rules() {
		if rule.MatchMode == frameworks.MatchTaint {
			taintCount++
		}
	}
	if taintCount != 3 {
		t.Fatalf("expected 3 MatchTaint rules, got %d", taintCount)
	}
}

func TestGraphQLAuthRuleInform(t *testing.T) {
	for _, rule := range New().Rules() {
		if rule.ID == "PF-GRAPHQL-AUTH-001" {
			if rule.Severity == analysis.SeverityHigh || rule.Severity == analysis.SeverityCritical {
				t.Fatalf("auth rule should not be high/critical severity, got %v", rule.Severity)
			}
		}
	}
}

func TestGraphQLDoSRuleExperimental(t *testing.T) {
	for _, rule := range New().Rules() {
		if rule.ID == "PF-GRAPHQL-DOS-001" {
			if rule.Maturity != frameworks.MaturityExperimental {
				t.Fatalf("DoS rule should be experimental, got %s", rule.Maturity)
			}
		}
	}
}

func TestGraphQLSourceCoverage(t *testing.T) {
	pack := New()
	sourceNames := map[string]bool{}
	for _, s := range pack.Sources() {
		sourceNames[s.FuncName] = true
	}
	required := []string{
		"info.context",
		"context.request",
		"kwargs",
	}
	for _, req := range required {
		if !sourceNames[req] {
			t.Errorf("missing source pattern: %s", req)
		}
	}
}

func TestGraphQLSinkCoverage(t *testing.T) {
	pack := New()
	sinkNames := map[string]bool{}
	for _, s := range pack.Sinks() {
		sinkNames[s.FuncName] = true
	}
	required := []string{
		"text",
		"execute",
		"requests.get",
		"httpx.get",
		"open",
		"send_file",
	}
	for _, req := range required {
		if !sinkNames[req] {
			t.Errorf("missing sink pattern: %s", req)
		}
	}
}

func TestGraphQLAuthRulePositive(t *testing.T) {
	findings := scanFixture(t, "resolver.py", `
def resolve_post(root, info, id):
    post = Post.query.filter_by(id=id).first()
    return post
`)
	if !hasFinding(findings, "PF-GRAPHQL-AUTH-001") {
		t.Fatalf("expected AUTH finding for filter_by(id=id) without ownership check, got %+v", findings)
	}
}

func TestGraphQLAuthRuleSafeWithOwnership(t *testing.T) {
	findings := scanFixture(t, "resolver.py", `
def resolve_post(root, info, id):
    post = Post.query.filter_by(id=id, owner=current_user.id).first()
    return post
`)
	if hasFinding(findings, "PF-GRAPHQL-AUTH-001") {
		t.Fatalf("ownership check (owner=current_user) should suppress AUTH finding, got %+v", findings)
	}
}

func TestGraphQLDoSRulePositive(t *testing.T) {
	findings := scanFixture(t, "schema.py", `
from graphene import Schema
schema = Schema(query=Query)
`)
	if !hasFinding(findings, "PF-GRAPHQL-DOS-001") {
		t.Fatalf("expected DoS finding for Schema() without depth limit, got %+v", findings)
	}
}

func TestGraphQLDoSRuleSafeWithDepthLimit(t *testing.T) {
	findings := scanFixture(t, "schema.py", `
from graphene import Schema
from graphql_depth_limit import depth_limit
schema = Schema(query=Query, validation_rules=[depth_limit(max_depth=10)])
`)
	if hasFinding(findings, "PF-GRAPHQL-DOS-001") {
		t.Fatalf("depth_limit validation rule should suppress DoS finding, got %+v", findings)
	}
}
