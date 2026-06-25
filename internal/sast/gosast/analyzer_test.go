package gosast

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/patchflow/patchflow-cli/internal/analysis"
)

func TestGoSAST_DetectsWeakCrypto(t *testing.T) {
	dir := createGoModule(t, `
package main

import (
	"crypto/md5"
	"fmt"
)

func main() {
	h := md5.New()
	fmt.Println(h)
}
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "G401" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected G401 (weak crypto MD5), got %d findings: %v", len(findings), findingRuleIDs(findings))
	}
}

func TestGoSAST_DetectsUnsafe(t *testing.T) {
	dir := createGoModule(t, `
package main

import "unsafe"

func main() {
	p := unsafe.Pointer(nil)
	_ = p
}
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "G103" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected G103 (unsafe), got %d findings: %v", len(findings), findingRuleIDs(findings))
	}
}

func TestGoSAST_DetectsHardcodedPassword(t *testing.T) {
	dir := createGoModule(t, `
package main

func main() {
	password := "supersecretpassword123"
	_ = password
}
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "G101" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected G101 (hardcoded credentials), got %d findings: %v", len(findings), findingRuleIDs(findings))
	}
}

func TestGoSAST_DetectsWeakRand(t *testing.T) {
	dir := createGoModule(t, `
package main

import "math/rand"

func main() {
	n := rand.Intn(100)
	_ = n
}
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "G404" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected G404 (weak random), got %d findings: %v", len(findings), findingRuleIDs(findings))
	}
}

func TestGoSAST_DetectsBlocklistedImport(t *testing.T) {
	dir := createGoModule(t, `
package main

import "crypto/md5"

func main() {
	_ = md5.New
}
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "G501" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected G501 (blocklisted import), got %d findings: %v", len(findings), findingRuleIDs(findings))
	}
}

func TestGoSAST_DetectsHTTPServeWithoutTimeout(t *testing.T) {
	dir := createGoModule(t, `
package main

import "net/http"

func main() {
	http.ListenAndServe(":8080", nil)
}
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "G114" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected G114 (HTTP serve without timeout), got %d findings: %v", len(findings), findingRuleIDs(findings))
	}
}

func TestGoSAST_DetectsBindToAllInterfaces(t *testing.T) {
	dir := createGoModule(t, `
package main

import "net"

func main() {
	net.Listen("tcp", "0.0.0.0:8080")
}
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "G102" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected G102 (bind to all interfaces), got %d findings: %v", len(findings), findingRuleIDs(findings))
	}
}

func TestGoSAST_NoFalsePositiveOnSafeCode(t *testing.T) {
	dir := createGoModule(t, `
package main

import (
	"crypto/rand"
	"fmt"
)

func main() {
	b := make([]byte, 16)
	rand.Read(b)
	fmt.Println(b)
}
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// Should not find weak random (G404) when using crypto/rand
	for _, f := range findings {
		if f.RuleID == "G404" {
			t.Errorf("should not flag crypto/rand as weak random")
		}
	}
}

// createGoModule creates a temporary Go module with the given source code.
func createGoModule(t *testing.T, src string) string {
	t.Helper()
	dir := t.TempDir()

	// Write go.mod
	modContent := `module testmod

go 1.25.0
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(modContent), 0644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	// Write main.go
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}

	return dir
}

func findingRuleIDs(findings []analysis.Finding) []string {
	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.RuleID
	}
	return ids
}
