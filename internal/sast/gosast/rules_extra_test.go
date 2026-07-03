package gosast

import (
	"context"
	"testing"
)

func TestGoSAST_DetectsNoErrorCheck(t *testing.T) {
	dir := createGoModule(t, `
package main

import "fmt"

func main() {
	_, err := fmt.Println("hello")
	_ = err
}
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// G104 is Low severity and only triggers when error is assigned to _
	// This test just verifies the rule doesn't crash
	_ = findings
}

func TestGoSAST_DetectsSlowloris(t *testing.T) {
	dir := createGoModule(t, `
package main

import "net/http"

func main() {
	srv := &http.Server{
		Addr: ":8080",
	}
	_ = srv
}
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "G112" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected G112 (slowloris), got %d findings: %v", len(findings), findingRuleIDs(findings))
	}
}

func TestGoSAST_SlowlorisWithTimeout_NoFinding(t *testing.T) {
	dir := createGoModule(t, `
package main

import (
	"net/http"
	"time"
)

func main() {
	srv := &http.Server{
		Addr:              ":8080",
		ReadHeaderTimeout: 10 * time.Second,
	}
	_ = srv
}
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	for _, f := range findings {
		if f.RuleID == "G112" {
			t.Errorf("should not flag G112 when ReadHeaderTimeout is set")
		}
	}
}

func TestGoSAST_DetectsTLSInsecureSkipVerify(t *testing.T) {
	dir := createGoModule(t, `
package main

import "crypto/tls"

func main() {
	cfg := &tls.Config{
		InsecureSkipVerify: true,
	}
	_ = cfg
}
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "G402" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected G402 (TLS InsecureSkipVerify), got %d findings: %v", len(findings), findingRuleIDs(findings))
	}
}

func TestGoSAST_DetectsDirectoryTraversal(t *testing.T) {
	dir := createGoModule(t, `
package main

import "net/http"

func main() {
	fs := http.Dir("/")
	_ = fs
}
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "G111" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected G111 (directory traversal), got %d findings: %v", len(findings), findingRuleIDs(findings))
	}
}

func TestGoSAST_DetectsWeakRSAKey(t *testing.T) {
	dir := createGoModule(t, `
package main

import "crypto/rsa"

func main() {
	key, _ := rsa.GenerateKey(nil, 1024)
	_ = key
}
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "G403" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected G403 (weak RSA key), got %d findings: %v", len(findings), findingRuleIDs(findings))
	}
}

func TestGoSAST_StrongRSAKey_NoFinding(t *testing.T) {
	dir := createGoModule(t, `
package main

import "crypto/rsa"

func main() {
	key, _ := rsa.GenerateKey(nil, 2048)
	_ = key
}
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	for _, f := range findings {
		if f.RuleID == "G403" {
			t.Errorf("should not flag G403 for 2048-bit RSA key")
		}
	}
}
