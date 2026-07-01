package gosast

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestG115_IntegerConversionOverflow(t *testing.T) {
	dir := t.TempDir()
	writeGoModule(t, dir)
	writeGoFile(t, dir, "main.go", `package main

import "fmt"

func main() {
	var x int32 = 2147483647
	y := int8(x) // narrowing conversion — potential overflow
	fmt.Println(y)
}
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	foundG115 := false
	for _, f := range findings {
		if f.RuleID == "G115" {
			foundG115 = true
		}
	}
	if !foundG115 {
		t.Errorf("expected G115 (integer overflow) finding, got %d findings", len(findings))
	}
}

func TestG115_NoFalsePositiveSameType(t *testing.T) {
	dir := t.TempDir()
	writeGoModule(t, dir)
	writeGoFile(t, dir, "main.go", `package main

import "fmt"

func main() {
	var x int = 42
	y := int(x) // same type — no overflow
	fmt.Println(y)
}
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	for _, f := range findings {
		if f.RuleID == "G115" {
			t.Errorf("false positive: G115 triggered for same-type conversion at %s:%d",
				f.FilePath, f.LineStart)
		}
	}
}

func TestG117_SecretSerialization(t *testing.T) {
	dir := t.TempDir()
	writeGoModule(t, dir)
	writeGoFile(t, dir, "main.go", `package main

import (
	"encoding/json"
	"fmt"
)

func main() {
	password := "secret123"
	data, _ := json.Marshal(password)
	fmt.Println(string(data))
}
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	foundG117 := false
	for _, f := range findings {
		if f.RuleID == "G117" {
			foundG117 = true
		}
	}
	if !foundG117 {
		t.Errorf("expected G117 (secret serialization) finding, got %d findings", len(findings))
	}
}

func TestG117_SecretSerializationCompositeLit(t *testing.T) {
	dir := t.TempDir()
	writeGoModule(t, dir)
	writeGoFile(t, dir, "main.go", `package main

import (
	"encoding/json"
	"fmt"
)

type Config struct {
	Password string
}

func main() {
	data, _ := json.Marshal(Config{Password: "secret123"})
	fmt.Println(string(data))
}
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	foundG117 := false
	for _, f := range findings {
		if f.RuleID == "G117" {
			foundG117 = true
		}
	}
	if !foundG117 {
		t.Errorf("expected G117 (secret serialization) finding, got %d findings", len(findings))
	}
}

func TestG602_SliceOutOfBounds(t *testing.T) {
	dir := t.TempDir()
	writeGoModule(t, dir)
	writeGoFile(t, dir, "main.go", `package main

import "fmt"

func main() {
	val := []int{1, 2, 3}[5:10] // out of bounds on composite literal
	fmt.Println(val)
}
`)

	a := NewAnalyzer()
	findings, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	foundG602 := false
	for _, f := range findings {
		if f.RuleID == "G602" {
			foundG602 = true
		}
	}
	if !foundG602 {
		t.Errorf("expected G602 (slice out of bounds) finding, got %d findings", len(findings))
	}
}

func writeGoModule(t *testing.T, dir string) {
	t.Helper()
	writeGoFile(t, dir, "go.mod", "module testapp\n\ngo 1.25.6\n")
}

func writeGoFile(t *testing.T, dir, name, content string) {
	t.Helper()
	fullPath := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
}
