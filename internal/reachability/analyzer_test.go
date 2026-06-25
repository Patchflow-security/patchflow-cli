package reachability

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParsePythonImports(t *testing.T) {
	dir := t.TempDir()
	content := `import os
import sys
from flask import Flask, request
import django.contrib.auth
import numpy as np
# import commented_out
from pathlib import Path
`
	path := filepath.Join(dir, "test.py")
	os.WriteFile(path, []byte(content), 0644)

	imports := parsePythonImports(path)

	expected := map[string]bool{
		"os":     true,
		"sys":    true,
		"flask":  true,
		"django": true,
		"numpy":  true,
		"pathlib": true,
	}

	if len(imports) != len(expected) {
		t.Fatalf("expected %d imports, got %d: %v", len(expected), len(imports), imports)
	}

	for _, imp := range imports {
		if !expected[imp] {
			t.Errorf("unexpected import: %s", imp)
		}
	}
}

func TestParseGoImports(t *testing.T) {
	dir := t.TempDir()
	content := `package main

import (
	"fmt"
	"os"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

import "strings"

func main() {}
`
	path := filepath.Join(dir, "test.go")
	os.WriteFile(path, []byte(content), 0644)

	imports := parseGoImports(path)

	expected := map[string]bool{
		"fmt":                   true,
		"os":                    true,
		"github.com/spf13/cobra": true,
		"github.com/spf13/viper": true,
		"strings":               true,
	}

	if len(imports) != len(expected) {
		t.Fatalf("expected %d imports, got %d: %v", len(expected), len(imports), imports)
	}

	for _, imp := range imports {
		if !expected[imp] {
			t.Errorf("unexpected import: %s", imp)
		}
	}
}

func TestParseJSImports(t *testing.T) {
	dir := t.TempDir()
	content := `import express from 'express';
import { Router } from 'express';
const lodash = require('lodash');
const _ = require('lodash/deep');
import { createServer } from 'http';
import('./dynamic-module');
import { something } from './local-file';
export { default } from '@scope/pkg';
`
	path := filepath.Join(dir, "test.js")
	os.WriteFile(path, []byte(content), 0644)

	imports := parseJSImports(path)

	expected := map[string]bool{
		"express":     true,
		"lodash":      true,
		"http":        true,
		"@scope/pkg":  true,
	}

	// Note: dynamic-module may or may not be captured depending on regex
	// The key test is that local imports (./local-file) are excluded
	if len(imports) < 4 {
		t.Fatalf("expected at least 4 imports, got %d: %v", len(imports), imports)
	}

	for _, imp := range imports {
		if !expected[imp] {
			t.Errorf("unexpected import: %s", imp)
		}
	}

	// Local imports should be excluded
	for _, imp := range imports {
		if imp == "./local-file" || imp == "" {
			t.Error("local imports should be excluded")
		}
	}
}

func TestNormalizeJSPackage(t *testing.T) {
	tests := []struct {
		input  string
		output string
	}{
		{"express", "express"},
		{"lodash/deep", "lodash"},
		{"@scope/pkg", "@scope/pkg"},
		{"@scope/pkg/sub", "@scope/pkg"},
		{"./local", ""},
		{"/absolute", ""},
	}

	for _, tt := range tests {
		if got := normalizeJSPackage(tt.input); got != tt.output {
			t.Errorf("normalizeJSPackage(%s) = %s, want %s", tt.input, got, tt.output)
		}
	}
}

func TestBuildImportGraph(t *testing.T) {
	dir := t.TempDir()

	// Create Python file
	os.WriteFile(filepath.Join(dir, "app.py"), []byte("import flask\nimport requests\n"), 0644)

	// Create Go file
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(`package main
import (
	"fmt"
	"github.com/spf13/cobra"
)
func main() {}
`), 0644)

	// Create JS file
	os.WriteFile(filepath.Join(dir, "index.js"), []byte("import express from 'express';\n"), 0644)

	// Create a file in node_modules that should be skipped
	nmDir := filepath.Join(dir, "node_modules", "somepkg")
	os.MkdirAll(nmDir, 0755)
	os.WriteFile(filepath.Join(nmDir, "index.js"), []byte("import 'should-be-skipped';\n"), 0644)

	analyzer := NewAnalyzer()
	graph, err := analyzer.buildImportGraph(dir)
	if err != nil {
		t.Fatalf("buildImportGraph failed: %v", err)
	}

	expected := map[string]bool{
		"flask":  true,
		"requests": true,
		"fmt":    true,
		"github.com/spf13/cobra": true,
		"express": true,
	}

	for pkg := range expected {
		if !graph.AllImportedPackages[pkg] {
			t.Errorf("expected package %s in import graph", pkg)
		}
	}

	// node_modules should be skipped
	if graph.AllImportedPackages["should-be-skipped"] {
		t.Error("node_modules imports should be skipped")
	}
}

func TestAssessReachabilityDirectImport(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "app.py"), []byte("import flask\n"), 0644)

	analyzer := NewAnalyzer()
	graph, _ := analyzer.buildImportGraph(dir)

	status, evidence := analyzer.assessReachability("flask", "", graph, nil)

	if status != "high" {
		t.Errorf("expected high reachability for directly imported package, got %s", status)
	}
	if len(evidence) == 0 {
		t.Error("expected evidence for directly imported package")
	}
}

func TestAssessReachabilityNotImported(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "app.py"), []byte("import flask\n"), 0644)

	analyzer := NewAnalyzer()
	graph, _ := analyzer.buildImportGraph(dir)

	status, _ := analyzer.assessReachability("nonexistent-pkg", "", graph, nil)

	if status != "none" {
		t.Errorf("expected none reachability for non-imported package, got %s", status)
	}
}
