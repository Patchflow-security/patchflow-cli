package frameworks

import (
	"os"
	"path/filepath"
	"testing"
)

// writeFile writes a file under root, creating parent dirs as needed.
func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", full, err)
	}
}

func TestDetectRails(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "Gemfile", `source "https://rubygems.org"\ngem "rails", "~> 7.0"\n`)
	writeFile(t, root, "config/routes.rb", `Rails.application.routes.draw do\nend\n`)
	writeFile(t, root, "app/controllers/application_controller.rb", `class ApplicationController < ActionController::Base\nend\n`)
	writeFile(t, root, "app/views/welcome/index.erb", `<h1>Hello</h1>`)

	d := NewDetector()
	res := d.Detect(root)

	var found bool
	for _, f := range res.Frameworks {
		if f.Name == NameRails {
			found = true
			if f.Confidence <= 0 {
				t.Fatalf("rails confidence should be > 0, got %v", f.Confidence)
			}
			if len(f.Matched) < 2 {
				t.Fatalf("rails should match >= 2 signals, got %d", len(f.Matched))
			}
		}
	}
	if !found {
		t.Fatalf("rails not detected; got %+v", res.Frameworks)
	}
}

func TestDetectRailsBelowThreshold(t *testing.T) {
	// Only one signal (Gemfile with rails) — below MinSignals=2.
	root := t.TempDir()
	writeFile(t, root, "Gemfile", `gem "rails"`)

	d := NewDetector()
	res := d.Detect(root)
	for _, f := range res.Frameworks {
		if f.Name == NameRails {
			t.Fatalf("rails should not be detected with only 1 signal, got %+v", f)
		}
	}
}

func TestDetectDjango(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "manage.py", `#!/usr/bin/env python\n`)
	writeFile(t, root, "mysite/settings.py", `INSTALLED_APPS = ["django.contrib"]\n`)
	writeFile(t, root, "mysite/urls.py", `from django.urls import path\n`)
	writeFile(t, root, "templates/base.html", `<html></html>`)

	d := NewDetector()
	res := d.Detect(root)

	var found bool
	for _, f := range res.Frameworks {
		if f.Name == NameDjango {
			found = true
		}
	}
	if !found {
		t.Fatalf("django not detected; got %+v", res.Frameworks)
	}
}

func TestDetectExpress(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"dependencies": {"express": "^4.18"}}\n`)
	writeFile(t, root, "index.js", `const express = require('express')\n`)

	d := NewDetector()
	res := d.Detect(root)

	var found bool
	for _, f := range res.Frameworks {
		if f.Name == NameExpress {
			found = true
		}
	}
	if !found {
		t.Fatalf("express not detected; got %+v", res.Frameworks)
	}
}

func TestDetectNoFrameworksInEmptyDir(t *testing.T) {
	root := t.TempDir()
	d := NewDetector()
	res := d.Detect(root)
	if len(res.Frameworks) != 0 {
		t.Fatalf("empty dir should detect no frameworks, got %+v", res.Frameworks)
	}
}

func TestDetectSpring(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "pom.xml", `<project><dependencies><dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency></dependencies></project>`)
	writeFile(t, root, "src/main/resources/application.yml", `server:\n  port: 8080\n`)

	d := NewDetector()
	res := d.Detect(root)

	var found bool
	for _, f := range res.Frameworks {
		if f.Name == NameSpring {
			found = true
		}
	}
	if !found {
		t.Fatalf("spring not detected; got %+v", res.Frameworks)
	}
}

func TestGlobRecursiveERB(t *testing.T) {
	root := t.TempDir()
	// Deeply nested .erb file under app/views — exercises the ** glob matcher.
	writeFile(t, root, "app/views/users/show.html.erb", `<p><%= @user.name %></p>`)

	d := NewDetector()
	res := d.Detect(root)
	// Rails needs 2 signals; we only have the glob. Confirm the glob itself
	// matched by checking that no false positive fires and that a rails
	// detection with the glob + one more signal would work.
	for _, f := range res.Frameworks {
		if f.Name == NameRails {
			t.Fatalf("rails should not fire with only the glob signal, got %+v", f)
		}
	}

	// Add a second signal and confirm the glob contributed.
	writeFile(t, root, "Gemfile", `gem "rails"`)
	res = d.Detect(root)
	var found bool
	for _, f := range res.Frameworks {
		if f.Name == NameRails {
			found = true
		}
	}
	if !found {
		t.Fatalf("rails should be detected with Gemfile + glob, got %+v", res.Frameworks)
	}
}
