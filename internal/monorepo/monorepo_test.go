package monorepo

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write %s failed: %v", name, err)
	}
}

func TestDetectNone(t *testing.T) {
	dir := t.TempDir()
	info := Detect(dir)
	if info.IsMonorepo() {
		t.Errorf("expected no monorepo, got tool=%s", info.Tool)
	}
}

func TestDetectGoWork(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.work", `go 1.21

use (
	./services/api
	./services/worker
)
`)
	writeFile(t, dir, "services/api/go.mod", "module api\n\ngo 1.21\n")
	writeFile(t, dir, "services/worker/go.mod", "module worker\n\ngo 1.21\n")

	info := Detect(dir)
	if info.Tool != ToolGoWork {
		t.Errorf("expected ToolGoWork, got %s", info.Tool)
	}
	if len(info.MemberDirs) != 2 {
		t.Errorf("expected 2 member dirs, got %d: %v", len(info.MemberDirs), info.MemberDirs)
	}
}

func TestDetectPnpm(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "pnpm-workspace.yaml", `packages:
  - "packages/*"
`)
	writeFile(t, dir, "packages/ui/package.json", `{"name":"ui"}`)
	writeFile(t, dir, "packages/utils/package.json", `{"name":"utils"}`)

	info := Detect(dir)
	if info.Tool != ToolPnpm {
		t.Errorf("expected ToolPnpm, got %s", info.Tool)
	}
	if len(info.MemberDirs) != 2 {
		t.Errorf("expected 2 member dirs, got %d", len(info.MemberDirs))
	}
}

func TestDetectYarn(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{
		"name": "root",
		"workspaces": ["packages/*"]
	}`)
	writeFile(t, dir, "packages/app/package.json", `{"name":"app"}`)

	info := Detect(dir)
	if info.Tool != ToolYarn {
		t.Errorf("expected ToolYarn, got %s", info.Tool)
	}
	if len(info.MemberDirs) != 1 {
		t.Errorf("expected 1 member dir, got %d", len(info.MemberDirs))
	}
}

func TestDetectNx(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "nx.json", `{"extends":"nx/presets/npm.json"}`)
	writeFile(t, dir, "package.json", `{"name":"root","workspaces":["packages/*"]}`)
	writeFile(t, dir, "packages/app/package.json", `{"name":"app"}`)

	info := Detect(dir)
	if info.Tool != ToolNx {
		t.Errorf("expected ToolNx, got %s", info.Tool)
	}
}

func TestDetectTurborepo(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "turbo.json", `{"pipeline":{"build":{}}}`)
	writeFile(t, dir, "package.json", `{"name":"root","workspaces":["apps/*"]}`)
	writeFile(t, dir, "apps/web/package.json", `{"name":"web"}`)

	info := Detect(dir)
	if info.Tool != ToolTurborepo {
		t.Errorf("expected ToolTurborepo, got %s", info.Tool)
	}
}

func TestDetectBazel(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "WORKSPACE", `local_repository(name="foo", path="bar")`)

	info := Detect(dir)
	if info.Tool != ToolBazel {
		t.Errorf("expected ToolBazel, got %s", info.Tool)
	}
}

func TestDetectMavenMultiModule(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "pom.xml", `<project>
	<modelVersion>4.0.0</modelVersion>
	<groupId>com.example</groupId>
	<artifactId>parent</artifactId>
	<version>1.0.0</version>
	<packaging>pom</packaging>
	<modules>
		<module>api</module>
		<module>web</module>
	</modules>
</project>`)

	info := Detect(dir)
	if info.Tool != ToolMaven {
		t.Errorf("expected ToolMaven, got %s", info.Tool)
	}
	if len(info.MemberDirs) != 2 {
		t.Errorf("expected 2 member dirs, got %d: %v", len(info.MemberDirs), info.MemberDirs)
	}
}

func TestDetectGradleMultiProject(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "settings.gradle", `
rootProject.name = 'myapp'
include 'core'
include 'web'
`)

	info := Detect(dir)
	if info.Tool != ToolGradle {
		t.Errorf("expected ToolGradle, got %s", info.Tool)
	}
	if len(info.MemberDirs) != 2 {
		t.Errorf("expected 2 member dirs, got %d: %v", len(info.MemberDirs), info.MemberDirs)
	}
}

func TestDetectUvWorkspace(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "pyproject.toml", `[project]
name = "myapp"
version = "0.1.0"

[tool.uv.workspace]
members = ["packages/*"]
`)

	info := Detect(dir)
	if info.Tool != ToolUvWorkspace {
		t.Errorf("expected ToolUvWorkspace, got %s", info.Tool)
	}
}
