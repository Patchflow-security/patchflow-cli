// Package monorepo detects monorepo tooling (Nx, Turborepo, Bazel, go.work,
// pnpm/yarn workspaces, Maven multi-module, Gradle multi-project) and provides
// metadata about the monorepo structure for scan orchestration.
package monorepo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Tool identifies a monorepo management tool.
type Tool string

const (
	ToolNone       Tool = ""
	ToolGoWork     Tool = "go.work"
	ToolPnpm       Tool = "pnpm"
	ToolYarn       Tool = "yarn"
	ToolNx         Tool = "nx"
	ToolTurborepo  Tool = "turborepo"
	ToolBazel      Tool = "bazel"
	ToolMaven      Tool = "maven-multi-module"
	ToolGradle     Tool = "gradle-multi-project"
	ToolUvWorkspace Tool = "uv-workspace"
)

// Info describes a detected monorepo structure.
type Info struct {
	Tool        Tool     `json:"tool"`
	RootDir     string   `json:"root_dir"`
	WorkspaceFiles []string `json:"workspace_files"`
	MemberDirs  []string `json:"member_dirs"`
}

// Detect checks a repository root for monorepo tooling and returns
// metadata about the detected structure. Returns Info with Tool=ToolNone
// if no monorepo tooling is found.
func Detect(root string) Info {
	info := Info{RootDir: root}

	// Check for go.work
	if _, err := os.Stat(filepath.Join(root, "go.work")); err == nil {
		info.Tool = ToolGoWork
		info.WorkspaceFiles = append(info.WorkspaceFiles, "go.work")
		members := detectGoWorkMembers(root)
		info.MemberDirs = append(info.MemberDirs, members...)
	}

	// Check for pnpm-workspace.yaml
	if _, err := os.Stat(filepath.Join(root, "pnpm-workspace.yaml")); err == nil {
		if info.Tool == ToolNone {
			info.Tool = ToolPnpm
		}
		info.WorkspaceFiles = append(info.WorkspaceFiles, "pnpm-workspace.yaml")
		members := detectPnpmWorkspaceMembers(root)
		info.MemberDirs = append(info.MemberDirs, members...)
	}

	// Check for yarn workspaces (root package.json with "workspaces" field)
	if pkgMembers := detectYarnWorkspaceMembers(root); len(pkgMembers) > 0 {
		if info.Tool == ToolNone {
			info.Tool = ToolYarn
		}
		info.WorkspaceFiles = append(info.WorkspaceFiles, "package.json")
		info.MemberDirs = append(info.MemberDirs, pkgMembers...)
	}

	// Check for Nx (nx.json — usually on top of pnpm/yarn workspaces)
	if _, err := os.Stat(filepath.Join(root, "nx.json")); err == nil {
		info.Tool = ToolNx
		info.WorkspaceFiles = append(info.WorkspaceFiles, "nx.json")
	}

	// Check for Turborepo (turbo.json — usually on top of pnpm/yarn workspaces)
	if _, err := os.Stat(filepath.Join(root, "turbo.json")); err == nil {
		if info.Tool == ToolNone || info.Tool == ToolPnpm || info.Tool == ToolYarn {
			info.Tool = ToolTurborepo
		}
		info.WorkspaceFiles = append(info.WorkspaceFiles, "turbo.json")
	}

	// Check for Bazel
	for _, bazelFile := range []string{"WORKSPACE", "WORKSPACE.bazel", "WORKSPACE.bazelmod"} {
		if _, err := os.Stat(filepath.Join(root, bazelFile)); err == nil {
			if info.Tool == ToolNone {
				info.Tool = ToolBazel
			}
			info.WorkspaceFiles = append(info.WorkspaceFiles, bazelFile)
			break
		}
	}

	// Check for Maven multi-module (root pom.xml with <modules>)
	if members := detectMavenMultiModule(root); len(members) > 0 {
		if info.Tool == ToolNone {
			info.Tool = ToolMaven
		}
		info.WorkspaceFiles = append(info.WorkspaceFiles, "pom.xml")
		info.MemberDirs = append(info.MemberDirs, members...)
	}

	// Check for Gradle multi-project (settings.gradle with includes)
	if members := detectGradleMultiProject(root); len(members) > 0 {
		if info.Tool == ToolNone {
			info.Tool = ToolGradle
		}
		info.WorkspaceFiles = append(info.WorkspaceFiles, "settings.gradle")
		info.MemberDirs = append(info.MemberDirs, members...)
	}

	// Check for uv workspace (pyproject.toml with [tool.uv.workspace])
	if detectUvWorkspace(root) {
		if info.Tool == ToolNone {
			info.Tool = ToolUvWorkspace
		}
		info.WorkspaceFiles = append(info.WorkspaceFiles, "pyproject.toml")
	}

	return info
}

// IsMonorepo returns true if a monorepo tool was detected.
func (i Info) IsMonorepo() bool {
	return i.Tool != ToolNone
}

// detectGoWorkMembers reads go.work and returns module directory paths.
func detectGoWorkMembers(root string) []string {
	data, err := os.ReadFile(filepath.Join(root, "go.work"))
	if err != nil {
		return nil
	}
	var members []string
	inUseBlock := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "use (" {
			inUseBlock = true
			continue
		}
		if strings.HasPrefix(trimmed, "use ") && !strings.HasSuffix(trimmed, "(") {
			rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "use "))
			if rest != "" {
				members = append(members, rest)
			}
			continue
		}
		if trimmed == ")" && inUseBlock {
			inUseBlock = false
			continue
		}
		if inUseBlock {
			m := strings.TrimSpace(trimmed)
			if m != "" {
				members = append(members, m)
			}
		}
	}
	return members
}

// detectPnpmWorkspaceMembers reads pnpm-workspace.yaml and returns member dirs.
func detectPnpmWorkspaceMembers(root string) []string {
	data, err := os.ReadFile(filepath.Join(root, "pnpm-workspace.yaml"))
	if err != nil {
		return nil
	}
	var ws struct {
		Packages []string `yaml:"packages"`
	}
	if err := yaml.Unmarshal(data, &ws); err != nil {
		return nil
	}
	var members []string
	for _, pattern := range ws.Packages {
		matches, err := filepath.Glob(filepath.Join(root, pattern))
		if err != nil {
			continue
		}
		for _, m := range matches {
			rel, err := filepath.Rel(root, m)
			if err == nil {
				members = append(members, rel)
			}
		}
	}
	return members
}

// detectYarnWorkspaceMembers checks root package.json for yarn workspaces.
func detectYarnWorkspaceMembers(root string) []string {
	data, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		return nil
	}
	var pkg struct {
		Workspaces json.RawMessage `json:"workspaces"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}
	if len(pkg.Workspaces) == 0 {
		return nil
	}
	// Try array format
	var patterns []string
	if err := json.Unmarshal(pkg.Workspaces, &patterns); err != nil {
		// Try object format
		var obj struct {
			Packages []string `json:"packages"`
		}
		if err := json.Unmarshal(pkg.Workspaces, &obj); err != nil {
			return nil
		}
		patterns = obj.Packages
	}
	var members []string
	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(root, pattern))
		if err != nil {
			continue
		}
		for _, m := range matches {
			rel, err := filepath.Rel(root, m)
			if err == nil {
				members = append(members, rel)
			}
		}
	}
	return members
}

// detectMavenMultiModule checks root pom.xml for <modules> section.
func detectMavenMultiModule(root string) []string {
	data, err := os.ReadFile(filepath.Join(root, "pom.xml"))
	if err != nil {
		return nil
	}
	src := string(data)
	modulesIdx := strings.Index(src, "<modules>")
	if modulesIdx < 0 {
		return nil
	}
	endIdx := strings.Index(src[modulesIdx:], "</modules>")
	if endIdx < 0 {
		return nil
	}
	block := src[modulesIdx : modulesIdx+endIdx]
	var members []string
	for _, line := range strings.Split(block, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "<module>") {
			name := strings.TrimSuffix(strings.TrimPrefix(trimmed, "<module>"), "</module>")
			name = strings.TrimSpace(name)
			if name != "" {
				members = append(members, name)
			}
		}
	}
	return members
}

// detectGradleMultiProject checks settings.gradle for include directives.
func detectGradleMultiProject(root string) []string {
	for _, settingsFile := range []string{"settings.gradle", "settings.gradle.kts"} {
		data, err := os.ReadFile(filepath.Join(root, settingsFile))
		if err != nil {
			continue
		}
		src := string(data)
		if !strings.Contains(src, "include") {
			continue
		}
		var members []string
		// Match: include 'name' or include('name') or include "name"
		for _, line := range strings.Split(src, "\n") {
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(trimmed, "include") {
				continue
			}
			// Extract quoted strings
			start := strings.IndexAny(trimmed, "'\"")
			if start < 0 {
				continue
			}
			quote := trimmed[start]
			end := strings.IndexByte(trimmed[start+1:], quote)
			if end < 0 {
				continue
			}
			name := trimmed[start+1 : start+1+end]
			if name != "" {
				members = append(members, strings.ReplaceAll(name, ":", "/"))
			}
		}
		if len(members) > 0 {
			return members
		}
	}
	return nil
}

// detectUvWorkspace checks root pyproject.toml for [tool.uv.workspace] section.
func detectUvWorkspace(root string) bool {
	data, err := os.ReadFile(filepath.Join(root, "pyproject.toml"))
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "[tool.uv.workspace]")
}
