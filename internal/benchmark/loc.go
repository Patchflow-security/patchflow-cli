package benchmark

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// scannableExts maps file extensions to a boolean indicating they are source
// files worth counting for LOC. Binary/generated/asset extensions are excluded.
var scannableExts = map[string]bool{
	".go": true, ".js": true, ".mjs": true, ".cjs": true, ".jsx": true, ".ts": true,
	".tsx": true, ".py": true, ".rb": true, ".php": true, ".java": true, ".kt": true,
	".rs": true, ".c": true, ".h": true, ".cpp": true, ".cc": true, ".hpp": true,
	".cs": true, ".swift": true, ".scala": true, ".clj": true, ".ex": true, ".exs": true,
	".erl": true, ".lua": true, ".pl": true, ".r": true,
	".vue": true, ".svelte": true, ".html": true, ".htm": true, ".css": true, ".scss": true,
	".sh": true, ".bash": true, ".zsh": true, ".ps1": true,
	".sql": true, ".yml": true, ".yaml": true, ".toml": true, ".json": true, ".xml": true,
	".tf": true, ".hcl": true, ".dockerfile": true,
	".gradle": true, ".groovy": true,
}

// ignoredDirNames lists directory names whose contents are never counted.
var ignoredDirNames = map[string]bool{
	".git": true, "vendor": true, "node_modules": true, "dist": true,
	"build": true, "__pycache__": true, ".next": true, ".nuxt": true,
	"target": true, ".gradle": true, ".idea": true, ".vscode": true,
	"bin": true, "obj": true, ".cache": true, ".pytest_cache": true,
	".mypy_cache": true, ".ruff_cache": true, "coverage": true,
	".turbo": true, ".svelte-kit": true, "out": true,
	"results": true, "reports": true,
}

// LOCStats holds line-of-code counts for a repository.
type LOCStats struct {
	LOC          int
	FilesScanned int
}

// CountLOC walks root and counts non-blank, non-comment-only lines in
// scannable source files. It respects ignored directories (vendor,
// node_modules, .git, build artifacts, ...). The count is intentionally a
// "physical-ish" LOC: blank lines are skipped but comment lines are counted,
// so the number reflects real file size a scanner must process.
func CountLOC(root string) (LOCStats, error) {
	var stats LOCStats
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			if ignoredDirNames[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		// Skip dotfiles that are not source (e.g. .DS_Store) but allow .env-style.
		ext := strings.ToLower(filepath.Ext(name))
		// Handle Dockerfile / Makefile by basename.
		if !scannableExts[ext] {
			if name == "Dockerfile" || name == "Makefile" {
				return countFile(path, &stats)
			}
			return nil
		}
		return countFile(path, &stats)
	})
	return stats, err
}

func countFile(path string, stats *LOCStats) error {
	f, err := os.Open(path)
	if err != nil {
		return nil // skip unreadable
	}
	defer f.Close()

	// Use bufio.Reader.ReadString instead of bufio.Scanner to avoid
	// any line-length limits (some generated XML/JSON files have 20MB+ lines).
	reader := bufio.NewReader(f)
	for {
		line, err := reader.ReadString('\n')
		if strings.TrimSpace(line) != "" {
			stats.LOC++
		}
		if err != nil {
			break // EOF or error
		}
	}
	stats.FilesScanned++
	return nil
}
