// Package cacheutil provides centralized cache directory resolution for
// PatchFlow. Instead of polluting every scanned project with a
// .patchflow/cache/ directory, cache data is stored in a global,
// XDG-compliant location keyed by a project hash.
//
// Resolution order (highest priority first):
//  1. PATCHFLOW_CACHE_DIR environment variable (explicit override)
//  2. --cache-dir CLI flag (set via SetGlobalCacheDir)
//  3. $XDG_CACHE_HOME/patchflow/<project-hash>/
//  4. ~/.cache/patchflow/<project-hash>/ (XDG default)
//
// Project-local artifacts (config.yml, baselines/, reports/) remain under
// .patchflow/ in the project root — only derived/reproducible cache data
// moves to the global location.
package cacheutil

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
)

// globalCacheDir is set by the CLI via SetGlobalCacheDir (from --cache-dir).
// If empty, the env var and XDG resolution path is used.
var (
	globalCacheDir string
	mu             sync.RWMutex
)

// SetGlobalCacheDir sets the override cache directory (from --cache-dir flag).
// When set, this takes priority over env vars and XDG defaults.
func SetGlobalCacheDir(dir string) {
	mu.Lock()
	defer mu.Unlock()
	globalCacheDir = dir
}

// getGlobalCacheDir returns the override cache directory, or "" if not set.
func getGlobalCacheDir() string {
	mu.RLock()
	defer mu.RUnlock()
	return globalCacheDir
}

// ProjectHash returns a short hex hash that uniquely identifies a project
// root path. This is used as a subdirectory under the global cache to avoid
// collisions between different projects.
func ProjectHash(projectRoot string) string {
	abs, err := filepath.Abs(projectRoot)
	if err != nil {
		abs = projectRoot
	}
	sum := sha256.Sum256([]byte(abs))
	return hex.EncodeToString(sum[:])[:16] // 16 hex chars = 8 bytes, enough uniqueness
}

// ResolveCacheDir returns the root cache directory for a given project.
// This is the base directory under which subdirectories like "osv",
// "registry", "maven", "sast_state.json" live.
//
// Resolution order:
//  1. --cache-dir flag (SetGlobalCacheDir)
//  2. PATCHFLOW_CACHE_DIR env var
//  3. $XDG_CACHE_HOME/patchflow/<hash>/
//  4. ~/.cache/patchflow/<hash>/
func ResolveCacheDir(projectRoot string) string {
	// 1. CLI flag override
	if dir := getGlobalCacheDir(); dir != "" {
		return filepath.Join(dir, ProjectHash(projectRoot))
	}

	// 2. Environment variable override
	if dir := os.Getenv("PATCHFLOW_CACHE_DIR"); dir != "" {
		return filepath.Join(dir, ProjectHash(projectRoot))
	}

	// 3. XDG_CACHE_HOME
	xdgCache := os.Getenv("XDG_CACHE_HOME")
	if xdgCache != "" {
		return filepath.Join(xdgCache, "patchflow", ProjectHash(projectRoot))
	}

	// 4. Default: ~/.cache/patchflow/<hash>/
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".cache", "patchflow", ProjectHash(projectRoot))
}

// ResolveSubdir returns the full path to a cache subdirectory for a project.
// Examples: ResolveSubdir(root, "osv"), ResolveSubdir(root, "registry")
func ResolveSubdir(projectRoot, subdir string) string {
	return filepath.Join(ResolveCacheDir(projectRoot), subdir)
}

// ResolveFile returns the full path to a cache file for a project.
// Examples: ResolveFile(root, "sast_state.json")
func ResolveFile(projectRoot, filename string) string {
	return filepath.Join(ResolveCacheDir(projectRoot), filename)
}

// GlobalCacheRoot returns the top-level patchflow cache directory (without
// the project hash). This is useful for `cache clean --all` operations.
func GlobalCacheRoot() string {
	// 1. CLI flag override
	if dir := getGlobalCacheDir(); dir != "" {
		return dir
	}
	// 2. Environment variable override
	if dir := os.Getenv("PATCHFLOW_CACHE_DIR"); dir != "" {
		return dir
	}
	// 3. XDG_CACHE_HOME
	if xdgCache := os.Getenv("XDG_CACHE_HOME"); xdgCache != "" {
		return filepath.Join(xdgCache, "patchflow")
	}
	// 4. Default: ~/.cache/patchflow/
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".cache", "patchflow")
}

// EnsureDir creates the cache directory for a project if it doesn't exist.
// This is called lazily by cache writers.
func EnsureDir(projectRoot string) error {
	return os.MkdirAll(ResolveCacheDir(projectRoot), 0o755)
}

// EnsureSubdir creates a cache subdirectory for a project if it doesn't exist.
func EnsureSubdir(projectRoot, subdir string) error {
	return os.MkdirAll(ResolveSubdir(projectRoot, subdir), 0o755)
}

// MigrateLegacyCache checks for a legacy .patchflow/cache/ directory in the
// project root and, if present, moves its contents to the new global cache
// location. This is called once on first scan of a project that was
// previously scanned with an older version.
//
// If the global cache already has data for this project, migration is
// skipped (the legacy dir is left alone for manual cleanup).
func MigrateLegacyCache(projectRoot string) error {
	legacyDir := filepath.Join(projectRoot, ".patchflow", "cache")
	if _, err := os.Stat(legacyDir); err != nil {
		return nil // no legacy cache, nothing to migrate
	}

	newDir := ResolveCacheDir(projectRoot)
	// If new cache already exists, don't overwrite it
	if _, err := os.Stat(newDir); err == nil {
		return nil
	}

	// Create the new cache directory
	if err := os.MkdirAll(newDir, 0o755); err != nil {
		return err
	}

	// Move contents
	entries, err := os.ReadDir(legacyDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		src := filepath.Join(legacyDir, entry.Name())
		dst := filepath.Join(newDir, entry.Name())
		if err := os.Rename(src, dst); err != nil {
			// If rename fails (cross-device), fall back to copy + remove
			if err := copyDir(src, dst); err != nil {
				continue // best-effort migration
			}
			_ = os.RemoveAll(src)
		}
	}

	// Remove the now-empty legacy cache directory
	_ = os.Remove(legacyDir)
	return nil
}

// copyDir recursively copies a directory from src to dst.
func copyDir(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		// Single file
		data, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, data, info.Mode())
	}
	if err := os.MkdirAll(dst, info.Mode()); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := copyDir(filepath.Join(src, entry.Name()), filepath.Join(dst, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}
