// Package incremental tracks file hashes between scans so that only changed
// files need to be re-scanned. State is persisted as JSON in a global
// XDG-compliant cache location (resolved via cacheutil) at
// ~/.cache/patchflow/<project-hash>/sast_state.json.
package incremental

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/cacheutil"
	"github.com/Patchflow-security/patchflow-cli/internal/ignore"
)

// maxFileSize matches the scanner limit (2MB). Files larger than this are
// skipped during traversal to avoid hashing large generated or vendored files.
const maxFileSize int64 = 2 * 1024 * 1024

// skipDirs are directory basenames that are never traversed. These match the
// directories skipped by the embedded scanners.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true,
	"build": true, "__pycache__": true, ".patchflow": true,
	// Third-party library directories
	"lib": true, "libs": true, "wwwroot": true, "third_party": true,
	"thirdparty": true, "external": true, "deps": true,
	"bower_components": true, "jspm_packages": true, "webjars": true,
	"packages": true, "Content": true, "Scripts": true,
}

// stateFile is the on-disk JSON representation of State.
type stateFile struct {
	Files     map[string]string `json:"files"`
	Meta      map[string]fileMeta `json:"meta,omitempty"`
	UpdatedAt string            `json:"updated_at"`
}

// fileMeta stores size and mod-time for a fast-path check that avoids
// hashing when both are unchanged.
type fileMeta struct {
	Size  int64  `json:"size"`
	Mtime int64  `json:"mtime"` // Unix nanoseconds
}

// State records SHA256 hashes for files between scans. The zero value is a
// valid empty state in which every file is considered changed.
type State struct {
	root   string
	files  map[string]string    // relative path -> hex sha256
	meta   map[string]fileMeta  // relative path -> size+mtime (fast-path)
}

// statePath returns the absolute path to the persisted state file for rootDir.
// The path is resolved via cacheutil to a global XDG-compliant location.
func statePath(rootDir string) string {
	return cacheutil.ResolveFile(rootDir, "sast_state.json")
}

// LoadState reads the persisted state for rootDir. If the state file is
// missing or corrupted, an empty State is returned so that the first run (or
// a run after corruption) treats every file as changed.
func LoadState(rootDir string) *State {
	s := &State{root: rootDir, files: map[string]string{}, meta: map[string]fileMeta{}}

	data, err := os.ReadFile(statePath(rootDir))
	if err != nil {
		// Missing file: first run, treat all files as changed.
		return s
	}

	var sf stateFile
	if err := json.Unmarshal(data, &sf); err != nil {
		// Corrupted file: treat all files as changed.
		return s
	}
	if sf.Files == nil {
		sf.Files = map[string]string{}
	}
	if sf.Meta == nil {
		sf.Meta = map[string]fileMeta{}
	}
	s.files = sf.Files
	s.meta = sf.Meta
	return s
}

// SaveState writes the current state to the global cache location,
// creating the cache directory if necessary.
func (s *State) SaveState(rootDir string) error {
	cacheDir := cacheutil.ResolveCacheDir(rootDir)
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	sf := stateFile{
		Files:     s.files,
		Meta:      s.meta,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}
	if err := os.WriteFile(statePath(rootDir), data, 0600); err != nil {
		return fmt.Errorf("failed to write state file: %w", err)
	}
	return nil
}

// hashFile computes the SHA256 hex digest of the file at path.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// HasChanged returns true if the file at path is new or its recorded hash
// differs from the current content. Uses a mtime+size fast-path to avoid
// hashing files that haven't been modified.
func (s *State) HasChanged(path string, info os.FileInfo) bool {
	rel, err := filepath.Rel(s.root, path)
	if err != nil {
		return true
	}
	rel = filepath.ToSlash(rel)

	if info.Size() > maxFileSize {
		return false
	}

	// Fast path: if size and mtime match the recorded values, the file is
	// unchanged. This avoids the expensive SHA256 hash for the vast majority
	// of files on incremental runs.
	if prev, ok := s.meta[rel]; ok {
		if prev.Size == info.Size() && prev.Mtime == info.ModTime().UnixNano() {
			// File is unchanged by mtime+size — still need to check if we
			// have a hash for it. If we do, it's definitely unchanged.
			if _, hasHash := s.files[rel]; hasHash {
				return false
			}
		}
	}

	// Slow path: hash the file to determine if content changed.
	hash, err := hashFile(path)
	if err != nil {
		return true
	}
	prev, ok := s.files[rel]
	if !ok || prev != hash {
		return true
	}
	return false
}

// UpdateHash records the SHA256 hash for a file. The path is normalized to a
// root-relative slash-separated path before storage.
func (s *State) UpdateHash(path, hash string) {
	rel, err := filepath.Rel(s.root, path)
	if err != nil {
		return
	}
	rel = filepath.ToSlash(rel)
	s.files[rel] = hash
}

// UpdateHashFromInfo computes the SHA256 hash of the file and records it
// along with its size and mtime for fast-path checking on the next run.
func (s *State) UpdateHashFromInfo(path string, info os.FileInfo) {
	if info.Size() > maxFileSize {
		return
	}
	hash, err := hashFile(path)
	if err != nil {
		return
	}
	s.UpdateHash(path, hash)

	// Record meta for fast-path on next run.
	rel, err := filepath.Rel(s.root, path)
	if err != nil {
		return
	}
	rel = filepath.ToSlash(rel)
	s.meta[rel] = fileMeta{
		Size:  info.Size(),
		Mtime: info.ModTime().UnixNano(),
	}
}

// shouldSkip reports whether a directory or file should be skipped during
// traversal based on the skipDirs set and the ignore matcher.
func shouldSkip(path string, info os.FileInfo, root string, ignoreMatcher *ignore.Matcher) bool {
	if info.IsDir() {
		if skipDirs[info.Name()] {
			return true
		}
		if ignoreMatcher != nil && !ignoreMatcher.IsEmpty() {
			if ignoreMatcher.Match(path, true) {
				return true
			}
		}
		return false
	}
	if ignoreMatcher != nil && !ignoreMatcher.IsEmpty() {
		if ignoreMatcher.Match(path, false) {
			return true
		}
	}
	return false
}

// walkFiles walks root and invokes fn for each non-skipped file. Directories in
// skipDirs or matched by ignoreMatcher are pruned via filepath.SkipDir.
func walkFiles(root string, ignoreMatcher *ignore.Matcher, fn func(path string, info os.FileInfo) error) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			if ignoreMatcher != nil && !ignoreMatcher.IsEmpty() {
				if ignoreMatcher.Match(path, true) {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if shouldSkip(path, info, root, ignoreMatcher) {
			return nil
		}
		if info.Size() > maxFileSize {
			return nil
		}
		return fn(path, info)
	})
}

// GetChangedFiles walks root and returns the list of files that are new or
// whose hash has changed since the last scan. Files larger than maxFileSize
// and files/directories matched by ignoreMatcher are excluded.
func (s *State) GetChangedFiles(root string, ignoreMatcher *ignore.Matcher) []string {
	var changed []string
	_ = walkFiles(root, ignoreMatcher, func(path string, info os.FileInfo) error {
		if s.HasChanged(path, info) {
			changed = append(changed, path)
		}
		return nil
	})
	return changed
}

// GetUnchangedFiles walks root and returns the list of files whose hash
// matches the recorded hash. Files larger than maxFileSize and files/directories
// matched by ignoreMatcher are excluded.
func (s *State) GetUnchangedFiles(root string, ignoreMatcher *ignore.Matcher) []string {
	var unchanged []string
	_ = walkFiles(root, ignoreMatcher, func(path string, info os.FileInfo) error {
		if !s.HasChanged(path, info) {
			unchanged = append(unchanged, path)
		}
		return nil
	})
	return unchanged
}

// PruneDeleted removes state entries for files that no longer exist on disk
// within root. It returns the number of entries removed.
func (s *State) PruneDeleted(root string, ignoreMatcher *ignore.Matcher) int {
	existing := map[string]bool{}
	_ = walkFiles(root, ignoreMatcher, func(path string, info os.FileInfo) error {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		existing[filepath.ToSlash(rel)] = true
		return nil
	})

	removed := 0
	for rel := range s.files {
		if !existing[rel] {
			delete(s.files, rel)
			removed++
		}
	}
	return removed
}
