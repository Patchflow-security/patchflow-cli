// Package incremental tracks file hashes between scans so that only changed
// files need to be re-scanned. State is persisted as JSON under
// .patchflow/cache/sast_state.json.
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

	"github.com/patchflow/patchflow-cli/internal/ignore"
)

// maxFileSize matches the scanner limit (2MB). Files larger than this are
// skipped during traversal to avoid hashing large generated or vendored files.
const maxFileSize int64 = 2 * 1024 * 1024

// skipDirs are directory basenames that are never traversed. These match the
// directories skipped by the embedded scanners.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true,
	"build": true, "__pycache__": true, ".patchflow": true,
}

// stateFile is the on-disk JSON representation of State.
type stateFile struct {
	Files     map[string]string `json:"files"`
	UpdatedAt string            `json:"updated_at"`
}

// State records SHA256 hashes for files between scans. The zero value is a
// valid empty state in which every file is considered changed.
type State struct {
	root   string
	files  map[string]string // relative path -> hex sha256
}

// statePath returns the absolute path to the persisted state file for rootDir.
func statePath(rootDir string) string {
	return filepath.Join(rootDir, ".patchflow", "cache", "sast_state.json")
}

// LoadState reads the persisted state for rootDir. If the state file is
// missing or corrupted, an empty State is returned so that the first run (or
// a run after corruption) treats every file as changed.
func LoadState(rootDir string) *State {
	s := &State{root: rootDir, files: map[string]string{}}

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
	s.files = sf.Files
	return s
}

// SaveState writes the current state to .patchflow/cache/sast_state.json,
// creating the cache directory if necessary.
func (s *State) SaveState(rootDir string) error {
	cacheDir := filepath.Join(rootDir, ".patchflow", "cache")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	sf := stateFile{
		Files:     s.files,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}
	if err := os.WriteFile(statePath(rootDir), data, 0644); err != nil {
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
// differs from the current content. The os.FileInfo is used to short-circuit
// unchanged files by size before hashing when no prior hash exists.
func (s *State) HasChanged(path string, info os.FileInfo) bool {
	rel, err := filepath.Rel(s.root, path)
	if err != nil {
		return true
	}
	rel = filepath.ToSlash(rel)

	if info.Size() > maxFileSize {
		// Large files are skipped by scanners; treat as unchanged so they
		// don't force re-scans, but they won't be in the changed set either.
		return false
	}

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

// UpdateHashFromInfo computes the SHA256 hash of the file and records it.
// This is used after scanning to update the incremental state.
func (s *State) UpdateHashFromInfo(path string, info os.FileInfo) {
	if info.Size() > maxFileSize {
		return
	}
	hash, err := hashFile(path)
	if err != nil {
		return
	}
	s.UpdateHash(path, hash)
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
