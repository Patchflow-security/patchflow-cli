package frameworks

import (
	"os"
	"path/filepath"
	"strings"
)

// Detector probes a project root for framework signatures.
// It is safe for concurrent use after construction.
type Detector struct {
	signatures []Signature
}

// NewDetector creates a detector with all known framework signatures.
func NewDetector() *Detector {
	return &Detector{signatures: Signatures()}
}

// NewDetectorWithSignatures creates a detector with a custom signature set.
// Used in tests to probe a subset of frameworks.
func NewDetectorWithSignatures(sigs []Signature) *Detector {
	return &Detector{signatures: sigs}
}

// Detect probes root and returns frameworks whose minimum signal threshold
// is met. Confidence is the ratio of matched signals to total signals,
// clamped to [0.1, 1.0] once the threshold is reached.
func (d *Detector) Detect(root string) Result {
	var frameworks []Detection
	for _, sig := range d.signatures {
		matched, total := evalSignals(root, sig.Signals)
		if len(matched) < sig.MinSignals || total == 0 {
			continue
		}
		confidence := float64(len(matched)) / float64(total)
		if confidence < 0.1 {
			confidence = 0.1
		}
		if confidence > 1.0 {
			confidence = 1.0
		}
		frameworks = append(frameworks, Detection{
			Name:       sig.Name,
			Language:   sig.Language,
			Confidence: roundConf(confidence),
			Matched:    matched,
		})
	}
	return Result{Frameworks: frameworks}
}

// evalSignals evaluates each signal against root and returns the list of
// human-readable matched descriptions plus the total number of signals.
func evalSignals(root string, signals []Signal) (matched []string, total int) {
	total = len(signals)
	for _, s := range signals {
		if evalSignal(root, s) {
			matched = append(matched, describeSignal(s))
		}
	}
	return matched, total
}

func evalSignal(root string, s Signal) bool {
	switch s.Kind {
	case SignalFilePresent:
		_, err := os.Stat(filepath.Join(root, s.Path))
		return err == nil
	case SignalFileContains:
		return fileContains(filepath.Join(root, s.Path), s.Contains)
	case SignalGlobMatch:
		matches, _ := filepath.Glob(filepath.Join(root, s.Glob))
		// filepath.Glob does not traverse '**'. Support a single '**' segment
		// by falling back to a recursive walk when no direct match is found.
		if len(matches) > 0 {
			return true
		}
		return globRecursive(root, s.Glob)
	}
	return false
}

// globRecursive handles globs containing '**' by walking the tree and matching
// the pattern with filepath.Match on the path relative to root after stripping
// the '**' segment. This is a minimal double-star matcher sufficient for the
// signature patterns used here (e.g. "app/views/**/*.erb").
func globRecursive(root, pattern string) bool {
	if !strings.Contains(pattern, "**") {
		matches, _ := filepath.Glob(filepath.Join(root, pattern))
		return len(matches) > 0
	}
	// Split into the part before '**' and the part after '**'.
	parts := strings.SplitN(pattern, "**", 2)
	before := strings.Trim(filepath.ToSlash(parts[0]), "/")
	after := strings.Trim(filepath.ToSlash(parts[1]), "/")

	base := root
	if before != "" {
		base = filepath.Join(root, filepath.FromSlash(before))
	}
	found := false
	_ = filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(base, path)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if after == "" {
			found = true
			return filepath.SkipDir
		}
		ok, _ := filepath.Match(after, filepath.Base(rel))
		if ok {
			found = true
			return filepath.SkipDir
		}
		// Match against the full relative tail (e.g. "views/users/show.erb").
		ok, _ = filepath.Match(after, rel)
		if ok {
			found = true
			return filepath.SkipDir
		}
		return nil
	})
	return found
}

func fileContains(path, needle string) bool {
	if needle == "" {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(data)), strings.ToLower(needle))
}

func describeSignal(s Signal) string {
	switch s.Kind {
	case SignalFilePresent:
		return "exists: " + s.Path
	case SignalFileContains:
		return s.Path + " contains \"" + s.Contains + "\""
	case SignalGlobMatch:
		return "glob: " + s.Glob
	}
	return ""
}

func roundConf(c float64) float64 {
	// Round to 2 decimal places for stable output.
	return float64(int(c*100+0.5)) / 100
}
