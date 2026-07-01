package frameworks

import (
	"github.com/Patchflow-security/patchflow-cli/internal/frameworks"
)

// SelectionConfig controls which framework packs are activated for a scan.
// It mirrors the user-facing `frameworks:` config block and the
// --framework / --disable-framework CLI flags.
type SelectionConfig struct {
	// AutoDetect enables framework detection. When true, packs are activated
	// for every framework detected by the detector. Default: true.
	AutoDetect bool
	// AutoDetectSet reports whether AutoDetect was explicitly configured. This
	// lets callers merge config layers without confusing an unset zero value
	// with an intentional "false".
	AutoDetectSet bool
	// Enabled is an explicit allowlist of framework names to activate
	// regardless of detection. Useful for monorepos or forced scans.
	Enabled []string
	// Disabled is a blocklist of framework names to never activate, even if
	// detected or explicitly enabled. Takes precedence over Enabled and
	// AutoDetect.
	Disabled []string
}

// DefaultSelectionConfig returns the default selection config: auto-detect on,
// no explicit enable/disable.
func DefaultSelectionConfig() SelectionConfig {
	return SelectionConfig{AutoDetect: true, AutoDetectSet: true}
}

// MergeSelectionConfig overlays the values in overlay onto base.
//
// AutoDetect is replaced only when explicitly set on overlay. Enabled and
// Disabled lists are appended uniquely so config can be layered across
// project defaults, YAML policy, and CLI flags.
func MergeSelectionConfig(base, overlay SelectionConfig) SelectionConfig {
	out := base
	if overlay.AutoDetectSet {
		out.AutoDetect = overlay.AutoDetect
		out.AutoDetectSet = true
	}
	out.Enabled = appendUniqueStrings(out.Enabled, overlay.Enabled...)
	out.Disabled = appendUniqueStrings(out.Disabled, overlay.Disabled...)
	return out
}

func appendUniqueStrings(dst []string, items ...string) []string {
	if len(items) == 0 {
		return dst
	}
	seen := make(map[string]bool, len(dst))
	for _, item := range dst {
		seen[item] = true
	}
	for _, item := range items {
		if item == "" || seen[item] {
			continue
		}
		dst = append(dst, item)
		seen[item] = true
	}
	return dst
}

// Selection is the resolved set of packs to activate for a scan, plus the
// detections that drove the decision (for reporting and explain output).
type Selection struct {
	Packs      []Pack
	Detections []frameworks.Detection
}

// Names returns the names of the selected packs, sorted.
func (s Selection) Names() []string {
	names := make([]string, 0, len(s.Packs))
	for _, p := range s.Packs {
		names = append(names, p.Name())
	}
	return names
}

// Loader resolves which packs to activate given a registry, a detector
// result, and a selection config.
type Loader struct {
	registry *Registry
}

// NewLoader creates a loader bound to a pack registry.
func NewLoader(reg *Registry) *Loader {
	return &Loader{registry: reg}
}

// Select resolves the active packs. The resolution order is:
//  1. Start from detections (if AutoDetect) or empty.
//  2. Merge in explicitly Enabled names.
//  3. Remove Disabled names.
//  4. Keep only names that have a registered pack.
//
// The returned Selection includes the detections so callers can surface
// framework context in reports and explain output.
func (l *Loader) Select(detections frameworks.Result, cfg SelectionConfig) Selection {
	want := map[string]bool{}

	if cfg.AutoDetect {
		for _, d := range detections.Frameworks {
			want[string(d.Name)] = true
		}
	}
	for _, n := range cfg.Enabled {
		want[n] = true
	}
	for _, n := range cfg.Disabled {
		delete(want, n)
	}

	var packs []Pack
	var dets []frameworks.Detection
	for _, d := range detections.Frameworks {
		if want[string(d.Name)] {
			dets = append(dets, d)
		}
	}
	// Add explicitly-enabled packs that were not detected (no detection entry).
	for name := range want {
		if l.registry.Has(name) {
			continue
		}
		// Unknown framework name requested: ignore silently. The detector is
		// the source of truth for what exists; an unknown name is a user typo
		// or a pack that isn't shipped in this build.
	}

	for _, p := range l.registry.All() {
		if want[p.Name()] {
			packs = append(packs, p)
		}
	}

	return Selection{Packs: packs, Detections: dets}
}

// SelectForRoot is a convenience that runs the detector against root and then
// resolves the selection.
func (l *Loader) SelectForRoot(root string, cfg SelectionConfig, detector *frameworks.Detector) Selection {
	detections := frameworks.Result{}
	if detector != nil {
		detections = detector.Detect(root)
	}
	return l.Select(detections, cfg)
}
