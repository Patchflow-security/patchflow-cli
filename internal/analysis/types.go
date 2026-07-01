// Package analysis defines the core types shared across all PatchFlow analyzers.
// These types are the lingua franca between SCA, SAST, reachability, risk scoring,
// and report generation. Every analyzer produces Findings; every renderer consumes them.
package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"time"
)

// Severity represents the severity level of a finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Confidence represents how certain an analyzer is about a finding.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// FindingType categorizes what kind of issue a Finding represents.
type FindingType string

const (
	TypeSCA            FindingType = "sca"
	TypeSAST           FindingType = "sast"
	TypeSecret         FindingType = "secret"
	TypeIaC            FindingType = "iac"
	TypeLicense        FindingType = "license"
	TypeBreakingChange FindingType = "breaking_change"
)

// ReachabilityStatus indicates whether vulnerable code is actually used.
type ReachabilityStatus string

const (
	ReachabilityHigh    ReachabilityStatus = "high"    // directly imported or invoked
	ReachabilityMedium  ReachabilityStatus = "medium"  // direct dependency, possible runtime usage
	ReachabilityLow     ReachabilityStatus = "low"     // transitive dependency, no direct usage
	ReachabilityNone    ReachabilityStatus = "none"    // not present in dependency graph
	ReachabilityUnknown ReachabilityStatus = "unknown" // analysis incomplete
)

// Finding is the normalized output of any analyzer.
type Finding struct {
	ID             string      `json:"id"`
	Type           FindingType `json:"type"`
	Analyzer       string      `json:"analyzer"`
	Severity       Severity    `json:"severity"`
	Confidence     Confidence  `json:"confidence"`
	Title          string      `json:"title"`
	Description    string      `json:"description,omitempty"`
	FilePath       string      `json:"file_path,omitempty"`
	LineStart      int         `json:"line_start,omitempty"`
	LineEnd        int         `json:"line_end,omitempty"`
	PackageName    string      `json:"package_name,omitempty"`
	PackageVersion string      `json:"package_version,omitempty"`
	FixedVersion   string      `json:"fixed_version,omitempty"`
	CVEID          string      `json:"cve_id,omitempty"`
	CWEID          string      `json:"cwe_id,omitempty"`
	AdvisoryURL    string      `json:"advisory_url,omitempty"`
	RuleID         string      `json:"rule_id,omitempty"`
	Evidence       string      `json:"evidence,omitempty"`
	Recommendation string      `json:"recommendation,omitempty"`

	// Reachability fields (populated by the reachability analyzer for SCA findings).
	Reachability           ReachabilityStatus `json:"reachability,omitempty"`
	ReachabilityConfidence Confidence         `json:"reachability_confidence,omitempty"`
	ReachabilityEvidence   []string           `json:"reachability_evidence,omitempty"`

	// Stable fingerprints used for baseline comparison and deduplication.
	// The semantic fingerprint is line-number independent so that findings
	// survive code reformatting and minor edits. The location fingerprint is
	// a coarser key that includes the line for legacy compatibility.
	SemanticFingerprint string `json:"semantic_fingerprint,omitempty"`
	LocationFingerprint string `json:"location_fingerprint,omitempty"`

	// Lifecycle
	DetectedAt time.Time `json:"detected_at"`
}

// Ecosystem represents a package ecosystem.
type Ecosystem string

const (
	EcosystemGo        Ecosystem = "Go"
	EcosystemNPM       Ecosystem = "npm"
	EcosystemPyPI      Ecosystem = "PyPI"
	EcosystemCargo     Ecosystem = "crates.io"
	EcosystemRubyGems  Ecosystem = "RubyGems"
	EcosystemPackagist Ecosystem = "Packagist"
	EcosystemMaven     Ecosystem = "Maven"
	EcosystemHelm      Ecosystem = "Helm"
)

// Dependency represents a single package dependency parsed from a manifest or lockfile.
type Dependency struct {
	Name         string    `json:"name"`
	Version      string    `json:"version"`
	Ecosystem    Ecosystem `json:"ecosystem"`
	ManifestPath string    `json:"manifest_path"`
	IsDirect     bool      `json:"is_direct"`
	IsDev        bool      `json:"is_dev,omitempty"`
	IsRoot       bool      `json:"is_root,omitempty"`
	License      string    `json:"license,omitempty"`
	Repository   string    `json:"repository,omitempty"`
}

// AnalysisResult is the complete output of an analysis run.
type AnalysisResult struct {
	ScanID         string          `json:"scan_id"`
	ProjectRoot    string          `json:"project_root"`
	Branch         string          `json:"branch"`
	CommitSHA      string          `json:"commit_sha"`
	BaseBranch     string          `json:"base_branch"`
	StartedAt      time.Time       `json:"started_at"`
	CompletedAt    time.Time       `json:"completed_at"`
	Findings       []Finding       `json:"findings"`
	Dependencies   []Dependency    `json:"dependencies"`
	LicenseSummary *LicenseSummary `json:"license_summary,omitempty"`
	RiskScore      int             `json:"risk_score"`
	RiskLevel      string          `json:"risk_level"`
	FilesChanged   int             `json:"files_changed"`
	AddedLines     int             `json:"added_lines"`
	DeletedLines   int             `json:"deleted_lines"`
	Manifests      []string        `json:"manifests"`
	Analyzers      []string        `json:"analyzers"`
	EngineTimings  []EngineTiming  `json:"engine_timings,omitempty"`

	// Monorepo metadata — describes the detected monorepo structure (if any).
	MonorepoTool    string   `json:"monorepo_tool,omitempty"`
	MonorepoMembers []string `json:"monorepo_members,omitempty"`

	// Scan metadata — describes how the scan was run so reports are
	// self-describing and reproducible in CI.
	Profile           string        `json:"profile,omitempty"`            // quick, standard, deep
	Mode              string        `json:"mode,omitempty"`               // full, changed, since
	Baseline          string        `json:"baseline,omitempty"`           // baseline name when --new-only
	NewOnly           bool          `json:"new_only,omitempty"`           // whether --new-only was active
	SinceRef          string        `json:"since_ref,omitempty"`          // git ref passed to --since
	GovernanceProfile string        `json:"governance_profile,omitempty"` // dev, pr, ci, audit
	Duration          time.Duration `json:"duration,omitempty"`           // total scan duration
	ExitCode          int           `json:"exit_code,omitempty"`          // final exit code (0=success, 1=findings, ...)
	Version           string        `json:"version,omitempty"`            // CLI version
	ChangedFiles      []string      `json:"changed_files,omitempty"`      // filtered changed-file inventory
}

// LicenseSummary captures dependency license coverage in scan reports without
// coupling the core analysis package to the SBOM package.
type LicenseSummary struct {
	Total       int            `json:"total"`
	WithLicense int            `json:"with_license"`
	NoLicense   int            `json:"no_license"`
	ByCategory  map[string]int `json:"by_category,omitempty"`
	ByRisk      map[string]int `json:"by_risk,omitempty"`
}

// EngineTiming records the duration a specific scanner engine took.
type EngineTiming struct {
	Engine   string        `json:"engine"`
	Duration time.Duration `json:"duration"`
	Findings int           `json:"findings"`
}

// SeverityWeight returns a numeric weight for a severity level used in risk scoring.
func SeverityWeight(s Severity) int {
	switch s {
	case SeverityCritical:
		return 100
	case SeverityHigh:
		return 75
	case SeverityMedium:
		return 50
	case SeverityLow:
		return 25
	case SeverityInfo:
		return 10
	default:
		return 0
	}
}

// SeverityOrder returns a comparable rank for sorting (higher = more severe).
func SeverityOrder(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// ReachabilityWeight returns a multiplier for reachability in risk scoring.
// Reachable vulnerabilities are weighted higher than unreachable ones.
func ReachabilityWeight(r ReachabilityStatus) float64 {
	switch r {
	case ReachabilityHigh:
		return 1.0
	case ReachabilityMedium:
		return 0.7
	case ReachabilityLow:
		return 0.3
	case ReachabilityNone:
		return 0.0
	case ReachabilityUnknown:
		return 0.5
	default:
		return 0.5
	}
}

// NormalizePath canonicalizes a file path for fingerprinting: it converts
// OS-specific separators to forward slashes, cleans redundant elements, and
// lowercases the result so that path comparisons are stable across platforms
// and case-insensitive filesystems.
func NormalizePath(p string) string {
	if p == "" {
		return ""
	}
	// Replace backslashes first so Windows-style paths are normalized even
	// when the fingerprint is computed on a Unix host (e.g. in CI scanning a
	// checked-out Windows repo).
	cleaned := strings.ReplaceAll(p, "\\", "/")
	cleaned = filepath.Clean(cleaned)
	cleaned = filepath.ToSlash(cleaned)
	return strings.ToLower(cleaned)
}

// NormalizeSnippet canonicalizes a code/evidence snippet for fingerprinting:
// it trims surrounding whitespace, collapses internal whitespace runs to a
// single space, and lowercases the result. This makes fingerprints resilient
// to indentation changes and minor reformatting.
func NormalizeSnippet(s string) string {
	if s == "" {
		return ""
	}
	s = strings.TrimSpace(s)
	// Collapse all internal whitespace (spaces, tabs, newlines) to single spaces.
	var sb strings.Builder
	sb.Grow(len(s))
	prevSpace := false
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			if !prevSpace {
				sb.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		sb.WriteRune(r)
		prevSpace = false
	}
	return strings.ToLower(sb.String())
}

// shortHash returns the first 16 hex characters of the SHA-256 digest of the
// given input. 16 hex chars (64 bits) give a collision space of ~1.8e19 which
// is more than sufficient for finding deduplication within a single scan.
func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:16]
}

// ComputeSemanticFingerprint builds a line-number-independent fingerprint for a
// finding. The key ingredients are the rule id, analyzer/scanner, normalized
// file path, normalized evidence snippet, and sink/source where available.
// Two findings with the same semantic fingerprint are considered the same
// underlying issue even if the surrounding code moved.
func ComputeSemanticFingerprint(f Finding) string {
	var parts []string
	if f.RuleID != "" {
		parts = append(parts, f.RuleID)
	} else {
		parts = append(parts, string(f.Type)+":"+f.Analyzer)
	}
	parts = append(parts, f.Analyzer)
	parts = append(parts, NormalizePath(f.FilePath))
	// SCA findings are identified by package + advisory, not by snippet.
	if f.Type == TypeSCA {
		if f.PackageName != "" {
			parts = append(parts, f.PackageName+"@"+f.PackageVersion)
		}
		if f.CVEID != "" {
			parts = append(parts, f.CVEID)
		} else if f.AdvisoryURL != "" {
			parts = append(parts, f.AdvisoryURL)
		}
	} else {
		// SAST/secret findings: use the normalized evidence/snippet so the
		// fingerprint is stable across line shifts.
		snippet := f.Evidence
		if snippet == "" {
			snippet = f.Title
		}
		parts = append(parts, NormalizeSnippet(snippet))
	}
	return shortHash(strings.Join(parts, "|"))
}

// ComputeLocationFingerprint builds a coarser, location-aware fingerprint that
// includes the line number. This is used as a fallback / legacy compatibility
// key and for SARIF partialFingerprints.
func ComputeLocationFingerprint(f Finding) string {
	var parts []string
	if f.RuleID != "" {
		parts = append(parts, f.RuleID)
	} else {
		parts = append(parts, string(f.Type)+":"+f.Analyzer)
	}
	parts = append(parts, NormalizePath(f.FilePath))
	parts = append(parts, NormalizeSnippet(f.Evidence))
	parts = append(parts, f.Analyzer)
	if f.LineStart > 0 {
		parts = append(parts, "L"+itoa(f.LineStart))
	}
	return shortHash(strings.Join(parts, "|"))
}

// PopulateFingerprints sets SemanticFingerprint and LocationFingerprint on
// every finding in the slice (in place) when they are not already set. This is
// the central post-processing step run after all analyzers have produced their
// findings and before reports/baselines are generated.
func PopulateFingerprints(findings []Finding) {
	for i := range findings {
		if findings[i].SemanticFingerprint == "" {
			findings[i].SemanticFingerprint = ComputeSemanticFingerprint(findings[i])
		}
		if findings[i].LocationFingerprint == "" {
			findings[i].LocationFingerprint = ComputeLocationFingerprint(findings[i])
		}
	}
}

// itoa is a small allocation-free int-to-string helper used by the fingerprint
// builders to avoid pulling in strconv for a hot path.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
