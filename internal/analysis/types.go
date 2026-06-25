// Package analysis defines the core types shared across all PatchFlow analyzers.
// These types are the lingua franca between SCA, SAST, reachability, risk scoring,
// and report generation. Every analyzer produces Findings; every renderer consumes them.
package analysis

import "time"

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
	ReachabilityNone    ReachabilityStatus = "none"     // not present in dependency graph
	ReachabilityUnknown ReachabilityStatus = "unknown" // analysis incomplete
)

// Finding is the normalized output of any analyzer.
type Finding struct {
	ID             string              `json:"id"`
	Type           FindingType         `json:"type"`
	Analyzer       string              `json:"analyzer"`
	Severity       Severity            `json:"severity"`
	Confidence     Confidence          `json:"confidence"`
	Title          string              `json:"title"`
	Description    string              `json:"description,omitempty"`
	FilePath       string              `json:"file_path,omitempty"`
	LineStart      int                 `json:"line_start,omitempty"`
	LineEnd        int                 `json:"line_end,omitempty"`
	PackageName    string              `json:"package_name,omitempty"`
	PackageVersion string              `json:"package_version,omitempty"`
	FixedVersion   string              `json:"fixed_version,omitempty"`
	CVEID          string              `json:"cve_id,omitempty"`
	CWEID          string              `json:"cwe_id,omitempty"`
	AdvisoryURL    string              `json:"advisory_url,omitempty"`
	RuleID         string              `json:"rule_id,omitempty"`
	Evidence       string              `json:"evidence,omitempty"`
	Recommendation string              `json:"recommendation,omitempty"`

	// Reachability fields (populated by the reachability analyzer for SCA findings).
	Reachability          ReachabilityStatus `json:"reachability,omitempty"`
	ReachabilityConfidence Confidence        `json:"reachability_confidence,omitempty"`
	ReachabilityEvidence  []string           `json:"reachability_evidence,omitempty"`

	// Lifecycle
	DetectedAt time.Time `json:"detected_at"`
}

// Ecosystem represents a package ecosystem.
type Ecosystem string

const (
	EcosystemGo       Ecosystem = "Go"
	EcosystemNPM      Ecosystem = "npm"
	EcosystemPyPI     Ecosystem = "PyPI"
	EcosystemCargo    Ecosystem = "crates.io"
	EcosystemRubyGems Ecosystem = "RubyGems"
	EcosystemPackagist Ecosystem = "Packagist"
	EcosystemMaven    Ecosystem = "Maven"
)

// Dependency represents a single package dependency parsed from a manifest or lockfile.
type Dependency struct {
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	Ecosystem   Ecosystem `json:"ecosystem"`
	ManifestPath string   `json:"manifest_path"`
	IsDirect    bool      `json:"is_direct"`
	IsDev       bool      `json:"is_dev,omitempty"`
	License     string    `json:"license,omitempty"`
}

// AnalysisResult is the complete output of an analysis run.
type AnalysisResult struct {
	ScanID         string    `json:"scan_id"`
	ProjectRoot    string    `json:"project_root"`
	Branch         string    `json:"branch"`
	CommitSHA      string    `json:"commit_sha"`
	BaseBranch     string    `json:"base_branch"`
	StartedAt      time.Time `json:"started_at"`
	CompletedAt    time.Time `json:"completed_at"`
	Findings       []Finding `json:"findings"`
	Dependencies   []Dependency `json:"dependencies"`
	RiskScore      int       `json:"risk_score"`
	RiskLevel      string    `json:"risk_level"`
	FilesChanged   int       `json:"files_changed"`
	AddedLines     int       `json:"added_lines"`
	DeletedLines   int       `json:"deleted_lines"`
	Manifests      []string  `json:"manifests"`
	Analyzers      []string  `json:"analyzers"`
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
		return 0.4
	case ReachabilityNone:
		return 0.1
	case ReachabilityUnknown:
		return 0.5
	default:
		return 0.5
	}
}
