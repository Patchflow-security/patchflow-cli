// Package benchmark orchestrates reproducible scanner benchmarks against
// open-source repositories. It runs PatchFlow (and optional comparison tools)
// against a declared suite of repos, collects metrics (LOC, duration, findings
// by severity/confidence, SARIF validity, exit codes, cache cold/warm timing),
// and computes precision, recall, and noise rate.
//
// Design principles:
//   - PatchFlow is invoked as a real subprocess so the benchmark measures
//     actual CLI behavior (startup, exit codes, SARIF generation) rather than
//     internal APIs that may diverge from the shipped binary.
//   - Comparison tools (semgrep, trivy, gitleaks, osv-scanner, codeql) are
//     invoked the same way, with their native JSON/SARIF output captured.
//   - Repos are either cloned from a URL or used from a local path. Clones are
//     shallow and pinned to a ref/commit for reproducibility.
//   - Responsible disclosure: findings from active/maintained repos are never
//     published in detail. Only intentionally-vulnerable and historical repos
//     expose per-finding detail in the public report.
package benchmark

import "time"

// RepoType classifies a benchmark repository by its purpose.
type RepoType string

const (
	// RepoIntentionallyVulnerable: safe, designed-for-testing projects
	// (Juice Shop, WebGoat, DVWA, NodeGoat, RailsGoat, ...). All findings
	// may be published.
	RepoIntentionallyVulnerable RepoType = "intentionally-vulnerable"
	// RepoHistoricalVulnerable: old tagged releases of real projects with
	// known CVEs. Known/historical issues may be published.
	RepoHistoricalVulnerable RepoType = "historical-vulnerable"
	// RepoCleanRealWorld: reputable, active, mature projects used to measure
	// false positives and performance. Findings are anonymized / responsibly
	// disclosed — never published in detail.
	RepoCleanRealWorld RepoType = "clean-real-world"
)

// Expected describes what a repo is expected to demonstrate.
type Expected string

const (
	ExpectedHighVulnDensity    Expected = "high-vulnerability-density"
	ExpectedKnownCVEValidation Expected = "known-cve-validation"
	ExpectedLowFalsePositive   Expected = "low-false-positive-rate"
)

// Config is the top-level benchmark suite definition (benchmark.yaml).
type Config struct {
	Suite      string     `yaml:"suite"`
	Date       string     `yaml:"date"`
	PatchFlow  ToolConfig `yaml:"patchflow"`
	Tools      []string   `yaml:"tools"`
	Repos      []RepoSpec `yaml:"repos"`
	ResultsDir string     `yaml:"results_dir,omitempty"`
	WorkDir    string     `yaml:"work_dir,omitempty"`
}

// ToolConfig configures how PatchFlow itself is invoked during the benchmark.
type ToolConfig struct {
	Binary    string   `yaml:"binary,omitempty"`  // path to patchflow binary (default: "patchflow")
	Profile   string   `yaml:"profile,omitempty"` // scan profile: quick, standard, deep
	FailOn    string   `yaml:"fail_on,omitempty"` // severity threshold for exit code 1
	NoReach   bool     `yaml:"no_reachability,omitempty"`
	ExtraArgs []string `yaml:"extra_args,omitempty"`
}

// RepoSpec describes a single repository to benchmark.
type RepoSpec struct {
	Name     string   `yaml:"name"`
	Type     RepoType `yaml:"type"`
	Language string   `yaml:"language"`
	Expected Expected `yaml:"expected"`
	URL      string   `yaml:"url,omitempty"`  // git URL to clone (shallow)
	Ref      string   `yaml:"ref,omitempty"`  // branch, tag, or commit to pin
	Path     string   `yaml:"path,omitempty"` // local path (alternative to URL)
	// ExpectedFindings is an optional curated list of rule IDs / CVE IDs that
	// are known to be present. Used to compute recall. For intentionally
	// vulnerable and historical repos this should be populated; for clean
	// repos it is typically empty (recall is not meaningful there).
	ExpectedFindings []string `yaml:"expected_findings,omitempty"`
	// ExpectedFrameworkFindings is the framework-pack-only recall set. It
	// matches only findings whose analyzer is "framework-<pack>".
	ExpectedFrameworkFindings []string `yaml:"expected_framework_findings,omitempty"`
	// PublishDetail controls whether per-finding detail is written to the
	// public report. Defaults to true for intentionally-vulnerable and
	// historical, false for clean-real-world. Override per-repo if needed.
	PublishDetail *bool `yaml:"publish_detail,omitempty"`
}

// Metrics holds the per-repo measurements collected during a benchmark run.
type Metrics struct {
	RepoName          string         `json:"repo_name"`
	RepoType          RepoType       `json:"repo_type"`
	Language          string         `json:"language"`
	LOC               int            `json:"loc"`
	FilesScanned      int            `json:"files_scanned"`
	ScanDuration      time.Duration  `json:"scan_duration"`
	ColdDuration      time.Duration  `json:"cold_duration"`
	WarmDuration      time.Duration  `json:"warm_duration"`
	CacheSpeedup      float64        `json:"cache_speedup_pct"` // (cold-warm)/cold * 100
	EnginesUsed       []string       `json:"engines_used"`
	TotalFindings     int            `json:"total_findings"`
	BySeverity        map[string]int `json:"by_severity"`
	ByConfidence      map[string]int `json:"by_confidence"`
	ByType            map[string]int `json:"by_type"`
	FrameworkFindings int            `json:"framework_findings"`
	ByFramework       map[string]int `json:"by_framework,omitempty"`
	NewAfterBaseline  int            `json:"new_after_baseline,omitempty"`
	SARIFGenerated    bool           `json:"sarif_generated"`
	SARIFValid        bool           `json:"sarif_valid"`
	ExitCode          int            `json:"exit_code"`
	MemoryMB          int            `json:"memory_mb,omitempty"`
	// Triaged counts (populated when a review file is supplied or expected
	// findings are matched). Unknown = total - truePositives - falsePositives.
	TruePositives  int     `json:"true_positives,omitempty"`
	FalsePositives int     `json:"false_positives,omitempty"`
	Unknown        int     `json:"unknown,omitempty"`
	Precision      float64 `json:"precision,omitempty"`
	Recall         float64 `json:"recall,omitempty"`
	NoiseRate      float64 `json:"noise_rate,omitempty"`
	// Per-tool comparison counts (tool name -> finding count).
	ToolFindings map[string]int `json:"tool_findings,omitempty"`
	// Expected findings detected (for recall against ExpectedFindings).
	ExpectedDetected          []string `json:"expected_detected,omitempty"`
	ExpectedMissed            []string `json:"expected_missed,omitempty"`
	ExpectedFrameworkDetected []string `json:"expected_framework_detected,omitempty"`
	ExpectedFrameworkMissed   []string `json:"expected_framework_missed,omitempty"`
	FrameworkRecall           float64  `json:"framework_recall,omitempty"`
}

// RepoResult is the full result for one repo across all tools.
type RepoResult struct {
	Repo         RepoSpec              `json:"repo"`
	PatchFlow    Metrics               `json:"patchflow"`
	Tools        map[string]ToolResult `json:"tools,omitempty"`
	SARIFPath    string                `json:"sarif_path,omitempty"`
	JSONPath     string                `json:"json_path,omitempty"`
	MarkdownPath string                `json:"markdown_path,omitempty"`
	Error        string                `json:"error,omitempty"`
}

// ToolResult captures the output of a comparison tool on one repo.
type ToolResult struct {
	Tool       string        `json:"tool"`
	Findings   int           `json:"findings"`
	Duration   time.Duration `json:"duration"`
	ExitCode   int           `json:"exit_code"`
	OutputPath string        `json:"output_path,omitempty"`
	Available  bool          `json:"available"`
	Error      string        `json:"error,omitempty"`
}

// Summary is the aggregate benchmark result written to summary.json.
type Summary struct {
	Suite                  string         `json:"suite"`
	Date                   string         `json:"date"`
	PatchFlowVersion       string         `json:"patchflow_version"`
	ReposScanned           int            `json:"repos_scanned"`
	TotalLOC               int            `json:"total_loc"`
	TotalFindings          int            `json:"total_findings"`
	ConfirmedTruePos       int            `json:"confirmed_true_positives"`
	FalsePositives         int            `json:"false_positives"`
	UnknownUnreviewed      int            `json:"unknown_unreviewed"`
	AvgScanTime            time.Duration  `json:"avg_scan_time"`
	CacheWarmSpeedup       float64        `json:"cache_warm_speedup_pct"`
	SARIFValidCount        int            `json:"sarif_valid_count"`
	SARIFTotalCount        int            `json:"sarif_total_count"`
	AvgPrecision           float64        `json:"avg_precision,omitempty"`
	AvgRecall              float64        `json:"avg_recall,omitempty"`
	AvgFrameworkRecall     float64        `json:"avg_framework_recall,omitempty"`
	TotalFrameworkFindings int            `json:"total_framework_findings,omitempty"`
	AvgNoiseRate           float64        `json:"avg_noise_rate,omitempty"`
	PerRepo                []Metrics      `json:"per_repo"`
	ToolComparison         map[string]int `json:"tool_comparison,omitempty"` // tool -> total findings across repos
	Hardware               string         `json:"hardware,omitempty"`
	Limitations            []string       `json:"limitations,omitempty"`
}
