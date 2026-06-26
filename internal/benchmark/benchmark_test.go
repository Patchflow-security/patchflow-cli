package benchmark

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "benchmark.yaml")
	cfgYAML := `
suite: test-suite
date: "2026-06-26"
patchflow:
  binary: ./patchflow
  profile: standard
  fail_on: high
tools:
  - semgrep
  - gitleaks
repos:
  - name: juice-shop
    type: intentionally-vulnerable
    language: javascript
    expected: high-vulnerability-density
    url: https://github.com/juice-shop/juice-shop
    ref: v15.0.0
    expected_findings:
      - CWE-79
  - name: clean-go
    type: clean-real-world
    language: go
    expected: low-false-positive-rate
    path: /tmp/some-local-repo
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Suite != "test-suite" {
		t.Errorf("Suite = %q", cfg.Suite)
	}
	if cfg.PatchFlow.Profile != "standard" {
		t.Errorf("Profile = %q", cfg.PatchFlow.Profile)
	}
	if len(cfg.Repos) != 2 {
		t.Fatalf("repos = %d", len(cfg.Repos))
	}
	if cfg.Repos[0].Type != RepoIntentionallyVulnerable {
		t.Errorf("repo[0] type = %q", cfg.Repos[0].Type)
	}
	if cfg.Repos[1].Type != RepoCleanRealWorld {
		t.Errorf("repo[1] type = %q", cfg.Repos[1].Type)
	}
	if got := cfg.Repos[0].PublishDetailFor(); !got {
		t.Error("intentionally-vulnerable should publish detail by default")
	}
	if got := cfg.Repos[1].PublishDetailFor(); got {
		t.Error("clean-real-world should NOT publish detail by default")
	}
}

func TestLoadConfigValidation(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		yaml string
	}{
		{"no repos", `suite: x`},
		{"missing url and path", `
repos:
  - name: foo
    type: intentionally-vulnerable
`},
		{"invalid type", `
repos:
  - name: foo
    type: bogus
    url: https://example.com
`},
		{"duplicate name", `
repos:
  - name: foo
    type: intentionally-vulnerable
    url: https://example.com
  - name: foo
    type: clean-real-world
    url: https://example.com
`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := filepath.Join(dir, c.name+".yaml")
			if err := os.WriteFile(p, []byte(c.yaml), 0644); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(p); err == nil {
				t.Fatalf("expected validation error, got nil")
			}
		})
	}
}

func TestPublishDetailOverride(t *testing.T) {
	t.Run("override true on clean repo", func(t *testing.T) {
		b := true
		r := RepoSpec{Type: RepoCleanRealWorld, PublishDetail: &b}
		if !r.PublishDetailFor() {
			t.Error("override should force publish=true")
		}
	})
	t.Run("override false on vuln repo", func(t *testing.T) {
		b := false
		r := RepoSpec{Type: RepoIntentionallyVulnerable, PublishDetail: &b}
		if r.PublishDetailFor() {
			t.Error("override should force publish=false")
		}
	})
}

func TestCountLOC(t *testing.T) {
	dir := t.TempDir()
	// Create scannable files.
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "node_modules"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "node_modules", "big.js"), []byte("var x = 1;\nvar y = 2;\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# Title\n\nbody\n"), 0644); err != nil {
		t.Fatal(err)
	}

	stats, err := CountLOC(dir)
	if err != nil {
		t.Fatalf("CountLOC: %v", err)
	}
	// main.go: 2 non-blank lines (package main, func main() {})
	// node_modules/big.js: ignored
	// README.md: .md not in scannableExts -> not counted
	if stats.LOC != 2 {
		t.Errorf("LOC = %d, want 2", stats.LOC)
	}
	if stats.FilesScanned != 1 {
		t.Errorf("FilesScanned = %d, want 1", stats.FilesScanned)
	}
}

func TestValidateSARIF(t *testing.T) {
	dir := t.TempDir()

	t.Run("valid sarif", func(t *testing.T) {
		p := filepath.Join(dir, "valid.sarif")
		valid := `{"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":{"name":"patchflow","version":"0.1.0"}},"results":[]}]}`
		if err := os.WriteFile(p, []byte(valid), 0644); err != nil {
			t.Fatal(err)
		}
		if err := ValidateSARIF(p); err != nil {
			t.Errorf("expected valid, got %v", err)
		}
	})

	t.Run("missing version", func(t *testing.T) {
		p := filepath.Join(dir, "nover.sarif")
		if err := os.WriteFile(p, []byte(`{"runs":[]}`), 0644); err != nil {
			t.Fatal(err)
		}
		if err := ValidateSARIF(p); err == nil {
			t.Error("expected error for missing version")
		}
	})

	t.Run("wrong version", func(t *testing.T) {
		p := filepath.Join(dir, "wrongver.sarif")
		if err := os.WriteFile(p, []byte(`{"version":"2.0.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[]}]}`), 0644); err != nil {
			t.Fatal(err)
		}
		if err := ValidateSARIF(p); err == nil {
			t.Error("expected error for wrong version")
		}
	})

	t.Run("no runs", func(t *testing.T) {
		p := filepath.Join(dir, "noruns.sarif")
		if err := os.WriteFile(p, []byte(`{"version":"2.1.0","runs":[]}`), 0644); err != nil {
			t.Fatal(err)
		}
		if err := ValidateSARIF(p); err == nil {
			t.Error("expected error for no runs")
		}
	})

	t.Run("missing driver name", func(t *testing.T) {
		p := filepath.Join(dir, "nodriver.sarif")
		if err := os.WriteFile(p, []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{}},"results":[]}]}`), 0644); err != nil {
			t.Fatal(err)
		}
		if err := ValidateSARIF(p); err == nil {
			t.Error("expected error for missing driver name")
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		p := filepath.Join(dir, "badjson.sarif")
		if err := os.WriteFile(p, []byte(`{not json`), 0644); err != nil {
			t.Fatal(err)
		}
		if err := ValidateSARIF(p); err == nil {
			t.Error("expected error for invalid JSON")
		}
	})
}

func TestBuildMetrics(t *testing.T) {
	pf := &pfJSONOutput{}
	pf.Analysis.Findings = []pfFinding{
		{Type: "sast", Severity: "high", Confidence: "high", RuleID: "GO101"},
		{Type: "sast", Severity: "medium", Confidence: "medium", RuleID: "GO102"},
		{Type: "secret", Severity: "critical", Confidence: "high", RuleID: "SEC001"},
		{Type: "sca", Severity: "high", Confidence: "high", CVEID: "CVE-2024-1234"},
	}
	pf.Analysis.EngineTimings = []pfEngineTiming{
		{Engine: "osv-sca", Duration: 2 * time.Second, Findings: 1},
		{Engine: "sast", Duration: 5 * time.Second, Findings: 3},
	}
	pf.Analysis.Analyzers = []string{"osv", "gosast", "secrets"}

	loc := LOCStats{LOC: 1000, FilesScanned: 20}
	m := buildMetrics(RepoSpec{Name: "test", Type: RepoIntentionallyVulnerable, Language: "go"},
		pf, loc, 10*time.Second, 4*time.Second, 0, 50)

	if m.TotalFindings != 4 {
		t.Errorf("TotalFindings = %d, want 4", m.TotalFindings)
	}
	if m.BySeverity["high"] != 2 {
		t.Errorf("BySeverity high = %d, want 2", m.BySeverity["high"])
	}
	if m.BySeverity["critical"] != 1 {
		t.Errorf("BySeverity critical = %d, want 1", m.BySeverity["critical"])
	}
	if m.ByType["sast"] != 2 {
		t.Errorf("ByType sast = %d, want 2", m.ByType["sast"])
	}
	if m.LOC != 1000 {
		t.Errorf("LOC = %d", m.LOC)
	}
	// Cache speedup = (10-4)/10 * 100 = 60
	if m.CacheSpeedup != 60 {
		t.Errorf("CacheSpeedup = %.1f, want 60", m.CacheSpeedup)
	}
	if m.MemoryMB != 50 {
		t.Errorf("MemoryMB = %d", m.MemoryMB)
	}
}

func TestApplyExpected(t *testing.T) {
	pf := &pfJSONOutput{}
	pf.Analysis.Findings = []pfFinding{
		{RuleID: "GO101"},
		{CVEID: "CVE-2024-1234"},
		{RuleID: "GO103"},
	}
	spec := RepoSpec{
		ExpectedFindings: []string{"GO101", "CVE-2024-1234", "GO999"},
	}
	m := &Metrics{}
	applyExpected(m, pf, spec)

	if len(m.ExpectedDetected) != 2 {
		t.Errorf("detected = %d, want 2", len(m.ExpectedDetected))
	}
	if len(m.ExpectedMissed) != 1 {
		t.Errorf("missed = %d, want 1", len(m.ExpectedMissed))
	}
	if m.Recall != 2.0/3.0 {
		t.Errorf("recall = %.3f, want %.3f", m.Recall, 2.0/3.0)
	}
}

func TestAggregate(t *testing.T) {
	cfg := &Config{Suite: "test", Date: "2026-06-26"}
	results := []RepoResult{
		{Repo: RepoSpec{ExpectedFindings: []string{"A", "B"}}, PatchFlow: Metrics{
			LOC: 1000, TotalFindings: 10, ScanDuration: 10 * time.Second, ColdDuration: 10 * time.Second,
			WarmDuration: 5 * time.Second, CacheSpeedup: 50, SARIFGenerated: true, SARIFValid: true,
			Recall: 1.0, TruePositives: 8, FalsePositives: 2,
			BySeverity: map[string]int{"high": 5, "medium": 5},
			ToolFindings: map[string]int{"semgrep": 12},
		}},
		{Repo: RepoSpec{}, PatchFlow: Metrics{
			LOC: 2000, TotalFindings: 20, ScanDuration: 20 * time.Second, ColdDuration: 20 * time.Second,
			WarmDuration: 10 * time.Second, CacheSpeedup: 50, SARIFGenerated: true, SARIFValid: false,
			TruePositives: 15, FalsePositives: 5,
		}},
	}

	s := Aggregate(results, cfg)
	if s.ReposScanned != 2 {
		t.Errorf("ReposScanned = %d", s.ReposScanned)
	}
	if s.TotalLOC != 3000 {
		t.Errorf("TotalLOC = %d", s.TotalLOC)
	}
	if s.TotalFindings != 30 {
		t.Errorf("TotalFindings = %d", s.TotalFindings)
	}
	if s.ConfirmedTruePos != 23 {
		t.Errorf("ConfirmedTruePos = %d, want 23", s.ConfirmedTruePos)
	}
	if s.FalsePositives != 7 {
		t.Errorf("FalsePositives = %d, want 7", s.FalsePositives)
	}
	if s.SARIFTotalCount != 2 || s.SARIFValidCount != 1 {
		t.Errorf("SARIF total=%d valid=%d", s.SARIFTotalCount, s.SARIFValidCount)
	}
	// Avg scan time = (10+20)/2 = 15s
	if s.AvgScanTime != 15*time.Second {
		t.Errorf("AvgScanTime = %s", s.AvgScanTime)
	}
	if s.ToolComparison["semgrep"] != 12 {
		t.Errorf("tool comparison semgrep = %d", s.ToolComparison["semgrep"])
	}
	if s.AvgRecall != 1.0 {
		t.Errorf("AvgRecall = %.2f", s.AvgRecall)
	}
}

func TestComputePrecision(t *testing.T) {
	m := &Metrics{TotalFindings: 100, TruePositives: 70, FalsePositives: 20}
	ComputePrecision(m)
	if m.Precision != 70.0/90.0 {
		t.Errorf("Precision = %.3f", m.Precision)
	}
	if m.NoiseRate != 20.0/90.0 {
		t.Errorf("NoiseRate = %.3f", m.NoiseRate)
	}
	if m.Unknown != 10 {
		t.Errorf("Unknown = %d, want 10", m.Unknown)
	}
}

func TestWriteAndLoadSummaryJSON(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "summary.json")
	s := &Summary{
		Suite: "test", Date: "2026-06-26", ReposScanned: 3, TotalLOC: 50000,
		TotalFindings: 100, PatchFlowVersion: "0.1.0",
	}
	if err := WriteSummaryJSON(s, p); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadSummary(p)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Suite != "test" || loaded.ReposScanned != 3 {
		t.Errorf("loaded: suite=%q repos=%d", loaded.Suite, loaded.ReposScanned)
	}
}

func TestWriteSummaryMarkdown(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "summary.md")
	s := &Summary{
		Suite: "test-suite", Date: "2026-06-26", PatchFlowVersion: "0.1.0",
		ReposScanned: 2, TotalLOC: 50000, TotalFindings: 42,
		ConfirmedTruePos: 30, FalsePositives: 8, UnknownUnreviewed: 4,
		AvgScanTime: 42 * time.Second, CacheWarmSpeedup: 63,
		SARIFValidCount: 2, SARIFTotalCount: 2,
		PerRepo: []Metrics{
			{RepoName: "juice-shop", RepoType: RepoIntentionallyVulnerable, Language: "javascript",
				LOC: 30000, FilesScanned: 500, TotalFindings: 30, ColdDuration: 30 * time.Second,
				WarmDuration: 12 * time.Second, CacheSpeedup: 60, SARIFGenerated: true, SARIFValid: true,
				BySeverity: map[string]int{"high": 20, "medium": 10}},
			{RepoName: "clean-go", RepoType: RepoCleanRealWorld, Language: "go",
				LOC: 20000, FilesScanned: 300, TotalFindings: 12, ColdDuration: 54 * time.Second,
				WarmDuration: 20 * time.Second, CacheSpeedup: 63, SARIFGenerated: true, SARIFValid: true},
		},
		ToolComparison: map[string]int{"semgrep": 55, "gitleaks": 3},
	}
	results := []RepoResult{
		{Repo: RepoSpec{Name: "juice-shop", Type: RepoIntentionallyVulnerable, ExpectedFindings: []string{"CWE-79"}},
			PatchFlow: s.PerRepo[0]},
		{Repo: RepoSpec{Name: "clean-go", Type: RepoCleanRealWorld}, PatchFlow: s.PerRepo[1]},
	}

	if err := WriteSummaryMarkdown(s, results, p); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	// Check key sections present.
	for _, want := range []string{"PatchFlow CLI Benchmark Report", "Responsible disclosure", "Tool comparison", "Recall"} {
		if !strings.Contains(body, want) {
			t.Errorf("markdown missing section %q", want)
		}
	}
	// Clean repo should NOT have per-finding detail; but its name appears in the table.
	if !strings.Contains(body, "clean-go") {
		t.Error("markdown missing clean-go repo row")
	}
}

func TestParsePatchFlowJSON(t *testing.T) {
	raw := `{"analysis":{"findings":[{"type":"sast","severity":"high","confidence":"high","rule_id":"GO101"}],"engine_timings":[{"engine":"sast","duration":5000000000,"findings":1}],"analyzers":["osv","gosast"],"duration":10000000000,"exit_code":0},"risk":{"findings_by_severity":{"high":1}}}`
	pf, err := parsePatchFlowJSON([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(pf.Analysis.Findings) != 1 {
		t.Fatalf("findings = %d", len(pf.Analysis.Findings))
	}
	if pf.Analysis.Findings[0].RuleID != "GO101" {
		t.Errorf("rule id = %q", pf.Analysis.Findings[0].RuleID)
	}
	if len(pf.Analysis.EngineTimings) != 1 {
		t.Errorf("engine timings = %d", len(pf.Analysis.EngineTimings))
	}
}

func TestParsePatchFlowJSONEmpty(t *testing.T) {
	if _, err := parsePatchFlowJSON(nil); err == nil {
		t.Error("expected error for empty stdout")
	}
}

func TestSummaryJSONRoundTrip(t *testing.T) {
	s := &Summary{Suite: "rt", Date: "2026-06-26", PerRepo: []Metrics{{RepoName: "x", LOC: 1}}}
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var back Summary
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.Suite != "rt" || len(back.PerRepo) != 1 {
		t.Errorf("round trip mismatch")
	}
}

func TestCompareSummaries(t *testing.T) {
	root := t.TempDir()
	for _, month := range []string{"2026-05", "2026-06"} {
		dir := filepath.Join(root, month)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		s := &Summary{Suite: "test", Date: month + "-01", ReposScanned: 5, TotalFindings: 10}
		if err := WriteSummaryJSON(s, filepath.Join(dir, "summary.json")); err != nil {
			t.Fatal(err)
		}
	}
	got, err := CompareSummaries(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 summaries, got %d", len(got))
	}
	if got["2026-06"].ReposScanned != 5 {
		t.Errorf("repos = %d", got["2026-06"].ReposScanned)
	}
}
