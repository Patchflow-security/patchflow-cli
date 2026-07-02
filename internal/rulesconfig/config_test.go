package rulesconfig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/rules"
)

func TestModeIsValid(t *testing.T) {
	tests := []struct {
		mode  Mode
		valid bool
	}{
		{ModeBlock, true},
		{ModeInform, true},
		{ModeOff, true},
		{ModeDefault, true},
		{Mode("invalid"), false},
		{Mode("BLOCK"), false}, // case-sensitive
	}
	for _, tt := range tests {
		if got := tt.mode.IsValid(); got != tt.valid {
			t.Errorf("Mode(%q).IsValid() = %v, want %v", tt.mode, got, tt.valid)
		}
	}
}

func TestParseMode(t *testing.T) {
	tests := []struct {
		input   string
		want    Mode
		wantErr bool
	}{
		{"block", ModeBlock, false},
		{"inform", ModeInform, false},
		{"off", ModeOff, false},
		{"", ModeDefault, false},
		{"default", ModeDefault, false},
		{"warn", ModeInform, false},     // alias
		{"warning", ModeInform, false},  // alias
		{"disable", ModeOff, false},     // alias
		{"disabled", ModeOff, false},    // alias
		{"  block  ", ModeBlock, false}, // whitespace trimmed
		{"BLOCK", ModeBlock, false},     // case-insensitive
		{"Off", ModeOff, false},
		{"invalid", ModeDefault, true},
	}
	for _, tt := range tests {
		got, err := ParseMode(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseMode(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseMode(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestLoadFromBytes(t *testing.T) {
	yaml := []byte(`
rules:
  PF-SPRING-SSRF-001: block
  PF-EXPRESS-AUTH-001: inform
  G601: off

custom_rules:
  - id: CUSTOM-001
    title: Test rule
    pattern: 'console\.log'
    languages: [javascript]
    severity: low

frameworks:
  auto_detect: true
  enabled: [rails]
`)
	cfg, err := LoadFromBytes(yaml)
	if err != nil {
		t.Fatalf("LoadFromBytes failed: %v", err)
	}

	if cfg.GetMode("PF-SPRING-SSRF-001") != ModeBlock {
		t.Errorf("expected PF-SPRING-SSRF-001 = block")
	}
	if cfg.GetMode("PF-EXPRESS-AUTH-001") != ModeInform {
		t.Errorf("expected PF-EXPRESS-AUTH-001 = inform")
	}
	if cfg.GetMode("G601") != ModeOff {
		t.Errorf("expected G601 = off")
	}
	if cfg.GetMode("UNKNOWN-RULE") != ModeDefault {
		t.Errorf("expected unknown rule = default")
	}

	if len(cfg.CustomRules) != 1 {
		t.Errorf("expected 1 custom rule, got %d", len(cfg.CustomRules))
	}
	if cfg.CustomRules[0].ID != "CUSTOM-001" {
		t.Errorf("expected custom rule ID CUSTOM-001, got %s", cfg.CustomRules[0].ID)
	}

	if cfg.Frameworks.AutoDetect == nil || !*cfg.Frameworks.AutoDetect {
		t.Errorf("expected auto_detect = true")
	}
}

func TestLoadFromBytesInvalidMode(t *testing.T) {
	yaml := []byte(`
rules:
  SOME-RULE: invalid_mode
`)
	_, err := LoadFromBytes(yaml)
	if err == nil {
		t.Fatal("expected error for invalid mode, got nil")
	}
}

func TestLoadFromDir(t *testing.T) {
	dir := t.TempDir()

	// No file → empty config, no error
	cfg, err := LoadFromDir(dir)
	if err != nil {
		t.Fatalf("LoadFromDir with no file failed: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if len(cfg.RuleModes) != 0 {
		t.Errorf("expected 0 rule modes, got %d", len(cfg.RuleModes))
	}

	// Create file → should load
	configDir := filepath.Join(dir, ".patchflow")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	yamlContent := []byte("rules:\n  G104: off\n")
	if err := os.WriteFile(filepath.Join(configDir, "rules.yaml"), yamlContent, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err = LoadFromDir(dir)
	if err != nil {
		t.Fatalf("LoadFromDir with file failed: %v", err)
	}
	if cfg.GetMode("G104") != ModeOff {
		t.Errorf("expected G104 = off")
	}
}

func TestSetMode(t *testing.T) {
	cfg := &Config{}
	cfg.SetMode("G104", ModeOff)
	if cfg.GetMode("G104") != ModeOff {
		t.Errorf("expected G104 = off after SetMode")
	}
}

func TestAllConfiguredRuleIDs(t *testing.T) {
	cfg := &Config{
		RuleModes: map[string]Mode{
			"Z-rule": ModeBlock,
			"A-rule": ModeInform,
			"M-rule": ModeOff,
		},
	}
	ids := cfg.AllConfiguredRuleIDs()
	expected := []string{"A-rule", "M-rule", "Z-rule"}
	if len(ids) != len(expected) {
		t.Fatalf("expected %d IDs, got %d", len(expected), len(ids))
	}
	for i, want := range expected {
		if ids[i] != want {
			t.Errorf("ids[%d] = %s, want %s", i, ids[i], want)
		}
	}
}

func TestUnknownRules(t *testing.T) {
	cfg := &Config{
		RuleModes: map[string]Mode{
			"G104":      ModeOff,
			"TYPO-RULE": ModeBlock,
		},
	}
	known := map[string]bool{"G104": true, "G201": true}
	unknown := cfg.UnknownRules(known)
	if len(unknown) != 1 || unknown[0] != "TYPO-RULE" {
		t.Errorf("expected [TYPO-RULE], got %v", unknown)
	}
}

func TestHasCustomRules(t *testing.T) {
	cfg := &Config{}
	if cfg.HasCustomRules() {
		t.Error("expected false for empty config")
	}
	cfg.CustomRules = []rawRule{{ID: "C1", Pattern: "x"}}
	if !cfg.HasCustomRules() {
		t.Error("expected true with custom rules")
	}
}

func TestHasFrameworkConfig(t *testing.T) {
	cfg := &Config{}
	if cfg.HasFrameworkConfig() {
		t.Error("expected false for empty config")
	}
	autoDetect := true
	cfg.Frameworks.AutoDetect = &autoDetect
	if !cfg.HasFrameworkConfig() {
		t.Error("expected true with framework config")
	}
}

// --- Resolver tests ---

func TestResolverExplicitConfig(t *testing.T) {
	cfg := &Config{
		RuleModes: map[string]Mode{
			"G201": ModeBlock,
			"G104": ModeOff,
		},
	}
	reg := buildTestRegistry()
	r := NewResolver(cfg, reg)

	entry := r.Resolve("G201")
	if entry.Mode != ModeBlock || !entry.Blocking || entry.Source != ModeSourceProjectConfig {
		t.Errorf("G201: expected block/project_config, got %s/%s (blocking=%v)",
			entry.Mode, entry.Source, entry.Blocking)
	}

	entry = r.Resolve("G104")
	if entry.Mode != ModeOff || entry.Blocking {
		t.Errorf("G104: expected off/non-blocking, got %s (blocking=%v)", entry.Mode, entry.Blocking)
	}
}

func TestResolverCLIOverride(t *testing.T) {
	cfg := &Config{
		RuleModes: map[string]Mode{"G201": ModeInform},
	}
	reg := buildTestRegistry()
	r := NewResolver(cfg, reg)
	r.SetCLIOverride("G201", ModeBlock)

	entry := r.Resolve("G201")
	if entry.Mode != ModeBlock || entry.Source != ModeSourceCLI {
		t.Errorf("G201: expected block/cli, got %s/%s", entry.Mode, entry.Source)
	}
}

func TestResolverMaturityDefault(t *testing.T) {
	reg := buildTestRegistry()
	r := NewResolver(nil, reg)

	// G201 is stable + high severity → should default to block
	entry := r.Resolve("G201")
	if entry.Mode != ModeBlock {
		t.Errorf("G201 (stable+high): expected block, got %s", entry.Mode)
	}
	if entry.Source != ModeSourceDefault {
		t.Errorf("G201: expected default source, got %s", entry.Source)
	}

	// G104 is stable + low severity → should default to inform
	entry = r.Resolve("G104")
	if entry.Mode != ModeInform {
		t.Errorf("G104 (stable+low): expected inform, got %s", entry.Mode)
	}

	// TS-PY001 is beta → should default to inform
	entry = r.Resolve("TS-PY001")
	if entry.Mode != ModeInform {
		t.Errorf("TS-PY001 (beta): expected inform, got %s", entry.Mode)
	}

	// PF-RAILS-001 is experimental → should default to inform (never block)
	entry = r.Resolve("PF-RAILS-001")
	if entry.Mode != ModeInform {
		t.Errorf("PF-RAILS-001 (experimental): expected inform, got %s", entry.Mode)
	}
	if entry.Blocking {
		t.Error("PF-RAILS-001 (experimental): should never be blocking by default")
	}
}

func TestResolverUnknownRule(t *testing.T) {
	reg := buildTestRegistry()
	r := NewResolver(nil, reg)

	entry := r.Resolve("UNKNOWN-RULE")
	if entry.Mode != ModeInform {
		t.Errorf("unknown rule: expected inform, got %s", entry.Mode)
	}
	if entry.Blocking {
		t.Error("unknown rule: should not be blocking")
	}
}

func TestResolverExperimentalNeverBlocksByDefault(t *testing.T) {
	reg := buildTestRegistry()
	r := NewResolver(nil, reg)

	// Even if an experimental rule has high severity, it should not block
	entry := r.Resolve("PF-RAILS-001")
	if entry.Mode == ModeBlock {
		t.Error("experimental rule should never default to block")
	}

	// But user can explicitly set it to block
	cfg := &Config{RuleModes: map[string]Mode{"PF-RAILS-001": ModeBlock}}
	r2 := NewResolver(cfg, reg)
	entry = r2.Resolve("PF-RAILS-001")
	if entry.Mode != ModeBlock || !entry.Blocking {
		t.Errorf("explicit block on experimental: expected block, got %s", entry.Mode)
	}
}

func TestResolverIsOff(t *testing.T) {
	cfg := &Config{RuleModes: map[string]Mode{"G104": ModeOff}}
	r := NewResolver(cfg, buildTestRegistry())

	if !r.IsOff("G104") {
		t.Error("expected G104 to be off")
	}
	if r.IsOff("G201") {
		t.Error("expected G201 to not be off")
	}
}

func TestResolverIsBlocking(t *testing.T) {
	cfg := &Config{RuleModes: map[string]Mode{"G201": ModeInform}}
	r := NewResolver(cfg, buildTestRegistry())

	// G201 is stable+high, but user set inform → not blocking
	if r.IsBlocking("G201") {
		t.Error("expected G201 to not be blocking (inform override)")
	}

	// G104 is stable+low → not blocking by default
	if r.IsBlocking("G104") {
		t.Error("expected G104 to not be blocking")
	}
}

// --- Init tests ---

func TestInitConfig(t *testing.T) {
	dir := t.TempDir()
	reg := buildTestRegistry()

	path, err := InitConfig(dir, reg)
	if err != nil {
		t.Fatalf("InitConfig failed: %v", err)
	}

	if path == "" {
		t.Fatal("expected non-empty path")
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read generated config: %v", err)
	}

	str := string(content)
	// Should contain header
	if !contains(str, "PatchFlow Rules Configuration") {
		t.Error("missing header comment")
	}
	// Should contain mode explanations
	if !contains(str, "block") || !contains(str, "inform") || !contains(str, "off") {
		t.Error("missing mode explanations")
	}
	// Should contain rules from registry
	if !contains(str, "G201") {
		t.Error("missing G201 rule")
	}
	// Should contain custom rules template
	if !contains(str, "custom_rules") {
		t.Error("missing custom_rules template")
	}
}

func TestInitConfigAlreadyExists(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, ".patchflow")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "rules.yaml"), []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := InitConfig(dir, buildTestRegistry())
	if err == nil {
		t.Fatal("expected error when config already exists")
	}
}

func TestInitConfigNilRegistry(t *testing.T) {
	dir := t.TempDir()
	path, err := InitConfig(dir, nil)
	if err != nil {
		t.Fatalf("InitConfig with nil registry failed: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(content), "custom_rules") {
		t.Error("expected custom_rules template even with nil registry")
	}
}

// --- Helpers ---

func buildTestRegistry() *rules.Registry {
	reg := rules.NewRegistry()

	// Stable + high severity → blocking eligible
	reg.Register(rules.RuleMetadata{
		ID:               "G201",
		Engine:           rules.EngineGoSAST,
		Title:            "SQL query construction using format string",
		Severity:         "high",
		Confidence:       "high",
		Language:         "go",
		Maturity:         rules.MaturityStable,
		CWE:              "CWE-89",
	})

	// Stable + low severity → not blocking eligible
	reg.Register(rules.RuleMetadata{
		ID:               "G104",
		Engine:           rules.EngineGoSAST,
		Title:            "Errors unhandled",
		Severity:         "low",
		Confidence:       "medium",
		Language:         "go",
		Maturity:         rules.MaturityStable,
		CWE:              "CWE-755",
	})

	// Beta → inform
	reg.Register(rules.RuleMetadata{
		ID:               "TS-PY001",
		Engine:           rules.EngineTreeSitter,
		Title:            "Tree-sitter Python eval",
		Severity:         "high",
		Confidence:       "high",
		Language:         "python",
		Maturity:         rules.MaturityBeta,
		CWE:              "CWE-95",
	})

	// Experimental → inform, never blocks
	reg.Register(rules.RuleMetadata{
		ID:               "PF-RAILS-001",
		Engine:           rules.EngineFrameworks,
		Title:            "Rails XSS in template",
		Severity:         "high",
		Confidence:       "medium",
		Language:         "ruby",
		Maturity:         rules.MaturityExperimental,
		CWE:              "CWE-79",
	})

	return reg
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && stringContains(s, substr))
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
