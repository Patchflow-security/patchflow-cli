package rulesconfig

import (
	"testing"
)

func TestFrameworkExtensions_Parse(t *testing.T) {
	yaml := `
framework_extensions:
  spring:
    custom_sources:
      - annotation: "@TenantInput"
    custom_sinks:
      - func: "LegacySql.run"
        cwe: "CWE-89"
        category: "sql_injection"
        severity: "high"
    custom_sanitizers:
      - func: "CompanySql.safe"
    safe_patterns:
      - pattern: "TenantAuth.requireOwner"
        reason: "Ownership validation"
`
	cfg, err := LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.HasFrameworkExtensions() {
		t.Fatal("expected HasFrameworkExtensions to be true")
	}
	ext, ok := cfg.FrameworkExtensions["spring"]
	if !ok {
		t.Fatal("expected spring extension")
	}
	if len(ext.CustomSources) != 1 {
		t.Errorf("expected 1 source, got %d", len(ext.CustomSources))
	}
	if len(ext.CustomSinks) != 1 {
		t.Errorf("expected 1 sink, got %d", len(ext.CustomSinks))
	}
	if ext.CustomSinks[0].CWE != "CWE-89" {
		t.Errorf("expected CWE-89, got %s", ext.CustomSinks[0].CWE)
	}
	if len(ext.CustomSanitizers) != 1 {
		t.Errorf("expected 1 sanitizer, got %d", len(ext.CustomSanitizers))
	}
	if len(ext.SafePatterns) != 1 {
		t.Errorf("expected 1 safe pattern, got %d", len(ext.SafePatterns))
	}
}

func TestFrameworkExtensions_EmptyConfig(t *testing.T) {
	cfg, err := LoadFromBytes([]byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HasFrameworkExtensions() {
		t.Error("expected HasFrameworkExtensions to be false for empty config")
	}
	if cfg.FrameworkExtensions == nil {
		t.Error("expected FrameworkExtensions to be initialized (non-nil)")
	}
}

func TestFrameworkExtensions_HasFrameworkConfig(t *testing.T) {
	yaml := `
framework_extensions:
  express:
    custom_sources:
      - func: "ctx.input"
`
	cfg, err := LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.HasFrameworkConfig() {
		t.Error("expected HasFrameworkConfig to be true when framework_extensions present")
	}
}
