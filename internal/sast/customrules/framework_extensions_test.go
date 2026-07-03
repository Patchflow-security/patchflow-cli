package customrules

import (
	"testing"
)

func TestFrameworkExtensionConfig_Parse(t *testing.T) {
	yaml := `
framework_extensions:
  spring:
    custom_sources:
      - annotation: "@TenantInput"
      - func: "InternalRequest.getParam"
    custom_sinks:
      - func: "LegacySql.run"
        cwe: "CWE-89"
        category: "sql_injection"
        severity: "high"
      - func: "InternalHttp.fetch"
        cwe: "CWE-918"
        category: "ssrf"
        severity: "high"
    custom_sanitizers:
      - func: "CompanySql.safe"
      - func: "UrlAllowlist.validate"
    safe_patterns:
      - pattern: "TenantAuth.requireOwner"
        reason: "Ownership validation performed by internal auth helper"
`
	policy, err := LoadPolicyFromBytes([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.FrameworkOverrides) != 1 {
		t.Fatalf("expected 1 framework override (from extensions), got %d", len(policy.FrameworkOverrides))
	}
	spring, ok := policy.FrameworkOverrides["spring"]
	if !ok {
		t.Fatal("expected spring override")
	}
	if len(spring.Sources) != 2 {
		t.Errorf("expected 2 sources, got %d", len(spring.Sources))
	}
	if len(spring.Sinks) != 2 {
		t.Errorf("expected 2 sinks, got %d", len(spring.Sinks))
	}
	if len(spring.Sanitizers) != 2 {
		t.Errorf("expected 2 sanitizers, got %d", len(spring.Sanitizers))
	}
	if len(spring.SafePatterns) != 1 {
		t.Errorf("expected 1 safe pattern, got %d", len(spring.SafePatterns))
	}
	// Verify annotation source
	found := false
	for _, s := range spring.Sources {
		if s.Annotation == "@TenantInput" {
			found = true
		}
	}
	if !found {
		t.Error("expected @TenantInput annotation source")
	}
	// Verify safe pattern
	if spring.SafePatterns[0].Reason != "Ownership validation performed by internal auth helper" {
		t.Errorf("unexpected safe pattern reason: %s", spring.SafePatterns[0].Reason)
	}
}

func TestFrameworkExtension_MergeWithOverrides(t *testing.T) {
	yaml := `
framework_overrides:
  spring:
    custom_sources:
      - func: "ExistingSource.getData"
    custom_sinks:
      - func: "ExistingSink.execute"

framework_extensions:
  spring:
    custom_sources:
      - func: "NewSource.getParam"
    custom_sinks:
      - func: "NewSink.run"
    safe_patterns:
      - pattern: "SafeGuard.check"
        reason: "Internal guard"
`
	policy, err := LoadPolicyFromBytes([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	spring, ok := policy.FrameworkOverrides["spring"]
	if !ok {
		t.Fatal("expected spring override")
	}
	if len(spring.Sources) != 2 {
		t.Errorf("expected 2 sources (1 override + 1 extension), got %d", len(spring.Sources))
	}
	if len(spring.Sinks) != 2 {
		t.Errorf("expected 2 sinks (1 override + 1 extension), got %d", len(spring.Sinks))
	}
	if len(spring.SafePatterns) != 1 {
		t.Errorf("expected 1 safe pattern (from extension), got %d", len(spring.SafePatterns))
	}
}

func TestFrameworkExtension_ValidateUnknownFrameworkWarns(t *testing.T) {
	// Unknown frameworks should be allowed (not error) — they may be
	// framework packs that aren't shipped in this build.
	yaml := `
framework_extensions:
  custom-internal-framework:
    custom_sources:
      - func: "InternalSource.getData"
    custom_sinks:
      - func: "InternalSink.run"
`
	policy, err := LoadPolicyFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("unknown framework should not cause error: %v", err)
	}
	if _, ok := policy.FrameworkOverrides["custom-internal-framework"]; !ok {
		t.Error("expected custom-internal-framework in overrides")
	}
}

func TestFrameworkExtension_InvalidSafePatternRegex(t *testing.T) {
	yaml := `
framework_extensions:
  spring:
    safe_patterns:
      - pattern: "[invalid("
        reason: "bad regex"
`
	_, err := LoadPolicyFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid regex in safe pattern")
	}
}

func TestFrameworkExtension_EmptyExtensionName(t *testing.T) {
	yaml := `
framework_extensions:
  "":
    custom_sources:
      - func: "SomeSource"
`
	_, err := LoadPolicyFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for empty framework name")
	}
}

func TestFrameworkExtension_SafePatternWithoutPattern(t *testing.T) {
	yaml := `
framework_extensions:
  spring:
    safe_patterns:
      - reason: "missing pattern field"
`
	_, err := LoadPolicyFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for safe pattern without pattern")
	}
}

func TestFrameworkExtension_ExpressExtension(t *testing.T) {
	yaml := `
framework_extensions:
  express:
    custom_sources:
      - func: "ctx.input"
      - func: "getRequestParam"
    custom_sinks:
      - func: "db.raw"
        cwe: "CWE-89"
        severity: "high"
    custom_sanitizers:
      - func: "sanitizeHtml"
      - func: "validateRedirectUrl"
`
	policy, err := LoadPolicyFromBytes([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	express, ok := policy.FrameworkOverrides["express"]
	if !ok {
		t.Fatal("expected express override")
	}
	if len(express.Sources) != 2 {
		t.Errorf("expected 2 sources, got %d", len(express.Sources))
	}
	if len(express.Sinks) != 1 {
		t.Errorf("expected 1 sink, got %d", len(express.Sinks))
	}
	if len(express.Sanitizers) != 2 {
		t.Errorf("expected 2 sanitizers, got %d", len(express.Sanitizers))
	}
}
