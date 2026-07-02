package rulesconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Patchflow-security/patchflow-cli/internal/rules"
)

// InitConfig generates a commented .patchflow/rules.yaml with all known rules
// from the governance registry, showing their ID, name, CWE, and default mode.
// Rules are commented out so the generated file is a no-op until the user
// uncomment lines they want to override.
func InitConfig(dir string, reg *rules.Registry) (string, error) {
	configDir := filepath.Join(dir, ".patchflow")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create .patchflow directory: %w", err)
	}

	configPath := filepath.Join(configDir, "rules.yaml")

	// Don't overwrite an existing config
	if _, err := os.Stat(configPath); err == nil {
		return "", fmt.Errorf("rules.yaml already exists at %s", configPath)
	}

	content := generateInitYAML(reg)
	if err := os.WriteFile(configPath, []byte(content), 0o644); err != nil {
		return "", fmt.Errorf("failed to write rules.yaml: %w", err)
	}

	return configPath, nil
}

// generateInitYAML produces the full YAML content for `patchflow rules init`.
func generateInitYAML(reg *rules.Registry) string {
	var sb strings.Builder

	sb.WriteString(`# PatchFlow Rules Configuration
# ================================
#
# Control how each rule behaves in your project.
# Modes:
#   block  — finding is reported and fails CI (non-zero exit code)
#   inform — finding is reported but does not fail CI
#   off    — finding is suppressed entirely
#
# Uncomment a line to override the default mode for that rule.
# Rules not listed here use maturity-based defaults:
#   stable + high/critical severity → block
#   stable + medium/low severity    → inform
#   beta                            → inform
#   experimental                    → inform (never blocks unless you set it)

`)

	if reg == nil || reg.Count() == 0 {
		sb.WriteString("# No rules registered — run `patchflow scan run` first to populate the registry.\n")
		sb.WriteString("\n# You can still add custom rules below:\n")
		sb.WriteString(customRulesTemplate)
		return sb.String()
	}

	// Group rules by engine for readability
	engines := []rules.Engine{
		rules.EngineGoSAST,
		rules.EngineSecrets,
		rules.EngineTreeSitter,
		rules.EnginePatterns,
		rules.EngineTaintPatterns,
		rules.EngineFrameworks,
	}

	for _, engine := range engines {
		ruleList := reg.ByEngine(engine)
		if len(ruleList) == 0 {
			continue
		}

		sb.WriteString(fmt.Sprintf("# ── %s ──\n", engine))
		for _, meta := range ruleList {
			defaultMode := maturityDefaultMode(meta)
			comment := fmt.Sprintf("# %s: %s  [%s, %s, %s]",
				meta.ID,
				truncate(meta.Title, 50),
				meta.Severity,
				meta.Maturity,
				defaultMode,
			)
			if meta.CWE != "" {
				comment += fmt.Sprintf("  %s", meta.CWE)
			}
			sb.WriteString(comment + "\n")
			sb.WriteString(fmt.Sprintf("# %s: %s\n\n", meta.ID, defaultMode))
		}
	}

	// Add custom rules template
	sb.WriteString("\n# ── Custom Rules ──\n")
	sb.WriteString(customRulesTemplate)

	return sb.String()
}

const customRulesTemplate = `# Define your own pattern or taint rules:
#
# custom_rules:
#   - id: CUSTOM-001
#     title: No console.log in production
#     description: console.log should not be used in production code
#     languages: [javascript, typescript]
#     pattern: 'console\.log\s*\('
#     severity: low
#     confidence: high
#
# custom_taint_rules:
#   - id: CUSTOM-TAINT-001
#     title: User input to eval
#     language: python
#     severity: high
#     cwe: CWE-95
#     taint:
#       sources:
#         - func: request.get
#       sinks:
#         - func: eval
#           arg: 0
#       sanitizers:
#         - func: sanitize_input

# ── Framework Pack Controls ──
#
# frameworks:
#   auto_detect: true
#   enabled: [rails, spring]
#   disabled: [angular]
#
# framework_overrides:
#   rails:
#     custom_sources:
#       - func: params
#         is_subscript: true
#     severity_overrides:
#       PF-RAILS-XSS-001: high
`

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "…"
}
