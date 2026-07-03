package rulesconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Patchflow-security/patchflow-cli/internal/rules"
)

// Profile defines a named configuration preset for `patchflow rules init --profile <name>`.
type Profile struct {
	Name        string
	Description string
	// RuleModeOverride returns the mode to set for a rule, or empty to leave commented out.
	RuleModeOverride func(meta rules.RuleMetadata) string
}

// Profiles returns all available configuration profiles.
func Profiles() []Profile {
	return []Profile{
		{
			Name:        "starter",
			Description: "Stable high-confidence rules block, beta/experimental inform (commented out)",
			RuleModeOverride: func(meta rules.RuleMetadata) string {
				if meta.Maturity == rules.MaturityStable || meta.Maturity == rules.MaturityEnterprise {
					if meta.Severity == "high" || meta.Severity == "critical" {
						return "block"
					}
				}
				return ""
			},
		},
		{
			Name:        "strict",
			Description: "Stable + beta injection/auth-critical rules block, heuristics stay inform",
			RuleModeOverride: func(meta rules.RuleMetadata) string {
				if meta.Maturity == rules.MaturityStable || meta.Maturity == rules.MaturityEnterprise {
					if meta.Severity == "high" || meta.Severity == "critical" {
						return "block"
					}
				}
				if meta.Maturity == rules.MaturityBeta {
					// Block on injection and auth-critical CWEs only
					if isInjectionCWE(meta.CWE) || isAuthCriticalCWE(meta.CWE) {
						if meta.Severity == "high" || meta.Severity == "critical" {
							return "block"
						}
					}
				}
				return ""
			},
		},
		{
			Name:        "audit",
			Description: "Everything inform, nothing blocks — for visibility without CI gates",
			RuleModeOverride: func(meta rules.RuleMetadata) string {
				return "inform"
			},
		},
		{
			Name:        "framework-heavy",
			Description: "Enable framework packs and template rules, stable rules block",
			RuleModeOverride: func(meta rules.RuleMetadata) string {
				if meta.Maturity == rules.MaturityStable || meta.Maturity == rules.MaturityEnterprise {
					if meta.Severity == "high" || meta.Severity == "critical" {
						return "block"
					}
				}
				return ""
			},
		},
		{
			Name:        "ci-blocking",
			Description: "Block on all high/critical findings (stable + beta), experimental off",
			RuleModeOverride: func(meta rules.RuleMetadata) string {
				if meta.Maturity == rules.MaturityExperimental {
					return "off"
				}
				if meta.Severity == "high" || meta.Severity == "critical" {
					return "block"
				}
				return "inform"
			},
		},
		{
			Name:        "enterprise",
			Description: "Stable rules block, beta inform, experimental off — conservative CI gate",
			RuleModeOverride: func(meta rules.RuleMetadata) string {
				if meta.Maturity == rules.MaturityExperimental {
					return "off"
				}
				if meta.Maturity == rules.MaturityStable || meta.Maturity == rules.MaturityEnterprise {
					if meta.Severity == "high" || meta.Severity == "critical" {
						return "block"
					}
					return "inform"
				}
				return ""
			},
		},
	}
}

// ProfileByName returns the profile with the given name, or nil if not found.
func ProfileByName(name string) *Profile {
	for _, p := range Profiles() {
		if p.Name == name {
			return &p
		}
	}
	return nil
}

func isInjectionCWE(cwe string) bool {
	switch cwe {
	case "CWE-79", "CWE-89", "CWE-78", "CWE-94", "CWE-1336", "CWE-95":
		return true
	}
	return false
}

func isAuthCriticalCWE(cwe string) bool {
	switch cwe {
	case "CWE-22", "CWE-918", "CWE-502":
		return true
	}
	return false
}

// InitConfig generates a commented .patchflow/rules.yaml with all known rules
// from the governance registry, showing their ID, name, CWE, and default mode.
// If profile is non-empty, rules are uncommented with the profile's mode overrides.
func InitConfig(dir string, reg *rules.Registry, profile string) (string, error) {
	configDir := filepath.Join(dir, ".patchflow")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create .patchflow directory: %w", err)
	}

	configPath := filepath.Join(configDir, "rules.yaml")

	// Don't overwrite an existing config
	if _, err := os.Stat(configPath); err == nil {
		return "", fmt.Errorf("rules.yaml already exists at %s", configPath)
	}

	var prof *Profile
	if profile != "" {
		prof = ProfileByName(profile)
		if prof == nil {
			return "", fmt.Errorf("unknown profile: %s (available: starter, strict, audit, framework-heavy, ci-blocking, enterprise)", profile)
		}
	}

	content := generateInitYAML(reg, prof)
	if err := os.WriteFile(configPath, []byte(content), 0o644); err != nil {
		return "", fmt.Errorf("failed to write rules.yaml: %w", err)
	}

	return configPath, nil
}

// generateInitYAML produces the full YAML content for `patchflow rules init`.
func generateInitYAML(reg *rules.Registry, prof *Profile) string {
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

	if prof != nil {
		sb.WriteString(fmt.Sprintf("#\n# Profile: %s\n# %s\n#\n# Rules below are pre-configured for this profile.\n# Adjust as needed for your project.\n", prof.Name, prof.Description))
	}

	sb.WriteString("\n")

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

			// If a profile is active, uncomment rules that the profile sets
			if prof != nil {
				overrideMode := prof.RuleModeOverride(meta)
				if overrideMode != "" {
					sb.WriteString(fmt.Sprintf("%s: %s\n\n", meta.ID, overrideMode))
				} else {
					sb.WriteString(fmt.Sprintf("# %s: %s\n\n", meta.ID, defaultMode))
				}
			} else {
				sb.WriteString(fmt.Sprintf("# %s: %s\n\n", meta.ID, defaultMode))
			}
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
