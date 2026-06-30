package packs

import (
	"github.com/Patchflow-security/patchflow-cli/internal/rules"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

// ToRulesMaturity converts a frameworks.Maturity to the governance
// rules.Maturity used by the registry. This bridge lives in the packs
// package to avoid an import cycle between internal/sast/frameworks and
// internal/rules (which imports internal/sast).
func ToRulesMaturity(m frameworks.Maturity) rules.Maturity {
	switch m {
	case frameworks.MaturityExperimental:
		return rules.MaturityExperimental
	case frameworks.MaturityBeta:
		return rules.MaturityBeta
	case frameworks.MaturityStable:
		return rules.MaturityStable
	case frameworks.MaturityEnterprise:
		return rules.MaturityEnterprise
	}
	return rules.MaturityExperimental
}
