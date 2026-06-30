package packs

import (
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/rules"
)

func TestDefaultRegistryIncludesP0Packs(t *testing.T) {
	reg := BuildDefaultRegistry()
	want := []string{
		"angular",
		"aspnet",
		"django",
		"echo",
		"express",
		"fastapi",
		"flask",
		"gin",
		"laravel",
		"nestjs",
		"nextjs",
		"rails",
		"razor",
		"react",
		"spring",
		"spring-security",
		"symfony",
	}

	for _, name := range want {
		if !reg.Has(name) {
			t.Fatalf("default registry missing framework pack %q", name)
		}
	}
}

func TestFrameworkRuleProfilesFollowMaturity(t *testing.T) {
	reg := rules.NewRegistry()
	RegisterFrameworkRules(reg)

	meta, ok := reg.Get("PF-EXPRESS-SQLI-001")
	if !ok {
		t.Fatal("expected Express framework rule in governance registry")
	}
	if meta.Maturity != rules.MaturityBeta {
		t.Fatalf("maturity = %s, want beta", meta.Maturity)
	}
	if reg.IsRuleActiveInProfile(meta.ID, rules.ProfileDev) {
		t.Fatal("beta framework rule should not be active in dev profile")
	}
	if !reg.IsRuleActiveInProfile(meta.ID, rules.ProfileCI) {
		t.Fatal("beta framework rule should be active in CI profile")
	}
	if !reg.IsRuleActiveInProfile(meta.ID, rules.ProfileAudit) {
		t.Fatal("beta framework rule should be active in audit profile")
	}
	if meta.BlockingEligible {
		t.Fatal("beta framework rule should not be blocking eligible")
	}
}
