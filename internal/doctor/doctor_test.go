package doctor

import (
	"testing"
)

// TestCheckConfigRoundTrip verifies that the config round-trip check succeeds
// with a valid config containing custom rules (rules: as a list) and framework
// extensions. This is the regression guard for the B11.5.4 unified-config schema
// conflict where rulesconfig and customrules disagreed on the rules: schema.
func TestCheckConfigRoundTrip(t *testing.T) {
	ok, errMsg := checkConfigRoundTrip()
	if !ok {
		t.Fatalf("config round-trip check failed: %s", errMsg)
	}
}

func TestEveryNonPassCheckHasRemediation(t *testing.T) {
	report, err := Run()
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if len(report.Checks) == 0 {
		t.Fatal("Run() returned no structured checks")
	}
	for _, check := range report.Checks {
		if check.Status != "pass" && check.Remediation == "" {
			t.Errorf("check %q has status %q without remediation", check.Name, check.Status)
		}
	}
}
