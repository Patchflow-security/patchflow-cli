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
