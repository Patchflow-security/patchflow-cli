package analysis

import "testing"

func TestSeverityWeight(t *testing.T) {
	tests := []struct {
		sev    Severity
		weight int
	}{
		{SeverityCritical, 100},
		{SeverityHigh, 75},
		{SeverityMedium, 50},
		{SeverityLow, 25},
		{SeverityInfo, 10},
		{Severity("unknown"), 0},
	}
	for _, tt := range tests {
		if got := SeverityWeight(tt.sev); got != tt.weight {
			t.Errorf("SeverityWeight(%s) = %d, want %d", tt.sev, got, tt.weight)
		}
	}
}

func TestSeverityOrder(t *testing.T) {
	if SeverityOrder(SeverityCritical) <= SeverityOrder(SeverityHigh) {
		t.Error("critical should rank higher than high")
	}
	if SeverityOrder(SeverityHigh) <= SeverityOrder(SeverityMedium) {
		t.Error("high should rank higher than medium")
	}
}

func TestReachabilityWeight(t *testing.T) {
	tests := []struct {
		status ReachabilityStatus
		min    float64
		max    float64
	}{
		{ReachabilityHigh, 0.9, 1.1},
		{ReachabilityMedium, 0.6, 0.8},
		{ReachabilityLow, 0.3, 0.5},
		{ReachabilityNone, 0.0, 0.2},
	}
	for _, tt := range tests {
		got := ReachabilityWeight(tt.status)
		if got < tt.min || got > tt.max {
			t.Errorf("ReachabilityWeight(%s) = %f, want in [%f, %f]", tt.status, got, tt.min, tt.max)
		}
	}

	// High should be weighted higher than medium, medium higher than low
	if ReachabilityWeight(ReachabilityHigh) <= ReachabilityWeight(ReachabilityMedium) {
		t.Error("high reachability should weight higher than medium")
	}
	if ReachabilityWeight(ReachabilityMedium) <= ReachabilityWeight(ReachabilityLow) {
		t.Error("medium reachability should weight higher than low")
	}
}
