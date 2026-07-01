package registry

import (
	"context"
	"fmt"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
)

func TestFetchLicensesHandlesConcurrentDirectLicenseWrites(t *testing.T) {
	deps := make([]analysis.Dependency, 0, 400)
	for i := 0; i < 200; i++ {
		deps = append(deps, analysis.Dependency{
			Name:      fmt.Sprintf("licensed-%d", i),
			Version:   "1.0.0",
			Ecosystem: analysis.EcosystemNPM,
			License:   "MIT",
		})
		deps = append(deps, analysis.Dependency{
			Name:      fmt.Sprintf("lookup-%d", i),
			Version:   "1.0.0",
			Ecosystem: analysis.EcosystemNPM,
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results := NewMetadataClient().FetchLicenses(ctx, deps)
	if len(results) != 200 {
		t.Fatalf("expected 200 direct licenses, got %d", len(results))
	}
}
