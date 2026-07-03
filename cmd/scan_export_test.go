package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestScanExport_SARIF runs the scan export command with --format sarif on a
// temp dir containing a vulnerable Python file and verifies the output is
// valid JSON with a "runs" array (SARIF top-level structure).
func TestScanExport_SARIF(t *testing.T) {
	tmpDir := t.TempDir()
	writeVulnPython(t, tmpDir)
	chdirTemp(t, tmpDir)

	outFile := filepath.Join(tmpDir, "results.sarif")

	out := runRootCommand(t, []string{"scan", "export", "--format", "sarif", "--output", outFile})

	// The export command writes to the output file when --output is set.
	data, err := os.ReadFile(outFile)
	if err != nil {
		// If the file wasn't written, check stdout (some code paths print to stdout).
		data = []byte(out)
		if len(data) == 0 {
			t.Fatalf("no SARIF output file and no stdout output: %v", err)
		}
	}

	var sarif map[string]interface{}
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v\noutput:\n%s", err, string(data))
	}

	runs, ok := sarif["runs"]
	if !ok {
		t.Fatalf("expected top-level 'runs' key in SARIF, got keys: %v", sarifKeys(sarif))
	}

	runsArr, ok := runs.([]interface{})
	if !ok {
		t.Fatalf("expected 'runs' to be an array, got %T", runs)
	}

	if len(runsArr) == 0 {
		t.Error("expected 'runs' array to have at least one element")
	}
}

// sarifKeys returns the keys of the SARIF map for debugging.
func sarifKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
