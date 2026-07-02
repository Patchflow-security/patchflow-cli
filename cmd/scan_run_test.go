package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// chdirTemp changes the working directory to dir and registers cleanup to
// restore the original directory. The scan run command uses git.DetectOrLocal
// which operates on the current working directory, so tests must chdir into
// the temp project directory.
func chdirTemp(t *testing.T, dir string) {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })
}

// writeVulnPython writes a simple vulnerable Python file to dir.
func writeVulnPython(t *testing.T, dir string) string {
	t.Helper()
	src := "import os\nuser_input = input()\neval(user_input)\n"
	p := filepath.Join(dir, "vuln.py")
	if err := os.WriteFile(p, []byte(src), 0644); err != nil {
		t.Fatalf("write vuln.py: %v", err)
	}
	return p
}

// resetAllFlags walks the root command tree and resets every flag (persistent
// and local) to its default value. This prevents flag state from leaking
// between tests that share the global rootCmd.
func resetAllFlags() {
	resetFlags(rootCmd)
	for _, c := range rootCmd.Commands() {
		resetFlags(c)
		for _, sub := range c.Commands() {
			resetFlags(sub)
		}
	}
}

func resetFlags(cmd *cobra.Command) {
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		_ = f.Value.Set(f.DefValue)
	})
	cmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		_ = f.Value.Set(f.DefValue)
	})
}

// captureStdout replaces os.Stdout with a pipe, runs fn, and returns whatever
// was written to stdout during fn's execution. The original os.Stdout is
// restored afterwards. This is necessary because the output formatter writes
// directly to os.Stdout (not via cmd.SetOut).
func captureStdout(t *testing.T, fn func() error) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = orig })

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	runErr := fn()
	_ = w.Close()
	os.Stdout = orig
	out := <-done

	if runErr != nil {
		t.Logf("command returned error: %v", runErr)
	}
	return out
}

// runRootCommand resets flags, sets args on the global rootCmd, captures
// stdout (via pipe since the formatter writes directly to os.Stdout), and
// returns the captured output.
func runRootCommand(t *testing.T, args []string) string {
	t.Helper()
	resetAllFlags()
	rootCmd.SetArgs(args)
	return captureStdout(t, func() error {
		return rootCmd.Execute()
	})
}

// TestScanRun_HelpOutput verifies the scan run command prints help text
// containing "scan" and "Usage" when invoked with --help.
func TestScanRun_HelpOutput(t *testing.T) {
	out := runRootCommand(t, []string{"scan", "run", "--help"})

	if !strings.Contains(out, "scan") {
		t.Errorf("expected help output to contain 'scan', got:\n%s", out)
	}
	if !strings.Contains(out, "Usage") {
		t.Errorf("expected help output to contain 'Usage', got:\n%s", out)
	}
}

// TestScanRun_JSONOutput runs the scan command with --json on a temp dir
// containing a vulnerable Python file and verifies the stdout is valid JSON
// with an "analysis" object containing a "findings" array.
func TestScanRun_JSONOutput(t *testing.T) {
	tmpDir := t.TempDir()
	writeVulnPython(t, tmpDir)
	chdirTemp(t, tmpDir)

	out := runRootCommand(t, []string{"scan", "run", "--json", "--quiet", "--no-reachability", "--offline"})

	// Parse the JSON output. The scan may emit log warnings to stderr; stdout
	// should contain the JSON payload.
	var result map[string]json.RawMessage
	if perr := json.Unmarshal([]byte(out), &result); perr != nil {
		t.Fatalf("stdout is not valid JSON: %v\noutput:\n%s", perr, out)
	}

	analysisRaw, ok := result["analysis"]
	if !ok {
		t.Fatalf("expected top-level 'analysis' key, got keys: %v\noutput:\n%s", mapKeys(result), out)
	}

	var analysis map[string]json.RawMessage
	if err := json.Unmarshal(analysisRaw, &analysis); err != nil {
		t.Fatalf("analysis is not valid JSON: %v", err)
	}

	findingsRaw, ok := analysis["findings"]
	if !ok {
		t.Fatalf("expected 'analysis.findings' key, got keys: %v", mapKeys(analysis))
	}

	var findings []json.RawMessage
	if err := json.Unmarshal(findingsRaw, &findings); err != nil {
		t.Fatalf("findings is not a JSON array: %v", err)
	}
	// We don't assert findings > 0 because the embedded scanner may or may not
	// flag eval() depending on rule configuration; we only verify structure.
	t.Logf("scan produced %d findings", len(findings))
}

// TestScanRun_QuietFlag verifies that --quiet suppresses the banner and
// summary output (no human-readable banner/summary lines).
func TestScanRun_QuietFlag(t *testing.T) {
	tmpDir := t.TempDir()
	writeVulnPython(t, tmpDir)
	chdirTemp(t, tmpDir)

	out := runRootCommand(t, []string{"scan", "run", "--quiet", "--no-reachability", "--offline"})

	// In quiet mode, the CLI should not print the ASCII banner or the
	// multi-line terminal summary. We check for absence of common banner
	// markers and the summary header.
	bannerMarkers := []string{"╔", "╗", "╚", "╝", "║", "PatchFlow CLI", "Scan Summary"}
	for _, marker := range bannerMarkers {
		if strings.Contains(out, marker) {
			t.Errorf("expected --quiet to suppress banner/summary marker %q, but found it in output:\n%s", marker, out)
		}
	}
}

// TestVersionCommand verifies the version command output contains "patchflow".
func TestVersionCommand(t *testing.T) {
	out := runRootCommand(t, []string{"version"})

	if !strings.Contains(strings.ToLower(out), "patchflow") {
		t.Errorf("expected version output to contain 'patchflow', got:\n%s", out)
	}
}

// mapKeys returns the keys of a map for debugging output.
func mapKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
