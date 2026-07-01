package benchmark

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// runWithMemory executes a command and returns stdout, exit code, peak memory
// (MiB), and error. Memory is measured best-effort via /usr/bin/time; if that
// is unavailable the memory is reported as 0 and the command still runs.
//
// On macOS, /usr/bin/time -l prints "maximum resident set size" in bytes.
// On Linux, /usr/bin/time -v prints "Maximum resident set size (kbytes)".
func runWithMemory(ctx context.Context, name string, args []string, dir string) ([]byte, int, int, error) {
	// Fast path: if /usr/bin/time is missing, run directly.
	// Try the bare "time" first (respects PATH), then fall back to the
	// absolute path which is more reliable on macOS where /usr/bin/time
	// is not in the default PATH.
	timePath, _ := exec.LookPath("time")
	if timePath == "" {
		timePath, _ = exec.LookPath("/usr/bin/time")
	}
	if timePath == "" {
		return runDirect(ctx, name, args, dir)
	}

	var timeArgs []string
	var parseMem func([]byte) int
	if runtime.GOOS == "darwin" {
		timeArgs = []string{"-l", name}
		parseMem = parseDarwinMem
	} else {
		timeArgs = []string{"-v", name}
		parseMem = parseLinuxMem
	}
	timeArgs = append(timeArgs, args...)

	cmd := exec.CommandContext(ctx, timePath, timeArgs...)
	if dir != "" {
		cmd.Dir = dir
	}
	var stderr bytes.Buffer
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	exitCode := exitCodeFromErr(runErr)
	memMB := parseMem(stderr.Bytes()) / (1024 * 1024)
	if memMB == 0 && runtime.GOOS == "linux" {
		// Linux reports kbytes, already divided; recompute as kbytes->MiB.
		memMB = parseMem(stderr.Bytes()) / 1024
	}
	return stdout.Bytes(), exitCode, memMB, runErr
}

func runDirect(ctx context.Context, name string, args []string, dir string) ([]byte, int, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	runErr := cmd.Run()
	return stdout.Bytes(), exitCodeFromErr(runErr), 0, runErr
}

func exitCodeFromErr(err error) int {
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return -1
}

// parseDarwinMem extracts "maximum resident set size" (bytes) from `time -l`.
func parseDarwinMem(stderr []byte) int {
	for _, line := range strings.Split(string(stderr), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasSuffix(line, "maximum resident set size") {
			parts := strings.Fields(line)
			if len(parts) >= 1 {
				if n, err := strconv.Atoi(parts[0]); err == nil {
					return n
				}
			}
		}
	}
	return 0
}

// parseLinuxMem extracts "Maximum resident set size (kbytes)" from `time -v`.
func parseLinuxMem(stderr []byte) int {
	for _, line := range strings.Split(string(stderr), "\n") {
		if strings.Contains(line, "Maximum resident set size") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				if n, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
					return n
				}
			}
		}
	}
	return 0
}

// detectHardware returns a short human-readable hardware label for the report.
func detectHardware() string {
	arch := runtime.GOOS + "/" + runtime.GOARCH
	if cpu, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(cpu), "\n") {
			if strings.HasPrefix(line, "model name") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					return arch + " (" + strings.TrimSpace(parts[1]) + ")"
				}
			}
		}
	}
	return arch
}
