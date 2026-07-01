package updatecheck

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name    string
		current string
		latest  string
		want    bool
	}{
		{"newer patch", "0.1.0", "0.1.1", true},
		{"newer minor", "0.1.1", "0.2.0", true},
		{"newer major", "1.9.9", "2.0.0", true},
		{"same version", "0.1.1", "0.1.1", false},
		{"older latest", "0.1.1", "0.1.0", false},
		{"v prefix on latest", "0.1.0", "v0.1.1", true},
		{"v prefix on both", "v0.1.0", "v0.2.0", true},
		{"empty latest", "0.1.0", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareVersions(tt.current, tt.latest)
			if got != tt.want {
				t.Errorf("compareVersions(%q, %q) = %v, want %v", tt.current, tt.latest, got, tt.want)
			}
		})
	}
}

func TestParseSemver(t *testing.T) {
	tests := []struct {
		input string
		want  [3]int
	}{
		{"0.1.1", [3]int{0, 1, 1}},
		{"v1.2.3", [3]int{1, 2, 3}},
		{"2.0.0", [3]int{2, 0, 0}},
		{"garbage", [3]int{0, 0, 0}},
		{"", [3]int{0, 0, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseSemver(tt.input)
			if got != tt.want {
				t.Errorf("parseSemver(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestShouldCheck_NoCache(t *testing.T) {
	// Point config dir to a temp dir so there's no cache file.
	tmp := t.TempDir()
	oldGetConfigDir := getConfigDirForTest
	getConfigDirForTest = func() string { return tmp }
	defer func() { getConfigDirForTest = oldGetConfigDir }()

	if !ShouldCheck() {
		t.Error("ShouldCheck() = false, want true when no cache exists")
	}
}

func TestShouldCheck_FreshCache(t *testing.T) {
	tmp := t.TempDir()
	oldGetConfigDir := getConfigDirForTest
	getConfigDirForTest = func() string { return tmp }
	defer func() { getConfigDirForTest = oldGetConfigDir }()

	// Write a cache file that was just created.
	r := Result{LatestVersion: "0.1.1", CheckedAt: time.Now()}
	data, _ := json.Marshal(r)
	_ = os.WriteFile(filepath.Join(tmp, cacheFile), data, 0o600)

	if ShouldCheck() {
		t.Error("ShouldCheck() = true, want false when cache is fresh")
	}
}

func TestShouldCheck_StaleCache(t *testing.T) {
	tmp := t.TempDir()
	oldGetConfigDir := getConfigDirForTest
	getConfigDirForTest = func() string { return tmp }
	defer func() { getConfigDirForTest = oldGetConfigDir }()

	// Write a cache file that's 2 days old.
	r := Result{LatestVersion: "0.1.0", CheckedAt: time.Now().Add(-48 * time.Hour)}
	data, _ := json.Marshal(r)
	_ = os.WriteFile(filepath.Join(tmp, cacheFile), data, 0o600)

	if !ShouldCheck() {
		t.Error("ShouldCheck() = false, want true when cache is stale")
	}
}

func TestCheck_WithMockedCache(t *testing.T) {
	tmp := t.TempDir()
	oldGetConfigDir := getConfigDirForTest
	getConfigDirForTest = func() string { return tmp }
	defer func() { getConfigDirForTest = oldGetConfigDir }()

	// Write a fresh cache pointing to a newer version.
	r := Result{LatestVersion: "99.0.0", CheckedAt: time.Now()}
	data, _ := json.Marshal(r)
	_ = os.WriteFile(filepath.Join(tmp, cacheFile), data, 0o600)

	// Since the cache is fresh, Check should use the cached value
	// and not hit the network. The current version (from the test
	// binary's version package) will be less than 99.0.0.
	got := Check(context.Background())
	if got == "" {
		t.Error("Check() = empty, expected update notice for newer cached version")
	}
}

func TestCheck_UpToDate(t *testing.T) {
	tmp := t.TempDir()
	oldGetConfigDir := getConfigDirForTest
	getConfigDirForTest = func() string { return tmp }
	defer func() { getConfigDirForTest = oldGetConfigDir }()

	// Write a fresh cache pointing to version 0.0.0 (older than anything).
	r := Result{LatestVersion: "0.0.0", CheckedAt: time.Now()}
	data, _ := json.Marshal(r)
	_ = os.WriteFile(filepath.Join(tmp, cacheFile), data, 0o600)

	got := Check(context.Background())
	if got != "" {
		t.Errorf("Check() = %q, expected empty when up-to-date", got)
	}
}

func TestFormatNotice(t *testing.T) {
	got := formatNotice("0.1.0", "0.1.1")
	if !contains(got, "0.1.0") || !contains(got, "0.1.1") {
		t.Errorf("formatNotice() = %q, expected both versions in message", got)
	}
	if !contains(got, "brew upgrade") {
		t.Errorf("formatNotice() = %q, expected brew upgrade hint", got)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
