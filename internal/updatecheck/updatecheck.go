// Package updatecheck provides a non-blocking check for newer PatchFlow CLI
// releases on GitHub. It caches the last check result for 24 hours so it
// doesn't hit the API on every invocation.
package updatecheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/config"
	"github.com/Patchflow-security/patchflow-cli/pkg/version"
)

const (
	// releasesAPI is the GitHub endpoint for the latest release.
	releasesAPI = "https://api.github.com/repos/Patchflow-security/patchflow-cli/releases/latest"

	// checkInterval is how often we actually hit the API (24h).
	checkInterval = 24 * time.Hour

	// requestTimeout caps the HTTP call so it never blocks the user.
	requestTimeout = 3 * time.Second

	// cacheFile stores the last check result.
	cacheFile = "update-check.json"
)

// Result holds the outcome of an update check.
type Result struct {
	LatestVersion string    `json:"latest_version"`
	CheckedAt     time.Time `json:"checked_at"`
}

// getConfigDirForTest is overridden in tests to point to a temp dir.
// In production it returns config.GetConfigDir().
var getConfigDirForTest = config.GetConfigDir

// githubRelease is the minimal subset of the GitHub releases API response.
type githubRelease struct {
	TagName string `json:"tag_name"`
}

// cachePath returns the full path to the update-check cache file.
func cachePath() string {
	return filepath.Join(getConfigDirForTest(), cacheFile)
}

// ShouldCheck reads the cache and returns true if enough time has elapsed
// since the last check (or if no cache exists).
func ShouldCheck() bool {
	data, err := os.ReadFile(cachePath())
	if err != nil {
		return true
	}
	var r Result
	if err := json.Unmarshal(data, &r); err != nil {
		return true
	}
	return time.Since(r.CheckedAt) >= checkInterval
}

// fetchLatestRelease calls the GitHub API and returns the latest release tag.
func fetchLatestRelease(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", releasesAPI, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "PatchFlow-CLI/"+version.Short())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github API returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return "", err
	}

	var rel githubRelease
	if err := json.Unmarshal(body, &rel); err != nil {
		return "", err
	}
	return rel.TagName, nil
}

// saveCache writes the result to the cache file.
func saveCache(r Result) error {
	dir := getConfigDirForTest()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return os.WriteFile(cachePath(), data, 0o600)
}

// readCachedVersion returns the cached latest version, if available.
func readCachedVersion() string {
	data, err := os.ReadFile(cachePath())
	if err != nil {
		return ""
	}
	var r Result
	if err := json.Unmarshal(data, &r); err != nil {
		return ""
	}
	return r.LatestVersion
}

// compareVersions compares two semver-like version strings (e.g. "0.1.1" vs "0.1.0").
// Returns true if latest is newer than current.
func compareVersions(current, latest string) bool {
	c := parseSemver(current)
	l := parseSemver(latest)
	if l[0] != c[0] {
		return l[0] > c[0]
	}
	if l[1] != c[1] {
		return l[1] > c[1]
	}
	return l[2] > c[2]
}

// parseSemver extracts [major, minor, patch] from a version string.
// Handles both "0.1.1" and "v0.1.1" formats. Returns [0,0,0] on parse failure.
func parseSemver(v string) [3]int {
	v = strings.TrimPrefix(v, "v")
	var nums [3]int
	fmt.Sscanf(v, "%d.%d.%d", &nums[0], &nums[1], &nums[2])
	return nums
}

// Check performs the update check. It fetches the latest release from GitHub
// (if the cache is stale), caches the result, and returns a message if a
// newer version is available. Returns empty string if up-to-date or on error.
//
// This function is designed to never block or fail the CLI — all errors are
// swallowed and result in an empty string.
func Check(ctx context.Context) string {
	if !ShouldCheck() {
		cached := readCachedVersion()
		if cached == "" {
			return ""
		}
		if compareVersions(version.Short(), cached) {
			return formatNotice(version.Short(), cached)
		}
		return ""
	}

	latest, err := fetchLatestRelease(ctx)
	if err != nil {
		// Silently fail — don't bother the user with network errors.
		return ""
	}

	latest = strings.TrimPrefix(latest, "v")

	_ = saveCache(Result{
		LatestVersion: latest,
		CheckedAt:     time.Now(),
	})

	if compareVersions(version.Short(), latest) {
		return formatNotice(version.Short(), latest)
	}
	return ""
}

// formatNotice builds the human-readable update notice.
func formatNotice(current, latest string) string {
	return fmt.Sprintf(
		"A new version of patchflow is available (%s → %s). Run: brew upgrade Patchflow-security/tap/patchflow",
		current, latest,
	)
}
