package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/cacheutil"
	"github.com/Patchflow-security/patchflow-cli/internal/git"
	"github.com/Patchflow-security/patchflow-cli/internal/osvdb"
	"github.com/Patchflow-security/patchflow-cli/internal/output"
	"github.com/spf13/cobra"
)

var cacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Manage the PatchFlow local cache",
	Long: `Inspect and clean the PatchFlow local cache.

The cache lives in a global XDG-compliant location:
  ~/.cache/patchflow/<project-hash>/
  (or $XDG_CACHE_HOME/patchflow/<project-hash>/)

It contains:
  - osv/            OSV vulnerability response cache (JSON files keyed by dependency hash)
  - sast_state.json Incremental SAST scan state (file hashes between scans)
  - registry/       Package registry metadata cache (npm, PyPI, Maven licenses)
  - maven/          Maven POM file cache for transitive resolution

Override the cache location with:
  --cache-dir DIR   CLI flag
  PATCHFLOW_CACHE_DIR  environment variable

Baselines (.patchflow/baselines/) and reports (.patchflow/reports/) are NOT
part of the cache and are preserved by 'cache clean'.`,
}

var cacheStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show cache directory location, size, and entry counts",
	RunE:  runCacheStatus,
}

var cacheCleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Remove OSV and incremental SAST cache contents",
	Long: `Remove all cache contents (OSV responses and incremental SAST state).

Baselines and reports are NOT removed.

Use --force to skip the confirmation prompt.`,
	RunE: runCacheClean,
}

var cacheCleanForce bool

var cacheUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Download the local OSV vulnerability database for offline scanning",
	Long: `Download OSV vulnerability data from the OSV.dev bulk export and cache
it locally at ~/.patchflow/osv-db/. This enables fast offline scanning without
API calls to OSV.dev.

The database is refreshed automatically when stale (>24h old), but you can
force a refresh with --force.

Supported ecosystems: PyPI, npm, Maven, Go, RubyGems, Packagist, crates.io.
Use --ecosystems to select specific ones (default: all relevant to detected manifests).`,
	RunE: runCacheUpdate,
}

var cacheUpdateForce bool
var cacheUpdateEcosystems []string

func init() {
	cacheCmd.AddCommand(cacheStatusCmd)
	cacheCmd.AddCommand(cacheCleanCmd)
	cacheCmd.AddCommand(cacheUpdateCmd)
	cacheCleanCmd.Flags().BoolVar(&cacheCleanForce, "force", false, "Skip confirmation prompt")
	cacheUpdateCmd.Flags().BoolVar(&cacheUpdateForce, "force", false, "Force refresh even if DB is fresh")
	cacheUpdateCmd.Flags().StringSliceVar(&cacheUpdateEcosystems, "ecosystems", nil, "Ecosystems to download (pypi,npm,maven,go,rubygems,packagist,crates.io)")
	rootCmd.AddCommand(cacheCmd)
}

// cacheStatus is the JSON-serializable result of 'cache status'.
type cacheStatus struct {
	CacheDir       string           `json:"cache_dir"`
	TotalSizeBytes int64            `json:"total_size_bytes"`
	TotalSize      string           `json:"total_size"`
	OSV            osvCacheStatus   `json:"osv"`
	SASTState      sastStateStatus  `json:"sast_state"`
	Baselines      baselinesStatus  `json:"baselines"`
}

type osvCacheStatus struct {
	Dir         string `json:"dir"`
	Entries     int    `json:"entries"`
	SizeBytes   int64  `json:"size_bytes"`
	Size        string `json:"size"`
}

type sastStateStatus struct {
	Path        string `json:"path"`
	Exists      bool   `json:"exists"`
	ModifiedAt  string `json:"modified_at,omitempty"`
}

type baselinesStatus struct {
	Dir   string `json:"dir"`
	Count int    `json:"count"`
}

func runCacheStatus(cmd *cobra.Command, _ []string) error {
	formatter := FormatterFromContext(cmd.Context())

	root, err := getProjectRoot()
	if err != nil {
		return formatter.PrintError(err)
	}

	cacheDir := cacheutil.ResolveCacheDir(root)
	osvDir := filepath.Join(cacheDir, "osv")
	sastStatePath := filepath.Join(cacheDir, "sast_state.json")
	baselinesDir := filepath.Join(root, ".patchflow", "baselines")

	osvEntries, osvSize := countDirEntries(osvDir)
	sastState := sastStateStatus{Path: sastStatePath}
	if info, err := os.Stat(sastStatePath); err == nil {
		sastState.Exists = true
		sastState.ModifiedAt = info.ModTime().UTC().Format("2006-01-02 15:04:05 MST")
	}
	baselineCount := countBaselines(baselinesDir)

	totalSize := osvSize
	if info, err := os.Stat(sastStatePath); err == nil {
		totalSize += info.Size()
	}

	status := cacheStatus{
		CacheDir:       cacheDir,
		TotalSizeBytes: totalSize,
		TotalSize:      humanBytes(totalSize),
		OSV: osvCacheStatus{
			Dir:       osvDir,
			Entries:   osvEntries,
			SizeBytes: osvSize,
			Size:      humanBytes(osvSize),
		},
		SASTState: sastState,
		Baselines: baselinesStatus{
			Dir:   baselinesDir,
			Count: baselineCount,
		},
	}

	if output.IsJSON(formatter) {
		return formatter.Print(status)
	}

	_ = formatter.Print("PatchFlow Cache Status")
	_ = formatter.Print("======================")
	_ = formatter.Print("")
	_ = formatter.Print("Cache directory: " + cacheDir)
	_ = formatter.Print("Total cache size: " + status.TotalSize + " (" + fmt.Sprintf("%d", status.TotalSizeBytes) + " bytes)")
	_ = formatter.Print("")
	_ = formatter.Print("OSV cache:")
	_ = formatter.Print("  Entries: " + fmt.Sprintf("%d", status.OSV.Entries))
	_ = formatter.Print("  Size:    " + status.OSV.Size + " (" + fmt.Sprintf("%d", status.OSV.SizeBytes) + " bytes)")
	_ = formatter.Print("  Dir:     " + status.OSV.Dir)
	_ = formatter.Print("")
	_ = formatter.Print("Incremental SAST state:")
	if status.SASTState.Exists {
		_ = formatter.Print("  Exists:      yes")
		_ = formatter.Print("  Last modified: " + status.SASTState.ModifiedAt)
	} else {
		_ = formatter.Print("  Exists: no")
	}
	_ = formatter.Print("  Path: " + status.SASTState.Path)
	_ = formatter.Print("")
	_ = formatter.Print("Baselines: " + fmt.Sprintf("%d", status.Baselines.Count))
	return nil
}

func runCacheClean(cmd *cobra.Command, _ []string) error {
	formatter := FormatterFromContext(cmd.Context())

	root, err := getProjectRoot()
	if err != nil {
		return formatter.PrintError(err)
	}

	cacheDir := cacheutil.ResolveCacheDir(root)
	osvDir := filepath.Join(cacheDir, "osv")
	sastStatePath := filepath.Join(cacheDir, "sast_state.json")

	// Compute sizes before removal for reporting.
	osvEntries, osvSize := countDirEntries(osvDir)
	sastStateSize := int64(0)
	if info, err := os.Stat(sastStatePath); err == nil {
		sastStateSize = info.Size()
	}
	freed := osvSize + sastStateSize

	if !output.IsJSON(formatter) {
		_ = formatter.Print("The following will be removed:")
		_ = formatter.Print("  " + osvDir + " (" + fmt.Sprintf("%d", osvEntries) + " entries, " + humanBytes(osvSize) + ")")
		if sastStateSize > 0 {
			_ = formatter.Print("  " + sastStatePath + " (" + humanBytes(sastStateSize) + ")")
		} else {
			_ = formatter.Print("  " + sastStatePath + " (not present)")
		}
		_ = formatter.Print("")
		_ = formatter.Print("Baselines and reports are NOT removed.")
		_ = formatter.Print("")
	}

	if !cacheCleanForce {
		if output.IsJSON(formatter) {
			return formatter.PrintError(fmt.Errorf("confirmation required: pass --force to clean cache"))
		}
		fmt.Print("Proceed? (y/N) ")
		var answer string
		_, _ = fmt.Scanln(&answer)
		if !strings.EqualFold(strings.TrimSpace(answer), "y") {
			_ = formatter.Print("Aborted.")
			return nil
		}
	}

	cleaned := []string{}
	if err := os.RemoveAll(osvDir); err != nil {
		return formatter.PrintError(fmt.Errorf("failed to remove OSV cache: %w", err))
	}
	cleaned = append(cleaned, osvDir)

	if _, err := os.Stat(sastStatePath); err == nil {
		if err := os.Remove(sastStatePath); err != nil {
			return formatter.PrintError(fmt.Errorf("failed to remove SAST state: %w", err))
		}
		cleaned = append(cleaned, sastStatePath)
	}

	if output.IsJSON(formatter) {
		return formatter.Print(map[string]interface{}{
			"cleaned":        cleaned,
			"freed_bytes":    freed,
			"freed_size":     humanBytes(freed),
			"osv_entries":    osvEntries,
		})
	}

	_ = formatter.PrintSuccess("Cache cleaned.")
	_ = formatter.Print("  Removed:")
	for _, p := range cleaned {
		_ = formatter.Print("    - " + p)
	}
	_ = formatter.Print("  Freed: " + humanBytes(freed) + " (" + fmt.Sprintf("%d", freed) + " bytes)")
	return nil
}

// getProjectRoot returns the project root, preferring git detection and
// falling back to the current working directory.
func getProjectRoot() (string, error) {
	repo, _, err := git.DetectOrLocal()
	if err != nil {
		return "", err
	}
	return repo.Root, nil
}

// countDirEntries returns the number of files and total size in dir.
func countDirEntries(dir string) (int, int64) {
	count := 0
	var size int64
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		count++
		size += info.Size()
	}
	return count, size
}

// countBaselines returns the number of baseline files in dir.
func countBaselines(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	count := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			count++
		}
	}
	return count
}

// humanBytes converts a byte count to a human-readable string (e.g. "1.2 KB").
func humanBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

// runCacheUpdate downloads the OSV vulnerability database for offline scanning.
func runCacheUpdate(cmd *cobra.Command, _ []string) error {
	formatter := FormatterFromContext(cmd.Context())
	ctx := cmd.Context()

	db := osvdb.DefaultLocalDB()

	// Determine which ecosystems to download
	var ecosystems []analysis.Ecosystem
	if len(cacheUpdateEcosystems) > 0 {
		for _, e := range cacheUpdateEcosystems {
			eco := parseEcosystemFlag(e)
			if eco != "" {
				ecosystems = append(ecosystems, eco)
			}
		}
	} else {
		// Default: all supported ecosystems
		ecosystems = []analysis.Ecosystem{
			analysis.EcosystemPyPI,
			analysis.EcosystemNPM,
			analysis.EcosystemMaven,
			analysis.EcosystemGo,
			analysis.EcosystemRubyGems,
			analysis.EcosystemPackagist,
		}
	}

	if !output.IsJSON(formatter) {
		formatter.Print(fmt.Sprintf("Downloading OSV vulnerability database for %d ecosystems...", len(ecosystems)))
	}

	// Check which ecosystems need refreshing
	var toDownload []analysis.Ecosystem
	for _, eco := range ecosystems {
		if cacheUpdateForce || db.NeedsRefresh(eco) {
			toDownload = append(toDownload, eco)
		}
	}

	if len(toDownload) == 0 {
		if !output.IsJSON(formatter) {
			formatter.Print("  All ecosystems are up to date. Use --force to refresh.")
		}
		return nil
	}

	if !output.IsJSON(formatter) {
		for _, eco := range toDownload {
			formatter.Print(fmt.Sprintf("  Downloading %s...", eco))
		}
	}

	if err := db.Download(ctx, toDownload); err != nil {
		return formatter.PrintError(fmt.Errorf("failed to download OSV DB: %w", err))
	}

	// Print stats
	stats := db.Stats()
	if output.IsJSON(formatter) {
		return formatter.Print(map[string]interface{}{
			"ecosystems": db.ListEcosystems(),
			"vuln_counts": stats,
		})
	}

	formatter.Print("")
	formatter.Print("OSV database updated successfully.")
	for eco, count := range stats {
		formatter.Print(fmt.Sprintf("  %-15s %d vulnerabilities", eco, count))
	}
	formatter.Print("")
	formatter.Print("Scans will now use the local DB for fast offline lookups.")
	return nil
}

// parseEcosystemFlag converts a string flag to an analysis.Ecosystem.
func parseEcosystemFlag(s string) analysis.Ecosystem {
	switch strings.ToLower(s) {
	case "pypi", "python":
		return analysis.EcosystemPyPI
	case "npm", "node", "javascript":
		return analysis.EcosystemNPM
	case "maven", "java":
		return analysis.EcosystemMaven
	case "go", "golang":
		return analysis.EcosystemGo
	case "rubygems", "ruby", "gem":
		return analysis.EcosystemRubyGems
	case "packagist", "php", "composer":
		return analysis.EcosystemPackagist
	case "crates.io", "cargo", "rust":
		return analysis.EcosystemCargo
	default:
		return ""
	}
}
