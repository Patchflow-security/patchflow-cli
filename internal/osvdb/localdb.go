// Package osvdb provides a local mirror of the OSV.dev vulnerability database.
// It downloads bulk OSV data as zip files per ecosystem from Google Cloud Storage
// and indexes them for fast offline lookups.
//
// Data source: https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip
// Each zip contains individual JSON files, one per vulnerability (e.g., PYSEC-2020-1.json).
//
// The local DB is stored at {home}/.patchflow/osv-db/ and refreshed daily.
// When the DB is present, the OSV client uses it for lookups instead of the
// API, eliminating network latency and enabling offline/air-gapped scanning.
package osvdb

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	osv "github.com/Patchflow-security/patchflow-cli/internal/osv"
)

const (
	// BaseURL is the Google Cloud Storage bucket for OSV bulk downloads.
	BaseURL = "https://osv-vulnerabilities.storage.googleapis.com"

	// DefaultDBDir is the default location for the local OSV DB.
	DefaultDBDir = ".patchflow/osv-db"

	// RefreshInterval is how often the DB is refreshed.
	RefreshInterval = 24 * time.Hour

	// DownloadTimeout is the max time for downloading a single ecosystem zip.
	DownloadTimeout = 10 * time.Minute
)

// ecosystemToOSVBucket maps PatchFlow ecosystems to OSV bucket names.
var ecosystemToOSVBucket = map[analysis.Ecosystem]string{
	analysis.EcosystemPyPI:      "PyPI",
	analysis.EcosystemNPM:       "npm",
	analysis.EcosystemMaven:     "Maven",
	analysis.EcosystemGo:        "Go",
	analysis.EcosystemRubyGems:  "RubyGems",
	analysis.EcosystemPackagist: "Packagist",
	analysis.EcosystemCargo:     "crates.io",
}

// LocalDB is a local mirror of the OSV vulnerability database.
type LocalDB struct {
	dir      string
	HTTPClient *http.Client
	mu       sync.RWMutex
	// index maps "ecosystem:package" → list of vulnerability IDs
	index map[string][]string
	// vulnStore maps "vulnID" → full vulnerability data, loaded from
	// the consolidated .db.bin file. This eliminates per-vuln file reads.
	vulnStore map[string]osv.Vulnerability
	// loaded tracks which ecosystems have been loaded into memory
	loaded map[string]bool
	// sqliteStores caches open SQLite connections per ecosystem
	sqliteStores map[string]*SQLiteStore
}

// NewLocalDB creates a local DB at the given directory.
func NewLocalDB(dir string) *LocalDB {
	return &LocalDB{
		dir:          dir,
		HTTPClient:   &http.Client{Timeout: DownloadTimeout},
		index:        make(map[string][]string),
		vulnStore:    make(map[string]osv.Vulnerability),
		loaded:       make(map[string]bool),
		sqliteStores: make(map[string]*SQLiteStore),
	}
}

// DefaultLocalDB creates a local DB at the default location (~/.patchflow/osv-db).
func DefaultLocalDB() *LocalDB {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return NewLocalDB(filepath.Join(home, DefaultDBDir))
}

// IsAvailable returns true if the local DB has been downloaded for at least
// one ecosystem. Checks for either the .db.bin consolidated file or
// individual vulnerability files (backward compat).
func (db *LocalDB) IsAvailable() bool {
	if db == nil {
		return false
	}
	entries, err := os.ReadDir(db.dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() || len(e.Name()) == 0 {
			continue
		}
		// Check for .db.bin (new format) or .metadata.json (old format)
		dbBin := filepath.Join(db.dir, e.Name(), ".db.bin")
		meta := filepath.Join(db.dir, e.Name(), ".metadata.json")
		if _, err := os.Stat(dbBin); err == nil {
			return true
		}
		if _, err := os.Stat(meta); err == nil {
			return true
		}
	}
	return false
}

// LastUpdated returns the last time the DB was updated for a given ecosystem,
// or time.Time{} if never updated.
func (db *LocalDB) LastUpdated(ecosystem analysis.Ecosystem) time.Time {
	bucket := ecosystemToOSVBucket[ecosystem]
	if bucket == "" {
		return time.Time{}
	}
	metaPath := filepath.Join(db.dir, bucket, ".metadata.json")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return time.Time{}
	}
	var meta struct {
		UpdatedAt time.Time `json:"updated_at"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return time.Time{}
	}
	return meta.UpdatedAt
}

// NeedsRefresh returns true if the DB for the given ecosystem is stale or missing.
func (db *LocalDB) NeedsRefresh(ecosystem analysis.Ecosystem) bool {
	updated := db.LastUpdated(ecosystem)
	return time.Since(updated) > RefreshInterval
}

// Download downloads and extracts the OSV data for the given ecosystems.
// This is a bulk operation — it downloads a zip file per ecosystem and
// extracts individual vulnerability JSON files.
func (db *LocalDB) Download(ctx context.Context, ecosystems []analysis.Ecosystem) error {
	for _, eco := range ecosystems {
		bucket := ecosystemToOSVBucket[eco]
		if bucket == "" {
			continue
		}
		if err := db.downloadEcosystem(ctx, bucket); err != nil {
			// Non-fatal — continue with other ecosystems
			fmt.Fprintf(os.Stderr, "warning: failed to download OSV data for %s: %v\n", bucket, err)
		}
	}
	return nil
}

// downloadEcosystem downloads and extracts a single ecosystem's zip file.
func (db *LocalDB) downloadEcosystem(ctx context.Context, bucket string) error {
	url := fmt.Sprintf("%s/%s/all.zip", BaseURL, bucket)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("creating request for %s: %w", url, err)
	}
	req.Header.Set("User-Agent", "PatchFlow-CLI/0.1")

	resp, err := db.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned %d for %s", resp.StatusCode, url)
	}

	// Read the zip into memory (we need to seek for zip reading)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 500<<20)) // 500MB limit
	if err != nil {
		return fmt.Errorf("read body failed: %w", err)
	}

	// Extract to the DB directory
	ecoDir := filepath.Join(db.dir, bucket)
	if err := os.MkdirAll(ecoDir, 0o755); err != nil {
		return fmt.Errorf("creating ecosystem dir %s: %w", ecoDir, err)
	}

	// Read the zip
	zipReader, err := zip.NewReader(strings.NewReader(string(body)), int64(len(body)))
	if err != nil {
		return fmt.Errorf("zip read failed: %w", err)
	}

	// Build the consolidated .db.bin file directly from the zip contents.
	// This is more efficient than extracting 20K+ individual files — we
	// parse each vulnerability JSON from the zip in memory and write a
	// single consolidated file.
	ecoStore := make(map[string]osv.Vulnerability)
	count := 0
	for _, file := range zipReader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(rc, 5<<20)) // 5MB per file
		rc.Close()
		if err != nil {
			continue
		}

		var vuln osv.Vulnerability
		if err := json.Unmarshal(data, &vuln); err != nil {
			continue
		}
		if vuln.ID == "" {
			continue
		}
		ecoStore[vuln.ID] = vuln
		count++
	}

	// Write the consolidated .db.bin file (single file, fast to load)
	// Using gob encoding for fast Go-native serialization (5-10x faster than JSON).
	dbBinPath := filepath.Join(ecoDir, ".db.bin")
	var binBuf bytes.Buffer
	enc := gob.NewEncoder(&binBuf)
	if err := enc.Encode(ecoStore); err != nil {
		// Fallback to JSON if gob fails
		binData, jsonErr := json.Marshal(ecoStore)
		if jsonErr != nil {
			return fmt.Errorf("failed to serialize .db.bin: %w", jsonErr)
		}
		if err := os.WriteFile(dbBinPath, binData, 0o644); err != nil {
			return fmt.Errorf("failed to write .db.bin: %w", err)
		}
	} else {
		if err := os.WriteFile(dbBinPath, binBuf.Bytes(), 0o644); err != nil {
			return fmt.Errorf("failed to write .db.bin: %w", err)
		}
	}

	// Also build the package→vulnIDs index and cache it
	ecoIndex := make(map[string][]string)
	for vid, vuln := range ecoStore {
		for _, affected := range vuln.Affected {
			if affected.Package != nil {
				key := fmt.Sprintf("%s:%s", bucket, affected.Package.Name)
				ecoIndex[key] = append(ecoIndex[key], vid)
			}
		}
	}
	if indexData, err := json.Marshal(ecoIndex); err == nil {
		_ = os.WriteFile(filepath.Join(ecoDir, ".index.json"), indexData, 0o644)
	}

	// Build the SQLite DB for fast indexed lookups (O(log n) per query)
	sqlitePath := SQLitePath(ecoDir)
	sqlStore, err := NewSQLiteStore(sqlitePath)
	if err == nil {
		_ = sqlStore.StoreBatch(ecoStore, bucket)
		_ = sqlStore.Close()
	}

	// Write metadata
	meta := struct {
		UpdatedAt   time.Time `json:"updated_at"`
		VulnCount   int       `json:"vuln_count"`
		Ecosystem   string    `json:"ecosystem"`
	}{
		UpdatedAt: time.Now(),
		VulnCount: count,
		Ecosystem: bucket,
	}
	metaData, _ := json.Marshal(meta)
	_ = os.WriteFile(filepath.Join(ecoDir, ".metadata.json"), metaData, 0o644)

	return nil
}

// extractZipFile extracts a single file from a zip archive.
func extractZipFile(file *zip.File, outPath string) error {
	rc, err := file.Open()
	if err != nil {
		return fmt.Errorf("opening zip entry %s: %w", file.Name, err)
	}
	defer rc.Close()

	out, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("creating output file %s: %w", outPath, err)
	}
	defer out.Close()

	if _, err := io.Copy(out, rc); err != nil {
		return fmt.Errorf("extracting %s to %s: %w", file.Name, outPath, err)
	}
	return nil
}

// Query looks up vulnerabilities for a package in the local DB.
// Returns the list of vulnerabilities that affect the given package and version.
// If the local DB is not available or the ecosystem is not loaded, returns nil.
//
// Query priority:
//  1. SQLite DB (if available) — single SQL query, O(log n)
//  2. In-memory index + lazy file loading — fallback for older DB downloads
func (db *LocalDB) Query(name, version string, ecosystem analysis.Ecosystem) []osv.Vulnerability {
	bucket := ecosystemToOSVBucket[ecosystem]
	if bucket == "" {
		return nil
	}

	ecoDir := filepath.Join(db.dir, bucket)

	// Path 0: Try SQLite first (fastest — single SQL query with index)
	if sqliteVulns := db.querySQLite(bucket, ecoDir, name, version, ecosystem); sqliteVulns != nil {
		return sqliteVulns
	}

	// Ensure the ecosystem index is loaded into memory
	db.mu.RLock()
	loaded := db.loaded[bucket]
	db.mu.RUnlock()

	if !loaded {
		db.loadEcosystem(bucket)
	}

	// Path 1: Use the in-memory index to find candidate vulnerability IDs
	// for this package name, then look up data from the vulnStore
	// (falling back to individual file reads for cache misses).
	db.mu.RLock()
	vulnIDs := db.index[fmt.Sprintf("%s:%s", bucket, name)]
	db.mu.RUnlock()

	if len(vulnIDs) == 0 {
		return nil
	}

	var vulns []osv.Vulnerability
	seen := make(map[string]bool)

	for _, vid := range vulnIDs {
		if seen[vid] {
			continue
		}
		seen[vid] = true

		// Check the in-memory store first (cache hit — no I/O)
		db.mu.RLock()
		vuln, ok := db.vulnStore[vid]
		db.mu.RUnlock()

		if !ok {
			// Cache miss — read from individual file or .db.bin
			vuln = db.loadVulnByID(bucket, ecoDir, vid)
			if vuln.ID == "" {
				continue
			}
		}

		// Check if this vulnerability affects the given package+version
		if vuln.IsWithdrawn() {
			continue
		}
		if vulnAffectsPackage(&vuln, name, version, ecosystem) {
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}

// querySQLite tries to query the SQLite DB for a package's vulnerabilities.
// Returns nil if SQLite is not available for this ecosystem.
func (db *LocalDB) querySQLite(bucket, ecoDir, name, version string, ecosystem analysis.Ecosystem) []osv.Vulnerability {
	sqlitePath := SQLitePath(ecoDir)
	if !HasSQLiteDB(ecoDir) {
		return nil
	}

	// Get or create a cached SQLite connection
	db.mu.Lock()
	store, ok := db.sqliteStores[bucket]
	if !ok {
		var err error
		store, err = NewSQLiteStore(sqlitePath)
		if err != nil {
			db.mu.Unlock()
			return nil
		}
		db.sqliteStores[bucket] = store
	}
	db.mu.Unlock()

	// Single SQL query with index lookup — O(log n)
	vulns, err := store.QueryVulnerabilities(bucket, name)
	if err != nil || len(vulns) == 0 {
		return nil
	}

	// Filter to vulnerabilities that affect the given version
	var result []osv.Vulnerability
	for _, vuln := range vulns {
		if vuln.IsWithdrawn() {
			continue
		}
		if vulnAffectsPackage(&vuln, name, version, ecosystem) {
			result = append(result, vuln)
		}
	}

	return result
}

// FetchVulnByID returns a full vulnerability by its ID from the local DB.
// This is used by the OSV client's EnrichAliases to fetch CVE aliases
// without hitting the API. Returns nil if not found.
func (db *LocalDB) FetchVulnByID(id string) *osv.Vulnerability {
	// Try each ecosystem's SQLite DB first (fastest)
	for _, bucket := range ecosystemToOSVBucket {
		ecoDir := filepath.Join(db.dir, bucket)
		if !HasSQLiteDB(ecoDir) {
			continue
		}

		db.mu.Lock()
		store, ok := db.sqliteStores[bucket]
		if !ok {
			s, err := NewSQLiteStore(SQLitePath(ecoDir))
			if err != nil {
				db.mu.Unlock()
				continue
			}
			store = s
			db.sqliteStores[bucket] = store
		}
		db.mu.Unlock()

		// Query SQLite for this vuln ID
		var data string
		err := store.db.QueryRow("SELECT data FROM vulnerabilities WHERE id = ?", id).Scan(&data)
		if err == nil {
			var vuln osv.Vulnerability
			if json.Unmarshal([]byte(data), &vuln) == nil {
				return &vuln
			}
		}
	}

	// Fallback: check in-memory vulnStore
	db.mu.RLock()
	for _, vuln := range db.vulnStore {
		if vuln.ID == id {
			v := vuln
			db.mu.RUnlock()
			return &v
		}
	}
	db.mu.RUnlock()

	return nil
}

// hasVulnFiles checks if individual vulnerability JSON files exist in the
// ecosystem directory (as opposed to only having a consolidated .db.bin).
func (db *LocalDB) hasVulnFiles(ecoDir string) bool {
	entries, err := os.ReadDir(ecoDir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".json") && name != ".metadata.json" && name != ".index.json" {
			return true
		}
	}
	return false
}

// loadVulnByID loads a single vulnerability by ID from disk. It tries the
// individual JSON file first (fast for small numbers of lookups), and caches
// the result in vulnStore for subsequent queries. This lazy-loading approach
// avoids loading the entire 20K+ vulnerability database into memory when we
// only need a few hundred entries per scan.
func (db *LocalDB) loadVulnByID(bucket, ecoDir, vulnID string) osv.Vulnerability {
	// Try individual file first (fast for cache misses)
	path := filepath.Join(ecoDir, vulnID+".json")
	if data, err := os.ReadFile(path); err == nil {
		var vuln osv.Vulnerability
		if err := json.Unmarshal(data, &vuln); err == nil {
			db.mu.Lock()
			db.vulnStore[vulnID] = vuln
			db.mu.Unlock()
			return vuln
		}
	}
	return osv.Vulnerability{}
}

// loadEcosystem loads the vulnerability index and vuln data for an ecosystem
// into memory. It first tries the consolidated .db.bin file (single read),
// falling back to the .index.json + individual files approach for backward
// compatibility with older DB downloads.
//
// The .db.bin file contains a serialized map[string]Vulnerability (vuln ID →
// full data), so loading it gives us both the index and the data in one read.
func (db *LocalDB) loadEcosystem(bucket string) {
	db.mu.Lock()
	defer db.mu.Unlock()

	if db.loaded[bucket] {
		return
	}

	ecoDir := filepath.Join(db.dir, bucket)
	dbBinPath := filepath.Join(ecoDir, ".db.bin")
	indexPath := filepath.Join(ecoDir, ".index.json")

	// Path 1: Try loading the consolidated .db.bin file (fast path).
	// This is a single file containing all vulnerabilities for the
	// ecosystem, keyed by vuln ID. Uses gob encoding for fast deserialization.
	// Falls back to JSON if the file was written in the old format.
	//
	// NOTE: We only load the .db.bin if it exists AND there are no individual
	// files (i.e., the download was done with the new format that doesn't
	// extract individual files). If individual files exist, we prefer the
	// lazy-loading approach (index.json + read files on demand) which is
	// faster for typical scans that only query a few hundred vulnerabilities.
	if data, err := os.ReadFile(dbBinPath); err == nil {
		// Check if individual files also exist
		hasIndividualFiles := db.hasVulnFiles(ecoDir)
		if !hasIndividualFiles {
			// No individual files — must load the entire .db.bin
			var store map[string]osv.Vulnerability
			dec := gob.NewDecoder(bytes.NewReader(data))
			if gobErr := dec.Decode(&store); gobErr == nil {
				for vid, vuln := range store {
					db.vulnStore[vid] = vuln
					for _, affected := range vuln.Affected {
						if affected.Package != nil {
							key := fmt.Sprintf("%s:%s", bucket, affected.Package.Name)
							db.index[key] = append(db.index[key], vid)
						}
					}
				}
				db.loaded[bucket] = true
				return
			}
			// Fallback: try JSON
			store = nil
			if jsonErr := json.Unmarshal(data, &store); jsonErr == nil {
				for vid, vuln := range store {
					db.vulnStore[vid] = vuln
					for _, affected := range vuln.Affected {
						if affected.Package != nil {
							key := fmt.Sprintf("%s:%s", bucket, affected.Package.Name)
							db.index[key] = append(db.index[key], vid)
						}
					}
				}
				db.loaded[bucket] = true
				return
			}
		}
	}

	// Path 2: Try loading the cached .index.json (backward compat).
	// This only has the package→vulnIDs mapping, not the actual data.
	// Vulnerability data is loaded lazily from individual files on demand
	// via loadVulnByID() — this avoids loading 20K files when we only need
	// a few hundred per scan.
	if data, err := os.ReadFile(indexPath); err == nil {
		var cachedIndex map[string][]string
		if err := json.Unmarshal(data, &cachedIndex); err == nil {
			for k, v := range cachedIndex {
				db.index[k] = v
			}
			// Don't load all vuln files here — use lazy loading in Query.
			// Build .db.bin for future use but don't load it now.
			db.loaded[bucket] = true
			return
		}
	}

	// Path 3: No cached index — build it by scanning all vulnerability files.
	entries, err := os.ReadDir(ecoDir)
	if err != nil {
		db.loaded[bucket] = true
		return
	}

	ecoIndex := make(map[string][]string)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		if entry.Name() == ".metadata.json" || entry.Name() == ".index.json" || entry.Name() == ".db.bin" {
			continue
		}

		path := filepath.Join(ecoDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		var vuln osv.Vulnerability
		if err := json.Unmarshal(data, &vuln); err != nil {
			continue
		}

		// Store in vulnStore and index
		db.vulnStore[vuln.ID] = vuln
		for _, affected := range vuln.Affected {
			if affected.Package != nil {
				key := fmt.Sprintf("%s:%s", bucket, affected.Package.Name)
				ecoIndex[key] = append(ecoIndex[key], vuln.ID)
			}
		}
	}

	// Merge into global index
	for k, v := range ecoIndex {
		db.index[k] = v
	}

	// Cache the index to disk for fast subsequent loads
	if indexData, err := json.Marshal(ecoIndex); err == nil {
		_ = os.WriteFile(indexPath, indexData, 0o644)
	}

	// Also build the consolidated .db.bin file for future fast loads
	db.buildDbBin(bucket, ecoDir)

	db.loaded[bucket] = true
}

// buildDbBin consolidates all individual vulnerability files for an ecosystem
// into a single .db.bin file. This file is a JSON-serialized
// map[string]Vulnerability (vuln ID → full data), enabling fast loads on
// subsequent scans (one file read instead of thousands).
func (db *LocalDB) buildDbBin(bucket, ecoDir string) {
	// Collect all vulnerabilities for this ecosystem from the store
	ecoStore := make(map[string]osv.Vulnerability)
	for vid, vuln := range db.vulnStore {
		// Only include vulns that have affected packages in this ecosystem
		for _, affected := range vuln.Affected {
			if affected.Package != nil && affected.Package.Ecosystem == bucket {
				ecoStore[vid] = vuln
				break
			}
		}
	}

	if len(ecoStore) == 0 {
		return
	}

	// Write the consolidated file using gob encoding (fast Go-native format)
	dbBinPath := filepath.Join(ecoDir, ".db.bin")
	var binBuf bytes.Buffer
	enc := gob.NewEncoder(&binBuf)
	if err := enc.Encode(ecoStore); err != nil {
		// Fallback to JSON
		data, jsonErr := json.Marshal(ecoStore)
		if jsonErr != nil {
			return
		}
		_ = os.WriteFile(dbBinPath, data, 0o644)
		return
	}
	_ = os.WriteFile(dbBinPath, binBuf.Bytes(), 0o644)
}

// vulnAffectsPackage checks if a vulnerability affects a specific package+version.
func vulnAffectsPackage(vuln *osv.Vulnerability, name, version string, ecosystem analysis.Ecosystem) bool {
	osvEco := ecosystemToOSVBucket[ecosystem]

	// Pass 1: Check if any specific (non-catch-all) range matches.
	// Also track if the version is "fixed" by a specific range (i.e., the
	// version is in the range's branch but past the fix).
	hasSpecificMatch := false
	isFixedBySpecific := false

	for _, affected := range vuln.Affected {
		if affected.Package == nil {
			continue
		}
		if affected.Package.Name != name || affected.Package.Ecosystem != osvEco {
			continue
		}
		for _, r := range affected.Ranges {
			// Only handle SEMVER and ECOSYSTEM ranges. GIT ranges use
			// commit hashes, not version numbers, so compareVersions can't
			// handle them correctly.
			if r.Type != "" && r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
				continue
			}
			introduced, fixed := parseRangeEvents(r)
			if introduced == "" {
				introduced = "0"
			}
			isCatchAll := introduced == "0" && fixed == ""

			if isCatchAll {
				continue // Handle catch-all in pass 2
			}

			// Use compareSemver for SEMVER ranges (handles pre-releases)
			cmp := compareVersions
			if r.Type == "SEMVER" {
				cmp = compareSemver
			}

			// Check if version is in this range's branch (>= introduced)
			if cmp(version, introduced) >= 0 {
				if fixed == "" {
					hasSpecificMatch = true
				} else if cmp(version, fixed) < 0 {
					hasSpecificMatch = true
				} else {
					// Version is >= introduced AND >= fixed → fixed in this branch
					isFixedBySpecific = true
				}
			}
		}
	}

	// If a specific range matches, the version is affected
	if hasSpecificMatch {
		return true
	}

	// If the version is fixed by a specific range, don't apply catch-all
	if isFixedBySpecific {
		return false
	}

	// Pass 2: Check catch-all ranges ([0, ∞))
	for _, affected := range vuln.Affected {
		if affected.Package == nil {
			continue
		}
		if affected.Package.Name != name || affected.Package.Ecosystem != osvEco {
			continue
		}
		for _, r := range affected.Ranges {
			// Only handle SEMVER and ECOSYSTEM ranges
			if r.Type != "" && r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
				continue
			}
			introduced, fixed := parseRangeEvents(r)
			if introduced == "" {
				introduced = "0"
			}
			isCatchAll := introduced == "0" && fixed == ""
			if isCatchAll {
				return true
			}
		}
	}

	return false
}

// parseRangeEvents extracts the introduced and fixed versions from a range's events.
func parseRangeEvents(r osv.Range) (introduced, fixed string) {
	for _, e := range r.Events {
		if e.Introduced != "" && e.Introduced != "0" {
			introduced = e.Introduced
		}
		if e.Fixed != "" {
			fixed = e.Fixed
		}
	}
	return
}

// isVersionAffected checks if a version falls within a single affected range.
// This handles the common cases of introduced/fixed events in semver and
// ecosystem-specific formats. Pre-release versions (e.g. 2.0.0-rc.4) are
// handled correctly: in semver, a pre-release of X.Y.Z is less than X.Y.Z.
func isVersionAffected(version string, r osv.Range) bool {
	if r.Type == "" || r.Type == "SEMVER" || r.Type == "ECOSYSTEM" {
		introduced := ""
		fixed := ""
		for _, e := range r.Events {
			if e.Introduced != "" && e.Introduced != "0" {
				introduced = e.Introduced
			}
			if e.Fixed != "" {
				fixed = e.Fixed
			}
		}
		// If no introduced, assume all versions up to fixed are affected
		if introduced == "" {
			introduced = "0"
		}
		// For SEMVER ranges, handle pre-release versions correctly.
		// A pre-release version like 2.0.0-rc.4 is LESS THAN 2.0.0.
		if r.Type == "SEMVER" {
			if isPreRelease(version) && !isPreRelease(introduced) {
				// Pre-release of X.Y.Z is < X.Y.Z, so if introduced is X.Y.Z,
				// the pre-release is not in range.
				if compareSemver(version, introduced) <= 0 {
					return false
				}
			}
		}
		// Simple version comparison
		if compareVersions(version, introduced) >= 0 {
			if fixed == "" {
				return true
			}
			if compareVersions(version, fixed) < 0 {
				return true
			}
		}
	}
	return false
}

// compareSemver compares two semver versions, correctly handling pre-release
// suffixes. A version with a pre-release suffix (e.g. "2.0.0-rc.4") is
// considered LESS THAN the same version without a pre-release (e.g. "2.0.0").
// This is important because strings.Split("2.0.0-rc.4", ".") produces
// ["2", "0", "0-rc", "4"], which would incorrectly compare as greater than
// ["2", "0", "0"].
func compareSemver(a, b string) int {
	// Strip pre-release suffixes for comparison
	aCore := stripPreRelease(a)
	bCore := stripPreRelease(b)
	cmp := compareVersions(aCore, bCore)
	if cmp != 0 {
		return cmp
	}
	// Same core version — pre-release < release
	aPre := isPreRelease(a)
	bPre := isPreRelease(b)
	if aPre && !bPre {
		return -1
	}
	if !aPre && bPre {
		return 1
	}
	return 0
}

// stripPreRelease removes the pre-release suffix from a version string.
// E.g. "2.0.0-rc.4" → "2.0.0", "1.0.0-beta" → "1.0.0"
func stripPreRelease(version string) string {
	if idx := strings.Index(version, "-"); idx > 0 {
		core := version[:idx]
		// Only strip if the character before "-" is a digit (part of version core)
		if len(core) > 0 && core[len(core)-1] >= '0' && core[len(core)-1] <= '9' {
			return core
		}
	}
	return version
}

// isPreRelease returns true if the version string contains a pre-release
// suffix (e.g. "2.0.0-rc.4", "1.0.0-beta", "3.0.0-alpha.1").
func isPreRelease(version string) bool {
	// Split off any build metadata first
	v := version
	if idx := strings.Index(v, "+"); idx >= 0 {
		v = v[:idx]
	}
	// Check for pre-release suffix after a hyphen
	if idx := strings.Index(v, "-"); idx >= 0 {
		// Make sure the hyphen is not part of the version core
		// (e.g. "1.2.3-rc.1" has a pre-release, "1.2.3" does not)
		core := v[:idx]
		if len(core) > 0 && core[len(core)-1] >= '0' && core[len(core)-1] <= '9' {
			return true
		}
	}
	return false
}

// compareVersions compares two version strings. Returns -1, 0, or 1.
// This is a simple comparison that splits on . and compares numerically
// where possible. It's not a full semver implementation but covers the
// common cases for OSV version ranges.
func compareVersions(a, b string) int {
	if a == b {
		return 0
	}
	pa := strings.Split(a, ".")
	pb := strings.Split(b, ".")
	maxLen := len(pa)
	if len(pb) > maxLen {
		maxLen = len(pb)
	}
	for i := 0; i < maxLen; i++ {
		var va, vb string
		if i < len(pa) {
			va = pa[i]
		}
		if i < len(pb) {
			vb = pb[i]
		}
		// Strip non-numeric suffixes for comparison
		va = numericPrefix(va)
		vb = numericPrefix(vb)
		na := atoiSafe(va)
		nb := atoiSafe(vb)
		if na < nb {
			return -1
		}
		if na > nb {
			return 1
		}
	}
	return 0
}

// numericPrefix extracts the leading numeric portion of a version segment.
func numericPrefix(s string) string {
	for i, c := range s {
		if c < '0' || c > '9' {
			return s[:i]
		}
	}
	return s
}

// atoiSafe converts a string to an int, returning 0 on failure.
func atoiSafe(s string) int {
	if s == "" {
		return 0
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// Stats returns statistics about the local DB.
func (db *LocalDB) Stats() map[string]int {
	stats := make(map[string]int)
	entries, err := os.ReadDir(db.dir)
	if err != nil {
		return stats
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		ecoDir := filepath.Join(db.dir, entry.Name())

		// Try .db.bin first (new format — count from the consolidated store)
		dbBinPath := filepath.Join(ecoDir, ".db.bin")
		if data, err := os.ReadFile(dbBinPath); err == nil {
			var store map[string]osv.Vulnerability
			// Try gob first
			dec := gob.NewDecoder(bytes.NewReader(data))
			if gobErr := dec.Decode(&store); gobErr == nil {
				stats[entry.Name()] = len(store)
				continue
			}
			// Fallback to JSON
			if jsonErr := json.Unmarshal(data, &store); jsonErr == nil {
				stats[entry.Name()] = len(store)
				continue
			}
		}

		// Fallback: count individual JSON files (old format)
		ecoEntries, err := os.ReadDir(ecoDir)
		if err != nil {
			continue
		}
		count := 0
		for _, e := range ecoEntries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") && e.Name() != ".metadata.json" && e.Name() != ".index.json" {
				count++
			}
		}
		stats[entry.Name()] = count
	}
	return stats
}

// ListEcosystems returns the ecosystems that have been downloaded.
func (db *LocalDB) ListEcosystems() []string {
	entries, err := os.ReadDir(db.dir)
	if err != nil {
		return nil
	}
	var result []string
	for _, entry := range entries {
		if entry.IsDir() {
			result = append(result, entry.Name())
		}
	}
	sort.Strings(result)
	return result
}
