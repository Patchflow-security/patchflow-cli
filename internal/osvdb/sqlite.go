// Package osvdb provides a local mirror of the OSV.dev vulnerability database.
// This file implements a SQLite-backed vulnerability store for fast lookups.
// The SQLite DB has two tables:
//   - vulnerabilities(id TEXT PRIMARY KEY, data TEXT)
//   - package_index(ecosystem TEXT, package TEXT, vuln_id TEXT)
// with an index on (ecosystem, package) for O(log n) lookups.
package osvdb

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	_ "modernc.org/sqlite"

	osv "github.com/Patchflow-security/patchflow-cli/internal/osv"
)

// SQLiteStore is a SQLite-backed vulnerability store.
type SQLiteStore struct {
	db   *sql.DB
	path string
	mu   sync.Mutex
}

// NewSQLiteStore opens or creates a SQLite store at the given path.
func NewSQLiteStore(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite db: %w", err)
	}

	// Create tables if they don't exist
	schema := `
	CREATE TABLE IF NOT EXISTS vulnerabilities (
		id   TEXT PRIMARY KEY,
		data TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS package_index (
		ecosystem TEXT NOT NULL,
		package   TEXT NOT NULL,
		vuln_id   TEXT NOT NULL,
		FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
	);
	CREATE INDEX IF NOT EXISTS idx_package ON package_index(ecosystem, package);
	`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	return &SQLiteStore{db: db, path: path}, nil
}

// Close closes the database connection.
func (s *SQLiteStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// StoreVulnerability stores a vulnerability and indexes its affected packages.
func (s *SQLiteStore) StoreVulnerability(vuln osv.Vulnerability, bucket string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(vuln)
	if err != nil {
		return err
	}

	// Insert vulnerability
	_, err = s.db.Exec("INSERT OR REPLACE INTO vulnerabilities (id, data) VALUES (?, ?)", vuln.ID, string(data))
	if err != nil {
		return err
	}

	// Index affected packages
	for _, affected := range vuln.Affected {
		if affected.Package != nil {
			_, err = s.db.Exec("INSERT OR IGNORE INTO package_index (ecosystem, package, vuln_id) VALUES (?, ?, ?)",
				bucket, affected.Package.Name, vuln.ID)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// StoreBatch stores multiple vulnerabilities in a single transaction for efficiency.
func (s *SQLiteStore) StoreBatch(vulns map[string]osv.Vulnerability, bucket string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Insert vulnerabilities
	stmtVuln, err := tx.Prepare("INSERT OR REPLACE INTO vulnerabilities (id, data) VALUES (?, ?)")
	if err != nil {
		return err
	}
	defer stmtVuln.Close()

	stmtIdx, err := tx.Prepare("INSERT OR IGNORE INTO package_index (ecosystem, package, vuln_id) VALUES (?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmtIdx.Close()

	for vid, vuln := range vulns {
		data, err := json.Marshal(vuln)
		if err != nil {
			continue
		}
		if _, err := stmtVuln.Exec(vid, string(data)); err != nil {
			continue
		}
		for _, affected := range vuln.Affected {
			if affected.Package != nil {
				_, _ = stmtIdx.Exec(bucket, affected.Package.Name, vid)
			}
		}
	}

	return tx.Commit()
}

// QueryVulnerabilities returns all vulnerabilities for a given package in an ecosystem.
// This does a single SQL query with an index lookup — O(log n) instead of
// scanning individual files.
func (s *SQLiteStore) QueryVulnerabilities(bucket, pkgName string) ([]osv.Vulnerability, error) {
	rows, err := s.db.Query(
		`SELECT v.data FROM vulnerabilities v
		 JOIN package_index p ON v.id = p.vuln_id
		 WHERE p.ecosystem = ? AND p.package = ?`,
		bucket, pkgName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vulns []osv.Vulnerability
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			continue
		}
		var vuln osv.Vulnerability
		if err := json.Unmarshal([]byte(data), &vuln); err != nil {
			continue
		}
		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

// Count returns the number of vulnerabilities in the store.
func (s *SQLiteStore) Count() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM vulnerabilities").Scan(&count)
	return count, err
}

// SQLitePath returns the path for the SQLite DB file for an ecosystem.
func SQLitePath(ecoDir string) string {
	return filepath.Join(ecoDir, ".db.sqlite")
}

// HasSQLiteDB returns true if a SQLite DB exists for the ecosystem.
func HasSQLiteDB(ecoDir string) bool {
	_, err := os.Stat(SQLitePath(ecoDir))
	return err == nil
}
