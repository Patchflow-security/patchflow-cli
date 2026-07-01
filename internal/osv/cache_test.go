package osv

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
)

func newTestCache(t *testing.T, ttl time.Duration) *Cache {
	t.Helper()
	dir := t.TempDir()
	c := NewCache(dir)
	c.ttl = ttl
	return c
}

func TestCacheSetGetRoundtrip(t *testing.T) {
	c := newTestCache(t, time.Hour)
	key := cacheKey(analysis.Dependency{
		Name:      "lodash",
		Version:   "4.17.20",
		Ecosystem: analysis.EcosystemNPM,
	})
	vulns := []Vulnerability{
		{ID: "GHSA-1", Summary: "prototype pollution"},
		{ID: "CVE-2021-23337", Summary: "command injection"},
	}

	c.Set(key, vulns)
	got, ok := c.Get(key)
	if !ok {
		t.Fatal("expected cache hit, got miss")
	}
	if len(got) != len(vulns) {
		t.Fatalf("expected %d vulns, got %d", len(vulns), len(got))
	}
	if got[0].ID != vulns[0].ID {
		t.Errorf("expected first vuln ID %s, got %s", vulns[0].ID, got[0].ID)
	}
	if got[1].Summary != vulns[1].Summary {
		t.Errorf("expected second vuln summary %s, got %s", vulns[1].Summary, got[1].Summary)
	}
}

func TestCacheTTLExpiry(t *testing.T) {
	c := newTestCache(t, 50*time.Millisecond)
	key := "deadbeef"
	vulns := []Vulnerability{{ID: "GHSA-1"}}

	c.Set(key, vulns)
	if _, ok := c.Get(key); !ok {
		t.Fatal("expected cache hit before TTL expiry")
	}

	time.Sleep(60 * time.Millisecond)
	if _, ok := c.Get(key); ok {
		t.Fatal("expected cache miss after TTL expiry, got hit")
	}
}

func TestCacheMissReturnsFalse(t *testing.T) {
	c := newTestCache(t, time.Hour)
	if _, ok := c.Get("nonexistent-key"); ok {
		t.Fatal("expected cache miss for nonexistent key, got hit")
	}
}

func TestCacheCorruptedFileHandledGracefully(t *testing.T) {
	c := newTestCache(t, time.Hour)
	key := "corruptedkey"

	// Write a corrupted JSON file directly into the cache dir.
	if err := os.MkdirAll(c.dir, 0o755); err != nil {
		t.Fatalf("failed to create cache dir: %v", err)
	}
	path := filepath.Join(c.dir, key+".json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0o644); err != nil {
		t.Fatalf("failed to write corrupted file: %v", err)
	}

	if _, ok := c.Get(key); ok {
		t.Fatal("expected cache miss for corrupted file, got hit")
	}

	// The corrupted file should have been removed.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected corrupted file to be removed, but it still exists")
	}
}

func TestCacheKeyConsistent(t *testing.T) {
	dep := analysis.Dependency{
		Name:      "express",
		Version:   "4.17.1",
		Ecosystem: analysis.EcosystemNPM,
	}
	key1 := cacheKey(dep)
	key2 := cacheKey(dep)
	if key1 != key2 {
		t.Fatalf("cacheKey not consistent: %s != %s", key1, key2)
	}

	// Different version should produce a different key.
	dep2 := dep
	dep2.Version = "4.17.2"
	if cacheKey(dep2) == key1 {
		t.Fatal("expected different key for different version, got same")
	}

	// Different ecosystem should produce a different key.
	dep3 := analysis.Dependency{
		Name:      "express",
		Version:   "4.17.1",
		Ecosystem: analysis.EcosystemPyPI,
	}
	if cacheKey(dep3) == key1 {
		t.Fatal("expected different key for different ecosystem, got same")
	}
}

func TestCacheNilSafe(t *testing.T) {
	var c *Cache
	// Should not panic.
	c.Set("key", nil)
	if _, ok := c.Get("key"); ok {
		t.Fatal("expected miss for nil cache, got hit")
	}
}

func TestCacheSetCreatesDirLazily(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(dir)
	cacheDir := c.dir // resolved via cacheutil (global XDG location)

	// Directory should not exist before first Set.
	if _, err := os.Stat(cacheDir); !os.IsNotExist(err) {
		t.Fatal("expected cache dir to not exist before first Set")
	}

	c.Set("somekey", []Vulnerability{{ID: "GHSA-1"}})

	// Directory should now exist.
	if _, err := os.Stat(cacheDir); err != nil {
		t.Fatalf("expected cache dir to exist after Set, got error: %v", err)
	}
}
