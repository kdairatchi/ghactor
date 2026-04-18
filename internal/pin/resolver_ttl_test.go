package pin

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock returns a function that always returns t.
func fakeClock(t time.Time) func() time.Time { return func() time.Time { return t } }

const (
	shaA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	shaB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// newTestResolver builds a Resolver wired to the given fake clock and fetch function,
// with no cachePath (in-memory only).
func newTestResolver(ttl time.Duration, now func() time.Time, fetch ResolveFunc) *Resolver {
	return &Resolver{
		cachePath: "",
		ttl:       ttl,
		now:       now,
		cache:     cacheFile{Version: cacheVersion, Entries: map[string]*cacheEntry{}},
		Fetch:     fetch,
	}
}

// ---- TTL expiry behaviour -----------------------------------------------

func TestTTLExpiry(t *testing.T) {
	const ttl = 30 * 24 * time.Hour
	base := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		entryAge    time.Duration // how old the cached entry is (relative to base)
		wantFetch   bool          // should Fetch be called?
		wantSHA     string
	}{
		{
			name:      "fresh entry served from cache",
			entryAge:  ttl / 2,
			wantFetch: false,
			wantSHA:   shaA,
		},
		{
			name:      "entry exactly at TTL boundary served from cache",
			entryAge:  ttl,
			wantFetch: false,
			wantSHA:   shaA,
		},
		{
			name:      "entry one nanosecond past TTL triggers re-fetch",
			entryAge:  ttl + time.Nanosecond,
			wantFetch: true,
			wantSHA:   shaB,
		},
		{
			name:      "entry far older than TTL triggers re-fetch",
			entryAge:  90 * 24 * time.Hour,
			wantFetch: true,
			wantSHA:   shaB,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls int32
			r := newTestResolver(ttl, fakeClock(base), func(_, _, _ string) (string, error) {
				atomic.AddInt32(&calls, 1)
				return shaB, nil
			})

			// Pre-populate cache with an entry whose age is tc.entryAge.
			resolvedAt := base.Add(-tc.entryAge)
			r.cache.Entries["actions/checkout@v4"] = &cacheEntry{SHA: shaA, ResolvedAt: resolvedAt}

			got, err := r.Resolve("actions", "checkout", "v4")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if tc.wantFetch && calls != 1 {
				t.Errorf("expected 1 fetch call, got %d", calls)
			}
			if !tc.wantFetch && calls != 0 {
				t.Errorf("expected 0 fetch calls (cache hit), got %d", calls)
			}
			if got != tc.wantSHA {
				t.Errorf("SHA = %q, want %q", got, tc.wantSHA)
			}
		})
	}
}

// ---- TTL=0 (never expire) -----------------------------------------------

func TestTTLZeroNeverExpires(t *testing.T) {
	base := time.Date(2026, 4, 18, 0, 0, 0, 0, time.UTC)
	// Entry was resolved 10 years ago — should still be served.
	veryOld := base.Add(-10 * 365 * 24 * time.Hour)

	var calls int32
	r := newTestResolver(0 /* TTL=0 */, fakeClock(base), func(_, _, _ string) (string, error) {
		atomic.AddInt32(&calls, 1)
		return shaB, nil
	})
	r.cache.Entries["actions/checkout@v4"] = &cacheEntry{SHA: shaA, ResolvedAt: veryOld}

	got, err := r.Resolve("actions", "checkout", "v4")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if calls != 0 {
		t.Errorf("TTL=0 should never expire: got %d fetch calls", calls)
	}
	if got != shaA {
		t.Errorf("SHA = %q, want %q", got, shaA)
	}
}

// ---- Legacy flat-map migration ------------------------------------------

func TestLegacyFlatMapMigration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	// Write a version-1 flat map.
	flat := map[string]string{
		"actions/checkout@v4":  shaA,
		"actions/setup-go@v5":  shaB,
	}
	data, _ := json.MarshalIndent(flat, "", "  ")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	cf, err := loadCache(path)
	if err != nil {
		t.Fatalf("loadCache: %v", err)
	}
	if cf.Version != cacheVersion {
		t.Errorf("version = %d, want %d", cf.Version, cacheVersion)
	}
	if len(cf.Entries) != 2 {
		t.Fatalf("entries count = %d, want 2", len(cf.Entries))
	}
	// All migrated entries must have their SHAs intact.
	for key, wantSHA := range flat {
		e, ok := cf.Entries[key]
		if !ok {
			t.Errorf("key %q missing after migration", key)
			continue
		}
		if e.SHA != wantSHA {
			t.Errorf("key %q: SHA = %q, want %q", key, e.SHA, wantSHA)
		}
		// Migration leaves ResolvedAt as zero so stale-detection forces re-fetch.
		if !e.ResolvedAt.IsZero() {
			t.Errorf("key %q: expected zero ResolvedAt after migration, got %v", key, e.ResolvedAt)
		}
	}
}

// TestMigratedEntriesTreatedAsStale verifies that after a flat-map migration,
// a TTL-aware Resolver re-fetches the migrated entries rather than serving them.
func TestMigratedEntriesTreatedAsStale(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	flat := map[string]string{"actions/checkout@v4": shaA}
	data, _ := json.MarshalIndent(flat, "", "  ")
	os.WriteFile(path, data, 0o644)

	base := time.Date(2026, 4, 18, 0, 0, 0, 0, time.UTC)
	var calls int32
	r := &Resolver{
		cachePath: path,
		ttl:       30 * 24 * time.Hour,
		now:       fakeClock(base),
		Fetch: func(_, _, _ string) (string, error) {
			atomic.AddInt32(&calls, 1)
			return shaB, nil
		},
	}
	cf, _ := loadCache(path)
	r.cache = cf

	got, err := r.Resolve("actions", "checkout", "v4")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if calls != 1 {
		t.Errorf("migrated entry should trigger re-fetch: got %d calls", calls)
	}
	if got != shaB {
		t.Errorf("SHA = %q, want %q", got, shaB)
	}
}

// ---- Roundtrip: Save then Load ------------------------------------------

func TestSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	base := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)

	var fetchCalls int32
	r := &Resolver{
		cachePath: path,
		ttl:       DefaultTTL,
		now:       fakeClock(base),
		cache:     cacheFile{Version: cacheVersion, Entries: map[string]*cacheEntry{}},
		Fetch: func(_, repo, ref string) (string, error) {
			atomic.AddInt32(&fetchCalls, 1)
			return fmt.Sprintf("%040d", fetchCalls), nil
		},
	}

	keys := []struct{ owner, repo, ref string }{
		{"actions", "checkout", "v4"},
		{"actions", "setup-go", "v5"},
		{"google-github-actions", "auth", "v2"},
	}
	shas := make([]string, len(keys))
	for i, k := range keys {
		sha, err := r.Resolve(k.owner, k.repo, k.ref)
		if err != nil {
			t.Fatalf("Resolve %v: %v", k, err)
		}
		shas[i] = sha
	}
	if err := r.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Load into a fresh resolver with TTL > entry age (all entries should be hits).
	r2 := &Resolver{
		cachePath: path,
		ttl:       DefaultTTL,
		now:       fakeClock(base.Add(time.Hour)), // 1 hour later — still fresh
		Fetch: func(_, _, _ string) (string, error) {
			t.Error("unexpected fetch after load")
			return "", nil
		},
	}
	cf, err := loadCache(path)
	if err != nil {
		t.Fatalf("loadCache: %v", err)
	}
	r2.cache = cf

	for i, k := range keys {
		got, err := r2.Resolve(k.owner, k.repo, k.ref)
		if err != nil {
			t.Fatalf("Resolve after load %v: %v", k, err)
		}
		if got != shas[i] {
			t.Errorf("key %v: SHA = %q, want %q", k, got, shas[i])
		}
	}
}

// ---- Eviction during Save -----------------------------------------------

func TestSaveEvictsVeryOldEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	const ttl = 30 * 24 * time.Hour
	base := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)

	r := &Resolver{
		cachePath: path,
		ttl:       ttl,
		now:       fakeClock(base),
		dirty:     true,
		cache: cacheFile{
			Version: cacheVersion,
			Entries: map[string]*cacheEntry{
				// Fresh entry — should survive.
				"actions/checkout@v4": {SHA: shaA, ResolvedAt: base.Add(-ttl / 2)},
				// Exactly 3×TTL old — should be evicted.
				"actions/setup-go@v4": {SHA: shaB, ResolvedAt: base.Add(-3 * ttl)},
				// Older than 3×TTL — should be evicted.
				"actions/cache@v3": {SHA: shaB, ResolvedAt: base.Add(-4 * ttl)},
			},
		},
	}
	if err := r.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	cf, err := loadCache(path)
	if err != nil {
		t.Fatalf("loadCache after save: %v", err)
	}
	if _, ok := cf.Entries["actions/checkout@v4"]; !ok {
		t.Error("fresh entry was wrongly evicted")
	}
	if _, ok := cf.Entries["actions/setup-go@v4"]; ok {
		t.Error("entry at 3×TTL boundary should have been evicted")
	}
	if _, ok := cf.Entries["actions/cache@v3"]; ok {
		t.Error("entry older than 3×TTL should have been evicted")
	}
}

// TestSaveNoEvictionWhenTTLZero ensures eviction is skipped when TTL=0.
func TestSaveNoEvictionWhenTTLZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	base := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)

	ancient := base.Add(-100 * 365 * 24 * time.Hour)
	r := &Resolver{
		cachePath: path,
		ttl:       0, // never expire
		now:       fakeClock(base),
		dirty:     true,
		cache: cacheFile{
			Version: cacheVersion,
			Entries: map[string]*cacheEntry{
				"actions/checkout@v4": {SHA: shaA, ResolvedAt: ancient},
			},
		},
	}
	if err := r.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	cf, err := loadCache(path)
	if err != nil {
		t.Fatalf("loadCache: %v", err)
	}
	if _, ok := cf.Entries["actions/checkout@v4"]; !ok {
		t.Error("TTL=0: ancient entry should not be evicted")
	}
}

// ---- On-disk JSON shape -------------------------------------------------

func TestOnDiskJSONShape(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	base := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)

	r := &Resolver{
		cachePath: path,
		ttl:       DefaultTTL,
		now:       fakeClock(base),
		dirty:     true,
		cache: cacheFile{
			Version: cacheVersion,
			Entries: map[string]*cacheEntry{
				"actions/checkout@v4": {SHA: shaA, ResolvedAt: base},
			},
		},
	}
	if err := r.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	raw, _ := os.ReadFile(path)
	var probe struct {
		Version int `json:"version"`
		Entries map[string]struct {
			SHA        string `json:"sha"`
			ResolvedAt string `json:"resolved_at"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("disk JSON invalid: %v\n%s", err, raw)
	}
	if probe.Version != 2 {
		t.Errorf("version = %d, want 2", probe.Version)
	}
	e, ok := probe.Entries["actions/checkout@v4"]
	if !ok {
		t.Fatal("entry missing from disk")
	}
	if e.SHA != shaA {
		t.Errorf("sha = %q, want %q", e.SHA, shaA)
	}
	if e.ResolvedAt == "" {
		t.Error("resolved_at is empty")
	}
}
