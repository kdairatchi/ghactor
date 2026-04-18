package pin

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

const cacheVersion = 2

// cacheEntry holds the resolved SHA and the wall-clock time it was fetched.
type cacheEntry struct {
	SHA        string    `json:"sha"`
	ResolvedAt time.Time `json:"resolved_at"`
}

// cacheFile is the on-disk representation for version 2.
//
//	{
//	  "version": 2,
//	  "entries": {
//	    "actions/checkout@v4": {"sha": "11bd71...", "resolved_at": "2026-04-18T12:00:00Z"}
//	  }
//	}
type cacheFile struct {
	Version int                    `json:"version"`
	Entries map[string]*cacheEntry `json:"entries"`
}

// loadCache reads the cache file at path.
// It supports two on-disk shapes:
//
//   - Version 2 (cacheFile): parsed verbatim.
//   - Version 1 / flat map (map[string]string): migrated to version 2 with
//     ResolvedAt set to the zero time so that TTL-aware callers treat them as
//     fresh (age = now − zero ≈ 56 years, which will exceed any reasonable TTL
//     and force a re-fetch on the next access — intentional for stale data).
//     Callers that want "treat migration entries as fresh" should set
//     ResolvedAt = now themselves; we use zero here so the TTL eviction logic
//     naturally re-validates them.
//
// If the file does not exist, an empty cacheFile is returned without error.
func loadCache(path string) (cacheFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cacheFile{Version: cacheVersion, Entries: map[string]*cacheEntry{}}, nil
		}
		return cacheFile{}, err
	}

	// Peek at the top-level shape to detect version.
	var probe struct {
		Version int `json:"version"`
	}
	if json.Unmarshal(data, &probe) == nil && probe.Version == cacheVersion {
		var cf cacheFile
		if err := json.Unmarshal(data, &cf); err != nil {
			return cacheFile{}, err
		}
		if cf.Entries == nil {
			cf.Entries = map[string]*cacheEntry{}
		}
		return cf, nil
	}

	// Legacy: flat map[string]string — version 1 or bare JSON object.
	var flat map[string]string
	if err := json.Unmarshal(data, &flat); err != nil {
		// Unrecognised format; start fresh rather than failing hard.
		return cacheFile{Version: cacheVersion, Entries: map[string]*cacheEntry{}}, nil
	}
	cf := cacheFile{
		Version: cacheVersion,
		Entries: make(map[string]*cacheEntry, len(flat)),
	}
	// Treat migrated entries as having ResolvedAt = zero so they look older
	// than any TTL and get refreshed on first access. This is the safest
	// migration strategy: we don't silently trust old, potentially stale SHAs.
	for k, sha := range flat {
		cf.Entries[k] = &cacheEntry{SHA: sha, ResolvedAt: time.Time{}}
	}
	return cf, nil
}

// saveCache writes cf to path (creates parent directories as needed).
// If ttl > 0, entries whose age exceeds 3×ttl are dropped before writing.
func saveCache(path string, cf cacheFile, ttl time.Duration, nowFn func() time.Time) error {
	if ttl > 0 {
		cutoff := nowFn().Add(-3 * ttl)
		for k, e := range cf.Entries {
			// Evict entries that are at or beyond 3×TTL old.
			if !e.ResolvedAt.After(cutoff) {
				delete(cf.Entries, k)
			}
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
