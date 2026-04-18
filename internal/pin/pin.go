// Package pin resolves GitHub Action refs to 40-char commit SHAs and rewrites
// workflow files in place.
package pin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/kdairatchi/ghactor/internal/ghapi"
	"github.com/kdairatchi/ghactor/internal/workflow"
)

// DefaultTTL is the out-of-the-box TTL applied by NewResolver.
// Entries older than this are considered stale and re-fetched transparently.
const DefaultTTL = 30 * 24 * time.Hour

// ResolveFunc looks up the 40-char commit SHA for a ref on GitHub.
// Injectable so tests don't need network or `gh`.
type ResolveFunc func(owner, repo, ref string) (string, error)

// Resolver resolves GitHub Action refs to pinned SHAs, backed by a TTL-aware
// on-disk cache. Use NewResolver for production; NewResolverWithTTL when you
// need a custom TTL (including TTL=0 for "never expire").
type Resolver struct {
	cachePath string
	ttl       time.Duration
	now       func() time.Time // injectable for tests; defaults to time.Now

	mu    sync.Mutex
	cache cacheFile
	dirty bool

	// Fetch is the network back-end. Tests may replace it without hitting GitHub.
	Fetch ResolveFunc
}

// NewResolver returns a Resolver with DefaultTTL (30 days).
// All callers in main.go continue to work unchanged.
func NewResolver(cachePath string) *Resolver {
	return NewResolverWithTTL(cachePath, DefaultTTL)
}

// NewResolverWithTTL returns a Resolver with the specified TTL.
// TTL=0 disables expiry entirely (all cached entries are served forever).
func NewResolverWithTTL(cachePath string, ttl time.Duration) *Resolver {
	r := &Resolver{
		cachePath: cachePath,
		ttl:       ttl,
		now:       time.Now,
	}
	cf, err := loadCache(cachePath)
	if err == nil {
		r.cache = cf
	} else {
		r.cache = cacheFile{Version: cacheVersion, Entries: map[string]*cacheEntry{}}
	}
	client, err := ghapi.New()
	if err != nil {
		// No auth available; Fetch stays nil and will error on first use.
		return r
	}
	r.Fetch = buildResolveSHA(client)
	return r
}

// Save flushes any dirty cache entries to disk.
// If TTL > 0, entries older than 3×TTL are pruned first.
func (r *Resolver) Save() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.dirty || r.cachePath == "" {
		return nil
	}
	return saveCache(r.cachePath, r.cache, r.ttl, r.now)
}

var sha40 = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Resolve returns the 40-char SHA for owner/repo@ref.
// If ref is already a full SHA it is returned as-is.
//
// Cache behaviour:
//   - A cached entry is served if its age is less than TTL (or TTL == 0).
//   - A stale or missing entry triggers a live fetch; the result is stored with
//     the current timestamp so the TTL window resets.
func (r *Resolver) Resolve(owner, repo, ref string) (string, error) {
	if sha40.MatchString(ref) {
		return ref, nil
	}
	key := fmt.Sprintf("%s/%s@%s", owner, repo, ref)

	r.mu.Lock()
	entry, ok := r.cache.Entries[key]
	if ok && !r.isStale(entry) {
		sha := entry.SHA
		r.mu.Unlock()
		return sha, nil
	}
	r.mu.Unlock()

	fetch := r.Fetch
	if fetch == nil {
		return "", fmt.Errorf("no GitHub auth: set GITHUB_TOKEN or authenticate via gh CLI")
	}
	sha, err := fetch(owner, repo, ref)
	if err != nil {
		return "", err
	}

	r.mu.Lock()
	r.cache.Entries[key] = &cacheEntry{SHA: sha, ResolvedAt: r.now()}
	r.dirty = true
	r.mu.Unlock()
	return sha, nil
}

// isStale reports whether e should be ignored due to TTL expiry.
// Must be called with r.mu held (or from a context where no writes can race).
func (r *Resolver) isStale(e *cacheEntry) bool {
	if r.ttl == 0 {
		return false
	}
	return r.now().Sub(e.ResolvedAt) > r.ttl
}

// buildResolveSHA returns a ResolveFunc backed by a ghapi.Client.
// Errors from the client are wrapped so callers can use errors.Is against
// ghapi sentinel errors.
func buildResolveSHA(c *ghapi.Client) ResolveFunc {
	return func(owner, repo, ref string) (string, error) {
		path := fmt.Sprintf("/repos/%s/%s/commits/%s", owner, repo, ref)
		out, err := c.Get(context.Background(), path)
		if err != nil {
			if errors.Is(err, ghapi.ErrNotFound) {
				return "", fmt.Errorf("resolve %s/%s@%s: %w", owner, repo, ref, ghapi.ErrNotFound)
			}
			if errors.Is(err, ghapi.ErrAuth) {
				return "", fmt.Errorf("resolve %s/%s@%s: %w", owner, repo, ref, ghapi.ErrAuth)
			}
			if errors.Is(err, ghapi.ErrRateLimit) {
				return "", fmt.Errorf("resolve %s/%s@%s: %w", owner, repo, ref, ghapi.ErrRateLimit)
			}
			return "", fmt.Errorf("resolve %s/%s@%s: %w", owner, repo, ref, err)
		}
		// GitHub returns a full commit object; extract the top-level "sha" field
		// without pulling in encoding/json for a small struct.
		sha := extractJSONString(out, "sha")
		if !sha40.MatchString(sha) {
			return "", fmt.Errorf("unexpected sha %q for %s/%s@%s", sha, owner, repo, ref)
		}
		return sha, nil
	}
}

// extractJSONString is a minimal helper that finds the first "key":"value" pair
// in a JSON byte slice without a full unmarshal. It only handles unescaped
// ASCII strings, which is fine for a hex SHA.
func extractJSONString(data []byte, key string) string {
	needle := `"` + key + `":`
	idx := strings.Index(string(data), needle)
	if idx < 0 {
		return ""
	}
	rest := strings.TrimSpace(string(data[idx+len(needle):]))
	if len(rest) == 0 || rest[0] != '"' {
		return ""
	}
	rest = rest[1:]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return ""
	}
	return rest[:end]
}

type Change struct {
	File    string
	Line    int
	Uses    string
	NewUses string
	Comment string
}

// Pin walks workflows, resolves each uses: to a SHA, and rewrites files in place unless dry.
func Pin(dir string, r *Resolver, dry bool) ([]Change, error) {
	files, err := workflow.LoadDir(dir)
	if err != nil {
		return nil, err
	}
	var changes []Change
	for _, f := range files {
		fileChanges, err := pinFile(f, r, dry)
		if err != nil {
			return changes, err
		}
		changes = append(changes, fileChanges...)
	}
	return changes, r.Save()
}

var usesLine = regexp.MustCompile(`^(\s*-?\s*uses:\s*)([^\s#]+)(\s*(#.*)?)$`)

func pinFile(f *workflow.File, r *Resolver, dry bool) ([]Change, error) {
	lines := strings.Split(string(f.Source), "\n")
	var changes []Change
	modified := false

	for i, line := range lines {
		m := usesLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		uses := m[2]
		if strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, "docker://") {
			continue
		}
		owner, repo, ref, ok := splitUses(uses)
		if !ok {
			continue
		}
		if sha40.MatchString(ref) {
			continue
		}
		sha, err := r.Resolve(owner, repo, ref)
		if err != nil {
			return changes, fmt.Errorf("%s:%d: resolve %s: %w", f.Path, i+1, uses, err)
		}
		newUses := fmt.Sprintf("%s/%s@%s", owner, repo, sha)
		comment := fmt.Sprintf("# %s", ref)
		newLine := m[1] + newUses + " " + comment
		changes = append(changes, Change{
			File: f.Path, Line: i + 1, Uses: uses, NewUses: newUses, Comment: ref,
		})
		if !dry {
			lines[i] = newLine
			modified = true
		}
	}

	if modified && !dry {
		if err := os.WriteFile(f.Path, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
			return changes, err
		}
	}
	return changes, nil
}

// Pinned describes a target SHA+tag for a uses-key, used by `update --apply`.
type Pinned struct {
	SHA string
	Tag string
}

// Key returns the `owner/repo[/path]` portion of a uses: value.
func Key(uses string) string {
	at := strings.LastIndex(uses, "@")
	if at < 0 {
		return uses
	}
	return uses[:at]
}

// RewriteFileTo applies Pinned targets to a workflow file (identified by path + source bytes).
func RewriteFileTo(path string, source []byte, targets map[string]Pinned, dry bool) ([]Change, []byte, error) {
	lines := strings.Split(string(source), "\n")
	var changes []Change
	modified := false
	for i, line := range lines {
		m := usesLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		uses := m[2]
		key := Key(uses)
		tgt, ok := targets[key]
		if !ok || tgt.SHA == "" {
			continue
		}
		newUses := fmt.Sprintf("%s@%s", key, tgt.SHA)
		if uses == newUses {
			continue
		}
		changes = append(changes, Change{
			File: path, Line: i + 1, Uses: uses, NewUses: newUses, Comment: tgt.Tag,
		})
		if !dry {
			lines[i] = m[1] + newUses + " # " + tgt.Tag
			modified = true
		}
	}
	var out []byte
	if modified {
		out = []byte(strings.Join(lines, "\n"))
		if !dry {
			if err := os.WriteFile(path, out, 0o644); err != nil {
				return changes, nil, err
			}
		}
	}
	return changes, out, nil
}

func splitUses(uses string) (owner, repo, ref string, ok bool) {
	at := strings.LastIndex(uses, "@")
	if at < 0 {
		return "", "", "", false
	}
	ref = uses[at+1:]
	full := uses[:at]
	// owner/repo or owner/repo/path (monorepo action)
	parts := strings.SplitN(full, "/", 3)
	if len(parts) < 2 {
		return "", "", "", false
	}
	return parts[0], parts[1], ref, true
}
