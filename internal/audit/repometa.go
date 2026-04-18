package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// RepoMetaFetcher fetches repository metadata from GitHub.
// Implementations must be safe for concurrent use.
type RepoMetaFetcher interface {
	// RepoMeta returns archival status for an owner/repo pair.
	// archived=true means the repo is archived.
	// exists=false means the repo returned 404 (deleted or renamed).
	// archivedAt is the ISO 8601 timestamp when the repo was archived, or "".
	// On network/auth error the error is returned; archived and exists are zero.
	RepoMeta(owner, repo string) (archived bool, exists bool, archivedAt string, err error)
}

// repoMetaResponse is the minimal shape of GET /repos/{owner}/{repo}.
type repoMetaResponse struct {
	Archived  bool   `json:"archived"`
	UpdatedAt string `json:"updated_at"` // ISO 8601 — GitHub doesn't expose archived_at directly
	PushedAt  string `json:"pushed_at"`
}

// DefaultRepoMetaFetcher implements RepoMetaFetcher against the GitHub REST API.
// Token resolution order matches trail.resolveToken:
//  1. GHACTOR_GITHUB_TOKEN
//  2. GITHUB_TOKEN
//  3. `gh auth token`
//  4. Unauthenticated (warns on stderr once)
type DefaultRepoMetaFetcher struct {
	token       string
	warned      bool // unauthenticated warning printed
	httpClient  *http.Client
	apiBase     string // override in tests via newDefaultFetcherWithBase
}

// NewDefaultRepoMetaFetcher constructs a fetcher with auto-resolved token.
// It never returns an error; missing auth results in unauthenticated requests.
func NewDefaultRepoMetaFetcher() *DefaultRepoMetaFetcher {
	return &DefaultRepoMetaFetcher{
		token:      resolveAuditToken(),
		httpClient: &http.Client{Timeout: 10 * time.Second},
		apiBase:    "https://api.github.com",
	}
}

// resolveAuditToken resolves the best available GitHub token.
// Resolution order: GHACTOR_GITHUB_TOKEN → GITHUB_TOKEN → `gh auth token`.
// Returns "" when nothing is available; callers warn the user.
func resolveAuditToken() string {
	if t := os.Getenv("GHACTOR_GITHUB_TOKEN"); t != "" {
		return t
	}
	if t := os.Getenv("GITHUB_TOKEN"); t != "" {
		return t
	}
	if out, err := exec.Command("gh", "auth", "token").Output(); err == nil {
		if tok := strings.TrimSpace(string(out)); tok != "" {
			return tok
		}
	}
	return ""
}

// RepoMeta fetches repository metadata for owner/repo.
func (f *DefaultRepoMetaFetcher) RepoMeta(owner, repo string) (archived bool, exists bool, archivedAt string, err error) {
	if f.token == "" && !f.warned {
		fmt.Fprintln(os.Stderr,
			"ghactor audit: no GitHub token found; repo-meta checks are unauthenticated (60 req/hr). "+
				"Set GHACTOR_GITHUB_TOKEN or GITHUB_TOKEN to authenticate.")
		f.warned = true
	}

	path := fmt.Sprintf("%s/repos/%s/%s", f.apiBase, owner, repo)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return false, false, "", fmt.Errorf("repometa: build request %s/%s: %w", owner, repo, err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if f.token != "" {
		req.Header.Set("Authorization", "Bearer "+f.token)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return false, false, "", fmt.Errorf("repometa: http %s/%s: %w", owner, repo, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return false, false, "", nil
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return false, false, "", fmt.Errorf("repometa: %s/%s: %w", owner, repo, errRepoMetaAuth)
	}
	if resp.StatusCode == http.StatusForbidden {
		return false, false, "", fmt.Errorf("repometa: %s/%s: %w", owner, repo, errRepoMetaRateLimit)
	}
	if resp.StatusCode != http.StatusOK {
		return false, false, "", fmt.Errorf("repometa: %s/%s: unexpected status %d", owner, repo, resp.StatusCode)
	}

	var meta repoMetaResponse
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return false, false, "", fmt.Errorf("repometa: decode %s/%s: %w", owner, repo, err)
	}

	// GitHub REST does not expose an archived_at field. We surface updated_at as
	// a proxy — it is the timestamp of the last change, which for a just-archived
	// repo is the archival event itself.
	at := ""
	if meta.Archived {
		at = meta.UpdatedAt
	}

	return meta.Archived, true, at, nil
}

// Sentinel errors for callers that want to distinguish failure modes.
var (
	errRepoMetaAuth      = errors.New("authentication failed (401)")
	errRepoMetaRateLimit = errors.New("rate limit exceeded (403)")
)
