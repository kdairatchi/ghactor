package trail

// rest.go: GitHub REST API fetcher for workflow runs.
//
// Env vars respected:
//   GHACTOR_GITHUB_TOKEN  — explicit token override (highest priority)
//   GITHUB_TOKEN          — standard CI token
//   GITHUB_REPOSITORY     — owner/repo (used in GitHub Actions; overrides git-remote detection)
//   GITHUB_API_URL        — GitHub Enterprise Server base URL (default: https://api.github.com)
//
// Auth resolution order (first hit wins):
//  1. GHACTOR_GITHUB_TOKEN
//  2. GITHUB_TOKEN
//  3. `gh auth token` shell-out
//  4. No token — unauthenticated (60 req/hr; a warning is printed to stderr)

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Version is embedded in the User-Agent header sent with every REST request.
// The trail command sets this once at startup via SetVersion.
var Version = "0.3.0"

// SetVersion overrides the package-level version string used in User-Agent.
func SetVersion(v string) { Version = v }

// apiBase returns the GitHub API root URL, honouring GITHUB_API_URL for
// GitHub Enterprise Server deployments.
func apiBase() string {
	if v := os.Getenv("GITHUB_API_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "https://api.github.com"
}

// resolveToken returns the best available GitHub token.
// When no token can be found an empty string is returned; the caller should
// proceed with an unauthenticated request and warn the user.
func resolveToken() string {
	if t := os.Getenv("GHACTOR_GITHUB_TOKEN"); t != "" {
		return t
	}
	if t := os.Getenv("GITHUB_TOKEN"); t != "" {
		return t
	}
	// Attempt `gh auth token` — this works when gh is installed and logged in.
	if out, err := exec.Command("gh", "auth", "token").Output(); err == nil {
		if tok := strings.TrimSpace(string(out)); tok != "" {
			return tok
		}
	}
	return ""
}

// restTransport is the http.RoundTripper used for REST calls. Tests replace
// it with a transport wired to an httptest.Server.
var restTransport http.RoundTripper = http.DefaultTransport

// httpClientForREST returns a *http.Client using restTransport so tests can
// swap the transport without touching the real network.
func httpClientForREST() *http.Client {
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: restTransport,
	}
}

// restRun is the JSON shape returned by the GitHub Actions Runs API.
// Fields are mapped to the canonical Run type via toRun().
type restRun struct {
	ID         int64     `json:"id"`
	Name       string    `json:"name"`
	Path       string    `json:"path"` // ".github/workflows/ci.yml"
	Event      string    `json:"event"`
	Status     string    `json:"status"`
	Conclusion *string   `json:"conclusion"` // nullable
	HeadBranch string    `json:"head_branch"`
	HeadSHA    string    `json:"head_sha"`
	HTMLURL    string    `json:"html_url"`
	RunAttempt int       `json:"run_attempt"`
	RunNumber  int       `json:"run_number"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// toRun converts a restRun into the canonical trail.Run.
func (r restRun) toRun() Run {
	conclusion := ""
	if r.Conclusion != nil {
		conclusion = *r.Conclusion
	}
	// Derive a short workflow name from the path when name is empty.
	name := r.Name
	if name == "" {
		// ".github/workflows/ci.yml" → "ci.yml"
		parts := strings.Split(r.Path, "/")
		name = parts[len(parts)-1]
	}
	return Run{
		DatabaseID: int(r.ID),
		Name:       name,
		Workflow:   name,
		Event:      r.Event,
		Status:     r.Status,
		Conclusion: conclusion,
		Branch:     r.HeadBranch,
		SHA:        r.HeadSHA,
		URL:        r.HTMLURL,
		Attempt:    r.RunAttempt,
		Number:     r.RunNumber,
		CreatedAt:  r.CreatedAt,
		UpdatedAt:  r.UpdatedAt,
	}
}

// runsPage is the top-level JSON envelope for the runs list endpoint.
type runsPage struct {
	TotalCount   int       `json:"total_count"`
	WorkflowRuns []restRun `json:"workflow_runs"`
}

// reLinkNext matches the "next" URL from a GitHub Link header, e.g.:
//
//	Link: <https://api.github.com/...?page=2>; rel="next", <...>; rel="last"
var reLinkNext = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// parseLinkNext extracts the next-page URL from a Link header value, or
// returns "" when there is no next page.
func parseLinkNext(header string) string {
	if m := reLinkNext.FindStringSubmatch(header); len(m) == 2 {
		return m[1]
	}
	return ""
}

// RecentREST fetches workflow runs directly from the GitHub REST API.
// It does not fall back to gh CLI on failure.
func RecentREST(opts WindowOpts) ([]Run, error) {
	return fetchViaREST(opts)
}

// RecentGHCLI fetches workflow runs exclusively via the gh CLI.
// It returns an error if gh is not on PATH.
func RecentGHCLI(opts WindowOpts) ([]Run, error) {
	return fetchViaGHCLI(opts)
}

// fetchViaREST is the internal REST implementation.
func fetchViaREST(o WindowOpts) ([]Run, error) {
	if o.Limit <= 0 {
		o.Limit = 100
	}

	slug, err := repoSlug()
	if err != nil {
		return nil, err
	}

	token := resolveToken()
	if token == "" {
		fmt.Fprintln(os.Stderr,
			"trail: no GitHub token found; proceeding unauthenticated (60 req/hr rate limit). "+
				"Set GHACTOR_GITHUB_TOKEN or GITHUB_TOKEN to authenticate.")
	}

	client := httpClientForREST()
	base := apiBase()

	// Build the initial query string.
	params := url.Values{}
	params.Set("per_page", "100")
	if o.Branch != "" {
		params.Set("branch", o.Branch)
	}
	if o.Workflow != "" {
		// The REST API accepts workflow file name or ID via workflow_id.
		params.Set("workflow_id", o.Workflow)
	}

	var cutoff time.Time
	if o.Window > 0 {
		cutoff = time.Now().Add(-o.Window)
	}

	nextURL := fmt.Sprintf("%s/repos/%s/actions/runs?%s", base, slug, params.Encode())

	var collected []Run
	page := 0

	for nextURL != "" {
		page++
		body, linkHeader, status, err := doRESTGet(client, token, nextURL)
		if err != nil {
			return nil, fmt.Errorf("trail: REST request failed: %w", err)
		}
		if status != http.StatusOK {
			return nil, restStatusError(status)
		}

		var pg runsPage
		if err := json.Unmarshal(body, &pg); err != nil {
			return nil, fmt.Errorf("trail: parse runs page %d: %w", page, err)
		}

		done := false
		for _, rr := range pg.WorkflowRuns {
			run := rr.toRun()
			// Window cutoff: GitHub returns runs newest-first. Once we see a
			// run older than the cutoff, everything after it is also older.
			if !cutoff.IsZero() && run.CreatedAt.Before(cutoff) {
				done = true
				break
			}
			collected = append(collected, run)
			if len(collected) >= o.Limit {
				done = true
				break
			}
		}

		if done {
			break
		}

		nextURL = parseLinkNext(linkHeader)
	}

	return collected, nil
}

// doRESTGet performs a single authenticated GET, returning body, Link header,
// HTTP status, and transport-level error. It does NOT follow redirects beyond
// what http.Client already does. On 5xx it retries once after 1 s.
func doRESTGet(client *http.Client, token, rawURL string) (body []byte, linkHeader string, status int, err error) {
	body, linkHeader, status, err = doRESTGetOnce(client, token, rawURL)
	if err != nil {
		return nil, "", 0, err
	}
	if status >= 500 {
		time.Sleep(1 * time.Second)
		body, linkHeader, status, err = doRESTGetOnce(client, token, rawURL)
	}
	return body, linkHeader, status, err
}

func doRESTGetOnce(client *http.Client, token, rawURL string) ([]byte, string, int, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", 0, fmt.Errorf("build request: %w", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "ghactor/"+Version)

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", 0, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", resp.StatusCode, fmt.Errorf("read body: %w", err)
	}
	return b, resp.Header.Get("Link"), resp.StatusCode, nil
}

// restStatusError maps HTTP status codes to descriptive errors.
func restStatusError(status int) error {
	switch status {
	case http.StatusUnauthorized:
		return fmt.Errorf("trail: GitHub returned 401 Unauthorized — check your token")
	case http.StatusForbidden:
		return fmt.Errorf("trail: GitHub returned 403 Forbidden — %w", errRateLimit)
	case http.StatusNotFound:
		return fmt.Errorf("trail: GitHub returned 404 Not Found — check owner/repo and token scopes")
	default:
		return fmt.Errorf("trail: GitHub returned unexpected status %d", status)
	}
}

// errRateLimit is a sentinel for rate-limit detection in callers.
var errRateLimit = fmt.Errorf("rate limit exceeded")

// isRateLimitError returns true when err wraps errRateLimit.
func isRateLimitError(err error) bool {
	return err != nil && strings.Contains(err.Error(), errRateLimit.Error())
}

// fetchViaGHCLI shells out to `gh run list` — the original implementation,
// extracted from RecentWindow for direct invocation.
func fetchViaGHCLI(o WindowOpts) ([]Run, error) {
	if o.Limit <= 0 {
		o.Limit = 100
	}

	if _, err := exec.LookPath("gh"); err != nil {
		return nil, fmt.Errorf(
			"trail: gh CLI not found; install it (https://cli.github.com) and run `gh auth login`. "+
				"Note: GITHUB_TOKEN alone is not sufficient for `gh run list` flag richness",
		)
	}

	args := []string{"run", "list",
		"--limit", strconv.Itoa(o.Limit),
		"--json", "databaseId,workflowName,event,status,conclusion,headBranch,headSha,url,attempt,number,createdAt,updatedAt",
	}
	if o.Branch != "" {
		args = append(args, "--branch", o.Branch)
	}
	if o.Workflow != "" {
		args = append(args, "--workflow", o.Workflow)
	}
	if o.Window > 0 {
		cutoff := time.Now().Add(-o.Window).UTC().Format("2006-01-02")
		args = append(args, "--created", ">="+cutoff)
	}

	out, err := exec.Command("gh", args...).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("gh run list: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("gh run list: %w", err)
	}

	var runs []Run
	if err := json.Unmarshal(out, &runs); err != nil {
		return nil, fmt.Errorf("parse gh output: %w", err)
	}

	if o.Window > 0 {
		cutoff := time.Now().Add(-o.Window)
		filtered := runs[:0]
		for _, r := range runs {
			if r.CreatedAt.After(cutoff) {
				filtered = append(filtered, r)
			}
		}
		runs = filtered
	}
	return runs, nil
}
