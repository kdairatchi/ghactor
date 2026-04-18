package trail

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

// makeRunJSON returns a single workflow_run JSON object with the given id and
// createdAt timestamp.
func makeRunJSON(id int, name string, createdAt time.Time, conclusion string) string {
	c := fmt.Sprintf("%q", conclusion)
	if conclusion == "" {
		c = "null"
	}
	return fmt.Sprintf(`{
		"id": %d,
		"name": %q,
		"path": ".github/workflows/ci.yml",
		"event": "push",
		"status": "completed",
		"conclusion": %s,
		"head_branch": "main",
		"head_sha": "abc%d",
		"html_url": "https://github.com/owner/repo/actions/runs/%d",
		"run_attempt": 1,
		"run_number": %d,
		"created_at": %q,
		"updated_at": %q
	}`, id, name, c, id, id, id,
		createdAt.UTC().Format(time.RFC3339),
		createdAt.UTC().Format(time.RFC3339))
}

// runsPageJSON wraps a slice of run JSON strings into a valid runs-list page.
func runsPageJSON(runs []string) string {
	return fmt.Sprintf(`{"total_count":%d,"workflow_runs":[%s]}`,
		len(runs), strings.Join(runs, ","))
}

// ---------------------------------------------------------------------------
// Transport override helpers
// ---------------------------------------------------------------------------

// withTestServer replaces the package-level restTransport with one wired to
// srv, and restores the original on test cleanup.
func withTestServer(t *testing.T, srv *httptest.Server) {
	t.Helper()
	orig := restTransport
	restTransport = srv.Client().Transport
	t.Cleanup(func() { restTransport = orig })
}

// withAPIBase overrides apiBase resolution by setting GITHUB_API_URL.
func withAPIBase(t *testing.T, base string) {
	t.Helper()
	t.Setenv("GITHUB_API_URL", base)
}

// withRepo sets GITHUB_REPOSITORY so repoSlug() doesn't shell out to git.
func withRepo(t *testing.T, slug string) {
	t.Helper()
	t.Setenv("GITHUB_REPOSITORY", slug)
}

// withToken sets GHACTOR_GITHUB_TOKEN and clears GITHUB_TOKEN.
func withToken(t *testing.T, tok string) {
	t.Helper()
	t.Setenv("GHACTOR_GITHUB_TOKEN", tok)
	t.Setenv("GITHUB_TOKEN", "")
}

// ---------------------------------------------------------------------------
// Pagination fixture: 2 pages × 3 runs
// ---------------------------------------------------------------------------

// buildPaginationServer returns a test server that serves two pages of runs
// and the URL of the first page. Runs are newest-first by id (6, 5, 4 / 3, 2, 1).
func buildPaginationServer(t *testing.T, baseTime time.Time) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		switch page {
		case "", "1":
			// First page: runs 6, 5, 4 — newest first.
			body := runsPageJSON([]string{
				makeRunJSON(6, "ci", baseTime.Add(-1*time.Hour), "success"),
				makeRunJSON(5, "ci", baseTime.Add(-2*time.Hour), "failure"),
				makeRunJSON(4, "ci", baseTime.Add(-3*time.Hour), "success"),
			})
			// Link header pointing to page 2.
			w.Header().Set("Link",
				fmt.Sprintf(`<%s/repos/owner/repo/actions/runs?per_page=100&page=2>; rel="next"`, srv.URL))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, body)
		case "2":
			// Second page: runs 3, 2, 1 — oldest.
			body := runsPageJSON([]string{
				makeRunJSON(3, "ci", baseTime.Add(-4*time.Hour), "success"),
				makeRunJSON(2, "ci", baseTime.Add(-5*time.Hour), "failure"),
				makeRunJSON(1, "ci", baseTime.Add(-6*time.Hour), "success"),
			})
			// No Link header → no more pages.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, body)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ---------------------------------------------------------------------------
// Test: pagination collects all 6 runs across 2 pages
// ---------------------------------------------------------------------------

func TestRESTFetch_Pagination(t *testing.T) {
	baseTime := time.Now()
	srv := buildPaginationServer(t, baseTime)
	withTestServer(t, srv)
	withAPIBase(t, srv.URL)
	withRepo(t, "owner/repo")
	withToken(t, "tok-test")

	runs, err := RecentREST(WindowOpts{Limit: 100})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(runs) != 6 {
		t.Errorf("want 6 runs, got %d", len(runs))
	}
	// Verify order: newest first (id 6 → 1).
	for i, want := range []int{6, 5, 4, 3, 2, 1} {
		if runs[i].DatabaseID != want {
			t.Errorf("runs[%d].DatabaseID = %d, want %d", i, runs[i].DatabaseID, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: Window cutoff stops pagination mid-stream
// ---------------------------------------------------------------------------

func TestRESTFetch_WindowCutoff(t *testing.T) {
	baseTime := time.Now()
	srv := buildPaginationServer(t, baseTime)
	withTestServer(t, srv)
	withAPIBase(t, srv.URL)
	withRepo(t, "owner/repo")
	withToken(t, "tok-test")

	// Window of 3.5 hours keeps runs 6 (−1h), 5 (−2h), 4 (−3h) but NOT 3 (−4h).
	runs, err := RecentREST(WindowOpts{
		Limit:  100,
		Window: 3*time.Hour + 30*time.Minute,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(runs) != 3 {
		t.Errorf("want 3 runs within window, got %d", len(runs))
	}
	for _, r := range runs {
		if r.DatabaseID < 4 {
			t.Errorf("run %d is outside the window", r.DatabaseID)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: 403 rate-limit triggers fallback when Source=Auto
// ---------------------------------------------------------------------------

func TestRESTFetch_403_FallsBackOnAuto(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"message":"API rate limit exceeded"}`)
	}))
	defer srv.Close()
	withTestServer(t, srv)
	withAPIBase(t, srv.URL)
	withRepo(t, "owner/repo")
	withToken(t, "tok-test")

	// SourceAuto should try REST, get 403, then try gh fallback.
	// gh is not available in the test environment, so the error should mention
	// the original REST failure.
	_, err := RecentWindow(WindowOpts{Source: SourceAuto})
	if err == nil {
		// If gh happens to be on PATH and authenticated, the test environment
		// may succeed — that is acceptable; skip asserting error.
		t.Log("gh CLI available; fallback succeeded — skipping error assertion")
		return
	}
	if !strings.Contains(err.Error(), "403") && !strings.Contains(err.Error(), "rate limit") {
		t.Errorf("expected rate-limit message in error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test: 403 returns error directly when Source=REST
// ---------------------------------------------------------------------------

func TestRESTFetch_403_ErrorOnSourceREST(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"message":"API rate limit exceeded"}`)
	}))
	defer srv.Close()
	withTestServer(t, srv)
	withAPIBase(t, srv.URL)
	withRepo(t, "owner/repo")
	withToken(t, "tok-test")

	_, err := RecentWindow(WindowOpts{Source: SourceREST})
	if err == nil {
		t.Fatal("expected error on 403, got nil")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("expected 403 in error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test: Limit stops pagination early
// ---------------------------------------------------------------------------

func TestRESTFetch_LimitStopsPagination(t *testing.T) {
	baseTime := time.Now()
	srv := buildPaginationServer(t, baseTime)
	withTestServer(t, srv)
	withAPIBase(t, srv.URL)
	withRepo(t, "owner/repo")
	withToken(t, "tok-test")

	runs, err := RecentREST(WindowOpts{Limit: 4})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(runs) != 4 {
		t.Errorf("want 4 runs (limit), got %d", len(runs))
	}
}

// ---------------------------------------------------------------------------
// Test: 5xx triggers one retry
// ---------------------------------------------------------------------------

func TestRESTFetch_5xx_Retry(t *testing.T) {
	calls := 0
	baseTime := time.Now()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		body := runsPageJSON([]string{
			makeRunJSON(1, "ci", baseTime, "success"),
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, body)
	}))
	defer srv.Close()
	withTestServer(t, srv)
	withAPIBase(t, srv.URL)
	withRepo(t, "owner/repo")
	withToken(t, "tok-test")

	runs, err := RecentREST(WindowOpts{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error after retry: %v", err)
	}
	if len(runs) != 1 {
		t.Errorf("want 1 run, got %d", len(runs))
	}
	if calls != 2 {
		t.Errorf("want 2 server calls (initial 5xx + retry), got %d", calls)
	}
}

// ---------------------------------------------------------------------------
// Test: User-Agent header is set correctly
// ---------------------------------------------------------------------------

func TestRESTFetch_UserAgent(t *testing.T) {
	var gotUA string
	baseTime := time.Now()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		body := runsPageJSON([]string{
			makeRunJSON(1, "ci", baseTime, "success"),
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, body)
	}))
	defer srv.Close()
	withTestServer(t, srv)
	withAPIBase(t, srv.URL)
	withRepo(t, "owner/repo")
	withToken(t, "tok-test")

	_, err := RecentREST(WindowOpts{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(gotUA, "ghactor/") {
		t.Errorf("User-Agent = %q, want prefix ghactor/", gotUA)
	}
}

// ---------------------------------------------------------------------------
// Test: Authorization header uses GHACTOR_GITHUB_TOKEN over GITHUB_TOKEN
// ---------------------------------------------------------------------------

func TestTokenResolution_GHACTORWinsOverGITHUB(t *testing.T) {
	var gotAuth string
	baseTime := time.Now()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		body := runsPageJSON([]string{
			makeRunJSON(1, "ci", baseTime, "success"),
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, body)
	}))
	defer srv.Close()
	withTestServer(t, srv)
	withAPIBase(t, srv.URL)
	withRepo(t, "owner/repo")

	t.Setenv("GHACTOR_GITHUB_TOKEN", "overriding-token")
	t.Setenv("GITHUB_TOKEN", "lower-priority-token")

	_, err := RecentREST(WindowOpts{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAuth != "Bearer overriding-token" {
		t.Errorf("Authorization = %q, want \"Bearer overriding-token\"", gotAuth)
	}
}

// ---------------------------------------------------------------------------
// Test: repo URL parsing (no network calls)
// ---------------------------------------------------------------------------

func TestParseRemoteURL(t *testing.T) {
	cases := []struct {
		raw  string
		want string
		ok   bool
	}{
		// HTTPS variants
		{"https://github.com/owner/repo.git", "owner/repo", true},
		{"https://github.com/owner/repo", "owner/repo", true},
		{"https://token@github.com/owner/repo.git", "owner/repo", true},
		// SSH variants
		{"git@github.com:owner/repo.git", "owner/repo", true},
		{"git@github.com:owner/repo", "owner/repo", true},
		{"ssh://git@github.com/owner/repo.git", "owner/repo", true},
		// git-proto
		{"git://github.com/owner/repo.git", "owner/repo", true},
		// Non-GitHub
		{"https://gitlab.com/owner/repo.git", "", false},
		{"", "", false},
		// Malformed
		{"https://github.com/onlyone", "", false},
	}
	for _, tc := range cases {
		got, ok := parseRemoteURL(tc.raw)
		if ok != tc.ok {
			t.Errorf("parseRemoteURL(%q) ok=%v, want %v", tc.raw, ok, tc.ok)
			continue
		}
		if ok && got != tc.want {
			t.Errorf("parseRemoteURL(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: parseLinkNext
// ---------------------------------------------------------------------------

func TestParseLinkNext(t *testing.T) {
	cases := []struct {
		header string
		want   string
	}{
		{
			`<https://api.github.com/repos/o/r/actions/runs?page=2>; rel="next", <...>; rel="last"`,
			"https://api.github.com/repos/o/r/actions/runs?page=2",
		},
		{`<https://api.github.com/repos/o/r/actions/runs?page=3>; rel="prev"`, ""},
		{"", ""},
	}
	for _, tc := range cases {
		got := parseLinkNext(tc.header)
		if got != tc.want {
			t.Errorf("parseLinkNext(%q) = %q, want %q", tc.header, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: toRun maps REST fields to canonical Run
// ---------------------------------------------------------------------------

func TestRestRun_toRun(t *testing.T) {
	s := "success"
	now := time.Now().Truncate(time.Second)
	rr := restRun{
		ID:         42,
		Name:       "CI",
		Path:       ".github/workflows/ci.yml",
		Event:      "push",
		Status:     "completed",
		Conclusion: &s,
		HeadBranch: "main",
		HeadSHA:    "deadbeef",
		HTMLURL:    "https://github.com/o/r/actions/runs/42",
		RunAttempt: 2,
		RunNumber:  7,
		CreatedAt:  now,
		UpdatedAt:  now.Add(3 * time.Minute),
	}
	r := rr.toRun()
	if r.DatabaseID != 42 {
		t.Errorf("DatabaseID = %d, want 42", r.DatabaseID)
	}
	if r.Conclusion != "success" {
		t.Errorf("Conclusion = %q, want success", r.Conclusion)
	}
	if r.Attempt != 2 {
		t.Errorf("Attempt = %d, want 2", r.Attempt)
	}
	if r.Branch != "main" {
		t.Errorf("Branch = %q, want main", r.Branch)
	}
}

func TestRestRun_toRun_NullConclusion(t *testing.T) {
	rr := restRun{
		ID:         1,
		Status:     "in_progress",
		Conclusion: nil,
		CreatedAt:  time.Now(),
	}
	r := rr.toRun()
	if r.Conclusion != "" {
		t.Errorf("Conclusion = %q for nil ptr, want empty", r.Conclusion)
	}
}
