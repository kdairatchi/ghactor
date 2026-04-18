package ghapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// TestHTTPS_OK verifies a 200 response is returned as raw bytes.
func TestHTTPS_OK(t *testing.T) {
	want := `{"sha":"abc123"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("missing/wrong Authorization header: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(want)) //nolint:errcheck
	}))
	defer srv.Close()

	c := newHTTPSClientWithBase(t, srv)
	got, err := c.Get(context.Background(), "/repos/owner/repo/commits/main")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

// TestHTTPS_404 verifies ErrNotFound is returned on 404.
func TestHTTPS_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := newHTTPSClientWithBase(t, srv)
	_, err := c.Get(context.Background(), "/repos/owner/missing/commits/main")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("errors.Is(err, ErrNotFound) = false; got %v", err)
	}
}

// TestHTTPS_401 verifies ErrAuth is returned on 401.
func TestHTTPS_401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := newHTTPSClientWithBase(t, srv)
	_, err := c.Get(context.Background(), "/repos/owner/repo/commits/main")
	if !errors.Is(err, ErrAuth) {
		t.Errorf("errors.Is(err, ErrAuth) = false; got %v", err)
	}
}

// TestHTTPS_403_NoRateLimit verifies ErrRateLimit on a plain 403 (no rate-limit headers).
func TestHTTPS_403_NoRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c := newHTTPSClientWithBase(t, srv)
	_, err := c.Get(context.Background(), "/repos/owner/repo/commits/main")
	if !errors.Is(err, ErrRateLimit) {
		t.Errorf("errors.Is(err, ErrRateLimit) = false; got %v", err)
	}
}

// TestHTTPS_RateLimitRetry_Success verifies the retry path: first response is
// 403 + rate-limit headers with a reset in the past; second response is 200.
func TestHTTPS_RateLimitRetry_Success(t *testing.T) {
	want := `{"sha":"deadbeef"}`
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			// Rate limit exhausted; reset is 1 second in the past so sleep = 0.
			resetUnix := strconv.FormatInt(time.Now().Add(-time.Second).Unix(), 10)
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", resetUnix)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(want)) //nolint:errcheck
	}))
	defer srv.Close()

	c := newHTTPSClientWithBase(t, srv)
	got, err := c.Get(context.Background(), "/repos/owner/repo/commits/main")
	if err != nil {
		t.Fatalf("unexpected error after retry: %v", err)
	}
	if string(got) != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	if calls != 2 {
		t.Errorf("expected 2 server calls (initial + retry), got %d", calls)
	}
}

// TestHTTPS_RateLimitRetry_StillFails verifies ErrRateLimit when retry also returns 403.
func TestHTTPS_RateLimitRetry_StillFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resetUnix := strconv.FormatInt(time.Now().Add(-time.Second).Unix(), 10)
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", resetUnix)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c := newHTTPSClientWithBase(t, srv)
	_, err := c.Get(context.Background(), "/repos/owner/repo/commits/main")
	if !errors.Is(err, ErrRateLimit) {
		t.Errorf("errors.Is(err, ErrRateLimit) = false; got %v", err)
	}
}

// TestHTTPS_RateLimitRetry_ContextCancelled verifies context cancellation during
// the rate-limit sleep is respected.
func TestHTTPS_RateLimitRetry_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reset is 30s in the future so sleep would block.
		resetUnix := strconv.FormatInt(time.Now().Add(30*time.Second).Unix(), 10)
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", resetUnix)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel immediately so the sleep select fires the ctx.Done branch.
	cancel()

	c := newHTTPSClientWithBase(t, srv)
	_, err := c.Get(ctx, "/repos/owner/repo/commits/main")
	if err == nil {
		t.Fatal("expected error on cancelled context, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled; got %v", err)
	}
}

// TestRateLimitSleep_Cap verifies the sleep is capped at maxRateLimitSleep.
func TestRateLimitSleep_Cap(t *testing.T) {
	h := make(http.Header)
	// Reset far in the future (10 minutes).
	future := strconv.FormatInt(time.Now().Add(10*time.Minute).Unix(), 10)
	h.Set("X-RateLimit-Remaining", "0")
	h.Set("X-RateLimit-Reset", future)
	got := rateLimitSleep(h)
	if got > maxRateLimitSleep {
		t.Errorf("sleep %v exceeds cap %v", got, maxRateLimitSleep)
	}
	if got != maxRateLimitSleep {
		t.Errorf("sleep = %v, want %v (cap)", got, maxRateLimitSleep)
	}
}

// TestRateLimitSleep_Past verifies sleep is zero when reset is in the past.
func TestRateLimitSleep_Past(t *testing.T) {
	h := make(http.Header)
	past := strconv.FormatInt(time.Now().Add(-time.Minute).Unix(), 10)
	h.Set("X-RateLimit-Remaining", "0")
	h.Set("X-RateLimit-Reset", past)
	got := rateLimitSleep(h)
	if got != 0 {
		t.Errorf("sleep = %v, want 0 for past reset", got)
	}
}

// TestIsRateLimited verifies header detection logic.
func TestIsRateLimited(t *testing.T) {
	cases := []struct {
		remaining string
		reset     string
		want      bool
	}{
		{"0", "1234567890", true},
		{"1", "1234567890", false},
		{"0", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		h := make(http.Header)
		if tc.remaining != "" {
			h.Set("X-RateLimit-Remaining", tc.remaining)
		}
		if tc.reset != "" {
			h.Set("X-RateLimit-Reset", tc.reset)
		}
		if got := isRateLimited(h); got != tc.want {
			t.Errorf("isRateLimited(remaining=%q, reset=%q) = %v, want %v",
				tc.remaining, tc.reset, got, tc.want)
		}
	}
}

// newHTTPSClientWithBase builds an HTTPS client whose http.Client is wired to
// the given httptest server and whose API base points at that server.
// We achieve the base override by temporarily mutating the package-level var.
func newHTTPSClientWithBase(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	orig := githubAPIBase
	githubAPIBase = srv.URL
	t.Cleanup(func() { githubAPIBase = orig })
	return &Client{
		m:     modeHTTPS,
		token: "test-token",
		http:  srv.Client(),
	}
}
