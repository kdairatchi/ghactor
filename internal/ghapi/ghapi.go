// Package ghapi wraps GitHub API calls used by pin, deps, and trail.
// It prefers shelling out to the gh CLI when available and authenticated,
// falling back to direct HTTPS calls using GITHUB_TOKEN / GH_TOKEN, and
// returns a clear error when neither is usable.
package ghapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Sentinel errors returned by Client.Get.
var (
	// ErrAuth is returned when GitHub responds with 401 Unauthorized.
	ErrAuth = errors.New("github: authentication failed (401)")

	// ErrNotFound is returned when GitHub responds with 404 Not Found.
	ErrNotFound = errors.New("github: resource not found (404)")

	// ErrRateLimit is returned when GitHub responds with 403 and the
	// rate-limit headers indicate the limit has been exhausted, and the
	// retry after sleeping also fails.
	ErrRateLimit = errors.New("github: rate limit exceeded (403)")
)

// mode selects how the client communicates with the GitHub API.
type mode int

const (
	modeGHCLI  mode = iota // shell out to `gh api`
	modeHTTPS              // direct HTTPS with Authorization header
)

// Client is the entry point for GitHub API access.
// Construct it via New; the zero value is not valid.
type Client struct {
	m     mode
	token string       // only set when m == modeHTTPS
	http  *http.Client // only set when m == modeHTTPS
}

// New auto-detects whether to use the gh CLI or HTTPS fallback.
// It returns an error only when neither path is available.
func New() (*Client, error) {
	if ghAvailable() {
		return &Client{m: modeGHCLI}, nil
	}
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}
	if token == "" {
		return nil, errors.New("no gh CLI auth and GITHUB_TOKEN unset")
	}
	return &Client{
		m:     modeHTTPS,
		token: token,
		http:  &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// Get fetches the GitHub API path (e.g. "/repos/owner/repo/commits/ref") and
// returns the raw JSON body. It wraps ErrAuth, ErrNotFound, and ErrRateLimit
// for callers to test with errors.Is.
func (c *Client) Get(ctx context.Context, path string) ([]byte, error) {
	switch c.m {
	case modeGHCLI:
		return c.getViaGH(ctx, path)
	case modeHTTPS:
		return c.getViaHTTPS(ctx, path)
	default:
		return nil, fmt.Errorf("ghapi: unknown mode %d", c.m)
	}
}

// ghAvailable returns true if `gh` is on PATH and `gh auth status` exits 0.
func ghAvailable() bool {
	if _, err := exec.LookPath("gh"); err != nil {
		return false
	}
	cmd := exec.Command("gh", "auth", "status")
	return cmd.Run() == nil
}

// getViaGH delegates to `gh api <path>`.
func (c *Client) getViaGH(ctx context.Context, path string) ([]byte, error) {
	// gh api expects paths without a leading slash.
	p := strings.TrimPrefix(path, "/")
	cmd := exec.CommandContext(ctx, "gh", "api", p)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			stderr := strings.TrimSpace(string(ee.Stderr))
			// Surface recognisable error kinds from gh's stderr text.
			lower := strings.ToLower(stderr)
			if strings.Contains(lower, "401") || strings.Contains(lower, "unauthorized") {
				return nil, fmt.Errorf("%w: %s", ErrAuth, stderr)
			}
			if strings.Contains(lower, "404") || strings.Contains(lower, "not found") {
				return nil, fmt.Errorf("%w: %s", ErrNotFound, stderr)
			}
			if strings.Contains(lower, "403") || strings.Contains(lower, "rate limit") {
				return nil, fmt.Errorf("%w: %s", ErrRateLimit, stderr)
			}
			return nil, fmt.Errorf("gh api %s: %s", p, stderr)
		}
		return nil, fmt.Errorf("gh api %s: %w", p, err)
	}
	return out, nil
}

// githubAPIBase is the root URL for GitHub REST API calls. Declared as a var
// so tests can redirect requests to an httptest server.
var githubAPIBase = "https://api.github.com"

// maxRateLimitSleep caps how long we are willing to wait on a rate-limit reset.
const maxRateLimitSleep = 60 * time.Second

// getViaHTTPS performs a direct HTTPS GET against the GitHub REST API.
// On 403 with X-RateLimit-Remaining: 0 it sleeps until X-RateLimit-Reset
// (capped at maxRateLimitSleep) and retries once.
func (c *Client) getViaHTTPS(ctx context.Context, path string) ([]byte, error) {
	body, status, headers, err := c.doRequest(ctx, path)
	if err != nil {
		return nil, err
	}
	if status == http.StatusOK {
		return body, nil
	}

	// Handle rate-limit before other 403 logic: try to sleep and retry once.
	if status == http.StatusForbidden && isRateLimited(headers) {
		sleep := rateLimitSleep(headers)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(sleep):
		}
		body, status, _, err = c.doRequest(ctx, path)
		if err != nil {
			return nil, err
		}
		if status == http.StatusOK {
			return body, nil
		}
		if status == http.StatusForbidden {
			return nil, ErrRateLimit
		}
	}

	return nil, statusError(status)
}

// doRequest executes a single authenticated GET and returns body, status, headers, error.
func (c *Client) doRequest(ctx context.Context, path string) ([]byte, int, http.Header, error) {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	url := githubAPIBase + path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("ghapi: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("ghapi: http: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, resp.Header, fmt.Errorf("ghapi: read body: %w", err)
	}
	return body, resp.StatusCode, resp.Header, nil
}

// isRateLimited returns true when the response headers signal a rate-limit exhaustion.
func isRateLimited(h http.Header) bool {
	remaining := h.Get("X-RateLimit-Remaining")
	reset := h.Get("X-RateLimit-Reset")
	// Both headers present and remaining is "0" indicates exhaustion.
	return remaining == "0" && reset != ""
}

// rateLimitSleep computes how long to sleep based on X-RateLimit-Reset, capped
// at maxRateLimitSleep and floored at zero.
func rateLimitSleep(h http.Header) time.Duration {
	resetStr := h.Get("X-RateLimit-Reset")
	if resetStr == "" {
		return maxRateLimitSleep
	}
	resetUnix, err := strconv.ParseInt(resetStr, 10, 64)
	if err != nil {
		return maxRateLimitSleep
	}
	sleep := time.Until(time.Unix(resetUnix, 0))
	if sleep < 0 {
		return 0
	}
	if sleep > maxRateLimitSleep {
		return maxRateLimitSleep
	}
	return sleep
}

// statusError maps an HTTP status code to the appropriate sentinel or a generic error.
func statusError(status int) error {
	switch status {
	case http.StatusUnauthorized:
		return ErrAuth
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusForbidden:
		return ErrRateLimit
	default:
		return fmt.Errorf("ghapi: unexpected status %d", status)
	}
}
