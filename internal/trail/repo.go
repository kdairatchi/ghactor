package trail

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// repoSlug returns "owner/repo" for the current working directory.
//
// Resolution order:
//  1. GITHUB_REPOSITORY env var (set automatically inside GitHub Actions)
//  2. git remote get-url origin — parses https, ssh, and git-proto URLs
//  3. Error with a helpful message
func repoSlug() (string, error) {
	if v := os.Getenv("GITHUB_REPOSITORY"); v != "" {
		// Validate it looks like owner/repo before trusting it.
		if isValidSlug(v) {
			return v, nil
		}
		return "", fmt.Errorf("trail: GITHUB_REPOSITORY=%q is not a valid owner/repo slug", v)
	}

	out, err := exec.Command("git", "remote", "get-url", "origin").Output()
	if err != nil {
		return "", fmt.Errorf(
			"trail: cannot determine repository: GITHUB_REPOSITORY is not set and " +
				"`git remote get-url origin` failed — set GITHUB_REPOSITORY=owner/repo or run inside a git checkout",
		)
	}

	slug, ok := parseRemoteURL(strings.TrimSpace(string(out)))
	if !ok {
		return "", fmt.Errorf(
			"trail: cannot parse GitHub owner/repo from remote URL %q; "+
				"set GITHUB_REPOSITORY=owner/repo explicitly",
			strings.TrimSpace(string(out)),
		)
	}
	return slug, nil
}

// reRemoteHTTPS matches https://github.com/owner/repo(.git)?
var reRemoteHTTPS = regexp.MustCompile(`(?i)https?://(?:[^@/]+@)?github\.com[:/]([^/]+/[^/]+?)(?:\.git)?$`)

// reRemoteSSH matches git@github.com:owner/repo(.git)? and
// github.com:owner/repo(.git)?
var reRemoteSSH = regexp.MustCompile(`(?i)(?:git@|ssh://git@)?github\.com[:/]([^/]+/[^/]+?)(?:\.git)?$`)

// reRemoteGit matches git://github.com/owner/repo(.git)?
var reRemoteGit = regexp.MustCompile(`(?i)git://github\.com/([^/]+/[^/]+?)(?:\.git)?$`)

// parseRemoteURL extracts "owner/repo" from any common GitHub remote URL
// format. Returns the slug and true on success.
func parseRemoteURL(raw string) (string, bool) {
	for _, re := range []*regexp.Regexp{reRemoteHTTPS, reRemoteSSH, reRemoteGit} {
		if m := re.FindStringSubmatch(raw); len(m) == 2 {
			slug := strings.TrimSuffix(m[1], ".git")
			if isValidSlug(slug) {
				return slug, true
			}
		}
	}
	return "", false
}

// isValidSlug returns true when s looks like "owner/repo" with no extra slashes
// or spaces.
func isValidSlug(s string) bool {
	parts := strings.SplitN(s, "/", 3)
	if len(parts) != 2 {
		return false
	}
	return parts[0] != "" && parts[1] != ""
}
