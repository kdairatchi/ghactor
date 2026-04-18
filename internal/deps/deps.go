// Package deps resolves the latest release tag and tags for a GitHub action.
package deps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/kdairatchi/ghactor/internal/ghapi"
)

// client is the shared ghapi client, initialised lazily via getClient.
var (
	sharedClient    *ghapi.Client
	sharedClientErr error
	sharedClientSet bool
)

// getClient returns the package-level ghapi client, creating it once.
// In tests the caller can replace LatestTag / Tags via the injectable vars.
func getClient() (*ghapi.Client, error) {
	if !sharedClientSet {
		sharedClient, sharedClientErr = ghapi.New()
		sharedClientSet = true
	}
	return sharedClient, sharedClientErr
}

// LatestTag returns the latest release tag for owner/repo.
func LatestTag(owner, repo string) (string, error) {
	c, err := getClient()
	if err != nil {
		return "", fmt.Errorf("deps: %w", err)
	}
	path := fmt.Sprintf("/repos/%s/%s/releases/latest", owner, repo)
	out, err := c.Get(context.Background(), path)
	if err != nil {
		if errors.Is(err, ghapi.ErrNotFound) {
			return "", fmt.Errorf("no releases for %s/%s: %w", owner, repo, ghapi.ErrNotFound)
		}
		return "", fmt.Errorf("deps: LatestTag %s/%s: %w", owner, repo, err)
	}
	tag := extractJSONString(out, "tag_name")
	if tag == "" {
		return "", fmt.Errorf("no releases for %s/%s", owner, repo)
	}
	return tag, nil
}

// LatestMajor converts a tag like v4.2.1 into v4.
func LatestMajor(tag string) string {
	if !strings.HasPrefix(tag, "v") {
		return tag
	}
	i := strings.IndexAny(tag[1:], ".-")
	if i < 0 {
		return tag
	}
	return tag[:i+1]
}

// PickHighestSemver returns the lexicographically-largest semver-shaped tag
// (vMAJ.MIN.PATCH) from the slice. Falls back to first element if none parse.
func PickHighestSemver(tags []string) string {
	type ver struct {
		raw  string
		nums [3]int
	}
	parse := func(t string) (ver, bool) {
		s := strings.TrimPrefix(t, "v")
		parts := strings.SplitN(s, ".", 3)
		var v ver
		v.raw = t
		for i := 0; i < len(parts) && i < 3; i++ {
			n := 0
			for _, c := range parts[i] {
				if c < '0' || c > '9' {
					break
				}
				n = n*10 + int(c-'0')
			}
			v.nums[i] = n
		}
		return v, len(parts) > 0
	}
	var best ver
	have := false
	for _, t := range tags {
		v, ok := parse(t)
		if !ok {
			continue
		}
		if !have || cmpNums(v.nums, best.nums) > 0 {
			best = v
			have = true
		}
	}
	if !have && len(tags) > 0 {
		return tags[0]
	}
	return best.raw
}

func cmpNums(a, b [3]int) int {
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			if a[i] > b[i] {
				return 1
			}
			return -1
		}
	}
	return 0
}

// Tags lists all tags for repo (limited to 100).
func Tags(owner, repo string) ([]string, error) {
	c, err := getClient()
	if err != nil {
		return nil, fmt.Errorf("deps: %w", err)
	}
	path := fmt.Sprintf("/repos/%s/%s/tags?per_page=100", owner, repo)
	out, err := c.Get(context.Background(), path)
	if err != nil {
		if errors.Is(err, ghapi.ErrNotFound) {
			return nil, fmt.Errorf("tags for %s/%s: %w", owner, repo, ghapi.ErrNotFound)
		}
		return nil, fmt.Errorf("deps: Tags %s/%s: %w", owner, repo, err)
	}
	// The endpoint returns a JSON array of objects: [{"name":"v1.0.0",...}, ...]
	var raw []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, fmt.Errorf("deps: Tags %s/%s: parse: %w", owner, repo, err)
	}
	tags := make([]string, 0, len(raw))
	for _, t := range raw {
		tags = append(tags, t.Name)
	}
	return tags, nil
}

// extractJSONString finds the first occurrence of "key":"value" in raw JSON
// without a full unmarshal. Sufficient for simple string fields like tag_name.
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
