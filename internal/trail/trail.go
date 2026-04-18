// Package trail reports recent workflow runs and flags flaky workflows.
//
// Run sources: by default the package tries the GitHub REST API first and
// falls back to the gh CLI only if REST fails. Use WindowOpts.Source to
// override the selection.
//
// Environment variables:
//
//	GHACTOR_GITHUB_TOKEN  token override (highest priority)
//	GITHUB_TOKEN          standard CI token
//	GITHUB_REPOSITORY     owner/repo slug (set automatically in GH Actions)
//	GITHUB_API_URL        GitHub Enterprise Server API base URL
package trail

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Source selects how RecentWindow fetches workflow runs.
type Source int

const (
	// SourceAuto tries the GitHub REST API first; on failure it warns to
	// stderr and falls back to the gh CLI. This is the default.
	SourceAuto Source = iota

	// SourceREST uses the REST API exclusively. Returns an error if it fails.
	SourceREST

	// SourceGHCLI uses `gh run list` exclusively. Requires gh on PATH.
	SourceGHCLI
)

type Run struct {
	DatabaseID int       `json:"databaseId"`
	Name       string    `json:"name"`
	Workflow   string    `json:"workflowName"`
	Event      string    `json:"event"`
	Status     string    `json:"status"`
	Conclusion string    `json:"conclusion"`
	Branch     string    `json:"headBranch"`
	SHA        string    `json:"headSha"`
	URL        string    `json:"url"`
	Attempt    int       `json:"attempt"`
	Number     int       `json:"number"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

// Recent wraps `gh run list` with basic filters. Kept for backward-compat.
func Recent(limit int, workflow string) ([]Run, error) {
	return RecentWindow(WindowOpts{Limit: limit, Workflow: workflow})
}

// WindowOpts controls how RecentWindow fetches and filters workflow runs.
type WindowOpts struct {
	Limit    int
	Window   time.Duration
	Branch   string
	Workflow string

	// Source selects the fetch mechanism. Default (zero value) is SourceAuto.
	Source Source
}

// RecentWindow fetches workflow runs according to opts.Source:
//
//   - SourceAuto (default): REST first, gh CLI fallback on network/rate errors.
//   - SourceREST: REST only; returns error on failure.
//   - SourceGHCLI: gh CLI only (legacy path).
func RecentWindow(o WindowOpts) ([]Run, error) {
	if o.Limit <= 0 {
		o.Limit = 100
	}

	switch o.Source {
	case SourceREST:
		return fetchViaREST(o)

	case SourceGHCLI:
		return fetchViaGHCLI(o)

	default: // SourceAuto
		runs, err := fetchViaREST(o)
		if err == nil {
			return runs, nil
		}
		// Only fall back on rate-limit, network errors, or 5xx. For auth
		// errors (401/404) surface the REST error directly — gh CLI would
		// fail for the same reason and the message is more informative.
		if !isRateLimitError(err) && !isNetworkError(err) {
			return nil, err
		}
		fmt.Fprintf(os.Stderr,
			"trail: REST fetch failed (%v); falling back to gh CLI\n", err)
		ghRuns, ghErr := fetchViaGHCLI(o)
		if ghErr != nil {
			// gh is not available — surface the original REST error so the
			// user knows what actually went wrong.
			return nil, fmt.Errorf("%w (gh fallback also failed: %v)", err, ghErr)
		}
		return ghRuns, nil
	}
}

// isNetworkError returns true for transport-level failures (not HTTP errors).
func isNetworkError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "dial tcp") ||
		strings.Contains(msg, "i/o timeout")
}

type WorkflowStats struct {
	Workflow       string        `json:"workflow"`
	Total          int           `json:"total"`
	Success        int           `json:"success"`
	Failure        int           `json:"failure"`
	Cancelled      int           `json:"cancelled"`
	InProgress     int           `json:"inProgress"`
	FlakyRecovered int           `json:"flakyRecovered"`
	FlakyBroken    int           `json:"flakyBroken"`
	FailRate       float64       `json:"failRate"`
	AvgDuration    time.Duration `json:"avgDuration"`
	LastFailureAt  time.Time     `json:"lastFailureAt,omitempty"`
}

type Report struct {
	Window      time.Duration   `json:"window"`
	Branch      string          `json:"branch,omitempty"`
	Threshold   float64         `json:"threshold"`
	Breached    bool            `json:"breached"`
	Overall     WorkflowStats   `json:"overall"`
	PerWorkflow []WorkflowStats `json:"perWorkflow"`
}

// Summarize (legacy) returns a flat Stats snapshot.
type Stats struct {
	Total       int
	Success     int
	Failure     int
	Cancelled   int
	InProgress  int
	AvgDuration time.Duration
}

func Summarize(runs []Run) Stats {
	var s Stats
	var total time.Duration
	var counted int
	for _, r := range runs {
		s.Total++
		switch r.Conclusion {
		case "success":
			s.Success++
		case "failure":
			s.Failure++
		case "cancelled":
			s.Cancelled++
		}
		if r.Status == "in_progress" || r.Status == "queued" {
			s.InProgress++
		}
		if !r.UpdatedAt.IsZero() && !r.CreatedAt.IsZero() {
			total += r.UpdatedAt.Sub(r.CreatedAt)
			counted++
		}
	}
	if counted > 0 {
		s.AvgDuration = total / time.Duration(counted)
	}
	return s
}

// Aggregate produces per-workflow + overall stats; computes fail-rate breach.
func Aggregate(runs []Run, window time.Duration, branch string, threshold float64) Report {
	by := map[string]*WorkflowStats{}
	add := func(name string) *WorkflowStats {
		s, ok := by[name]
		if !ok {
			s = &WorkflowStats{Workflow: name}
			by[name] = s
		}
		return s
	}
	durs := map[string][]time.Duration{}
	for _, r := range runs {
		s := add(r.Workflow)
		s.Total++
		switch r.Conclusion {
		case "success":
			s.Success++
			if r.Attempt > 1 {
				s.FlakyRecovered++
			}
		case "failure":
			s.Failure++
			if r.Attempt > 1 {
				s.FlakyBroken++
			}
			if r.UpdatedAt.After(s.LastFailureAt) {
				s.LastFailureAt = r.UpdatedAt
			}
		case "cancelled":
			s.Cancelled++
		}
		if r.Status == "in_progress" || r.Status == "queued" {
			s.InProgress++
		}
		if !r.UpdatedAt.IsZero() && !r.CreatedAt.IsZero() {
			durs[r.Workflow] = append(durs[r.Workflow], r.UpdatedAt.Sub(r.CreatedAt))
		}
	}
	var per []WorkflowStats
	overall := WorkflowStats{Workflow: "<overall>"}
	for name, s := range by {
		denom := s.Success + s.Failure
		if denom > 0 {
			s.FailRate = float64(s.Failure) / float64(denom) * 100
		}
		if ds := durs[name]; len(ds) > 0 {
			var sum time.Duration
			for _, d := range ds {
				sum += d
			}
			s.AvgDuration = sum / time.Duration(len(ds))
		}
		per = append(per, *s)
		overall.Total += s.Total
		overall.Success += s.Success
		overall.Failure += s.Failure
		overall.Cancelled += s.Cancelled
		overall.InProgress += s.InProgress
		overall.FlakyRecovered += s.FlakyRecovered
		overall.FlakyBroken += s.FlakyBroken
	}
	denom := overall.Success + overall.Failure
	if denom > 0 {
		overall.FailRate = float64(overall.Failure) / float64(denom) * 100
	}
	sort.Slice(per, func(i, j int) bool {
		if per[i].FailRate != per[j].FailRate {
			return per[i].FailRate > per[j].FailRate
		}
		return per[i].Failure > per[j].Failure
	})
	breached := threshold > 0 && overall.FailRate > threshold
	return Report{
		Window: window, Branch: branch, Threshold: threshold, Breached: breached,
		Overall: overall, PerWorkflow: per,
	}
}

// levenshtein returns the Levenshtein edit distance between a and b.
// Both strings are lowercased before comparison.
func levenshtein(a, b string) int {
	a = strings.ToLower(a)
	b = strings.ToLower(b)
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	// Use two rows to keep allocations small.
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost
			if del < ins {
				curr[j] = del
			} else {
				curr[j] = ins
			}
			if sub < curr[j] {
				curr[j] = sub
			}
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}

// ValidateWorkflow checks that name appears in the repo's workflow list via
// `gh workflow list`. If gh is not available or not authenticated the function
// returns nil (validation is skipped silently). When the workflow is not found
// the error includes up to 3 closest matches by Levenshtein distance or
// substring containment.
func ValidateWorkflow(name string) error {
	out, err := exec.Command("gh", "workflow", "list", "--json", "name", "--jq", ".[].name").Output()
	if err != nil {
		// gh unavailable or not authenticated — skip validation.
		return nil
	}
	var known []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			known = append(known, line)
			if strings.EqualFold(line, name) {
				return nil
			}
		}
	}
	// Collect candidates: substring match first, then Levenshtein.
	type scored struct {
		name string
		dist int
	}
	var candidates []scored
	lower := strings.ToLower(name)
	for _, k := range known {
		if strings.Contains(strings.ToLower(k), lower) {
			candidates = append(candidates, scored{k, -1}) // substring match → priority
		} else {
			candidates = append(candidates, scored{k, levenshtein(name, k)})
		}
	}
	// Sort: substring matches first (dist -1), then by edit distance.
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].dist != candidates[j].dist {
			if candidates[i].dist == -1 {
				return true
			}
			if candidates[j].dist == -1 {
				return false
			}
			return candidates[i].dist < candidates[j].dist
		}
		return candidates[i].name < candidates[j].name
	})
	limit := 3
	if len(candidates) < limit {
		limit = len(candidates)
	}
	var suggestions []string
	for _, c := range candidates[:limit] {
		suggestions = append(suggestions, c.name)
	}
	msg := fmt.Sprintf("workflow %q not found", name)
	if len(suggestions) > 0 {
		msg += fmt.Sprintf("; did you mean: %s", strings.Join(suggestions, ", "))
	}
	return fmt.Errorf("%s", msg)
}

// ParseWindow accepts "24h", "7d", "30d", or any time.ParseDuration input.
func ParseWindow(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, fmt.Errorf("invalid window %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}
