// Package audit cross-checks pinned GitHub Actions against the GitHub Security
// Advisory Database (GHSA) and a static deny-list, reporting known-vulnerable
// or malicious action versions as Findings.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/kdairatchi/ghactor/internal/config"
	"github.com/kdairatchi/ghactor/internal/ghapi"
	"github.com/kdairatchi/ghactor/internal/workflow"
)

// ---- public types -----------------------------------------------------------

// Finding describes a single vulnerability match against a pinned action.
//
// Kind disambiguates the signal source:
//   - "ghsa"     — known advisory from the GitHub Advisory Database (existing)
//   - "archived" — the action's repository is archived (no security patches)
//   - "missing"  — the action's repository returned 404 (deleted or renamed)
//
// Fields Advisory, CVSS, Title, and URL are populated for "ghsa" findings only.
// ArchivedAt is populated for "archived" findings when the timestamp is available.
// Existing "ghsa" consumers are unaffected: the new fields carry omitempty so
// they are absent from JSON when empty.
type Finding struct {
	File       string  `json:"file"`
	Line       int     `json:"line"`
	Uses       string  `json:"uses"`
	Version    string  `json:"version"`
	Advisory   string  `json:"advisory"`           // GHSA-xxxx-xxxx-xxxx or CVE-XXXX-XXXXX
	CVSS       float64 `json:"cvss,omitempty"`
	Severity   string  `json:"severity"`           // error|warning|info
	Title      string  `json:"title"`
	URL        string  `json:"url"`
	Kind       string  `json:"kind,omitempty"`       // "ghsa"|"archived"|"missing"
	ArchivedAt string  `json:"archived_at,omitempty"` // ISO 8601; only for kind=archived
}

// Advisory is a normalised advisory record returned by the Fetcher.
type Advisory struct {
	GHSAID          string
	CVEID           string
	Severity        string  // "critical" | "high" | "medium" | "low"
	CVSSScore       float64
	Title           string
	URL             string
	VulnerableRange string // e.g. "< 46"
	PatchedVersion  string
}

// Fetcher returns advisories for an action ecosystem entry.
// The interface is intentionally narrow so tests can inject a mock without
// pulling in the ghapi package.
type Fetcher interface {
	Advisories(owner, repo string) ([]Advisory, error)
}

// Options configures a Scan run.
type Options struct {
	Dir         string
	Concurrency int
	Fetcher     Fetcher         // injectable; nil → GHSAFetcher backed by ghapi
	DenyActions []string        // patterns from .ghactor.yml deny_actions
	Offline     bool            // skip live GHSA fetch; only static known-bad

	// Repo-metadata checks (supply-chain phase-two signals).
	// Both default to true when the zero value is used; set to false to disable.
	// When Offline is true both checks are skipped regardless.
	CheckArchival bool           // flag archived repos (no security patches)
	CheckMissing  bool           // flag repos that 404 (deleted/renamed)
	RepoMeta      RepoMetaFetcher // injectable; nil → DefaultRepoMetaFetcher
}

// ---- static known-bad list --------------------------------------------------
//
// Leave the slice empty so the binary ships clean. Add entries in the format
// below; users can also enumerate patterns via .ghactor.yml deny_actions.
//
//	{"tj-actions/changed-files@*", "CVE-2025-30066 supply chain compromise", "CVE-2025-30066"},
var knownBad = []struct{ Pattern, Reason, CVE string }{
	// examples — uncomment to activate:
	// {"tj-actions/changed-files@*", "CVE-2025-30066 supply chain compromise", "CVE-2025-30066"},
	// {"reviewdog/action-setup@*", "CVE-2025-30154 supply chain compromise", "CVE-2025-30154"},
}

// ---- pinned action extraction -----------------------------------------------

var sha40 = regexp.MustCompile(`^[0-9a-f]{40}$`)

// tagComment extracts a semver/tag from a trailing comment on a `uses:` line.
// e.g. `actions/checkout@abc123  # v4.1.0` → "v4.1.0"
// e.g. `actions/checkout@abc123  # v4`     → "v4"
var tagComment = regexp.MustCompile(`#\s*(\S+)\s*$`)

// pinnedAction represents a unique pinned action reference found in workflows.
type pinnedAction struct {
	owner string
	repo  string
	sha   string
	tag   string // from trailing comment; empty when absent
	// representative occurrence for reporting
	file string
	line int
	uses string
}

// collectPinned walks workflow files under dir and returns all unique
// owner/repo pins that are 40-char SHAs (already-pinned refs).
// Non-pinned refs (branches/tags) are intentionally skipped: the audit
// command focuses on verifying that pinned refs are safe, not on enforcing
// pinning (that's the pin subcommand's job).
func collectPinned(dir string) ([]pinnedAction, error) {
	files, err := workflow.LoadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("load workflows: %w", err)
	}

	seen := map[string]bool{}
	var out []pinnedAction

	for _, f := range files {
		// Walk the raw source lines to capture inline tag comments, which the
		// YAML parser discards.
		lines := strings.Split(string(f.Source), "\n")

		for _, job := range f.WF.Jobs {
			for _, step := range job.Steps {
				if step.Uses == "" {
					continue
				}
				uses := step.Uses
				owner, repo, ref, ok := splitUses(uses)
				if !ok {
					continue
				}
				if !sha40.MatchString(ref) {
					continue // not pinned
				}

				key := fmt.Sprintf("%s/%s@%s", owner, repo, ref)
				if seen[key] {
					continue
				}
				seen[key] = true

				tag := tagFromLine(lines, step.Line)
				out = append(out, pinnedAction{
					owner: owner,
					repo:  repo,
					sha:   ref,
					tag:   tag,
					file:  f.Path,
					line:  step.Line,
					uses:  uses,
				})
			}
		}
	}
	return out, nil
}

// tagFromLine extracts a tag comment from a 1-indexed source line.
func tagFromLine(lines []string, lineNum int) string {
	if lineNum < 1 || lineNum > len(lines) {
		return ""
	}
	m := tagComment.FindStringSubmatch(lines[lineNum-1])
	if m == nil {
		return ""
	}
	t := m[1]
	// Reject obvious non-version comments.
	if strings.HasPrefix(t, "pin") || strings.HasPrefix(t, "renovate") {
		return ""
	}
	return t
}

// splitUses splits `owner/repo[/path]@ref` into (owner, repo, ref).
func splitUses(uses string) (owner, repo, ref string, ok bool) {
	at := strings.LastIndex(uses, "@")
	if at < 0 {
		return "", "", "", false
	}
	ref = uses[at+1:]
	parts := strings.SplitN(uses[:at], "/", 3)
	if len(parts) < 2 {
		return "", "", "", false
	}
	return parts[0], parts[1], ref, true
}

// ---- version range matching -------------------------------------------------

// versionInRange reports whether version is in a vulnerable range string.
//
// Supported operators: <, <=, >, >=, =, ==
// Version strings are compared as dot-separated integers after stripping a
// leading "v". When comparison fails (non-numeric versions), the range is
// conservatively treated as matching.
//
// Range examples:
//
//	"< 46"        → version < 46
//	"<= 1.2.3"    → version <= 1.2.3
//	">= 1.0, < 2" → both conditions must hold
func versionInRange(version, rangeStr string) bool {
	if rangeStr == "" || version == "" || version == "unknown-version" {
		return false
	}
	rangeStr = strings.TrimSpace(rangeStr)
	if rangeStr == "" {
		return false
	}

	// Multiple conditions joined by comma.
	parts := strings.Split(rangeStr, ",")
	for _, part := range parts {
		if !singleConditionHolds(version, strings.TrimSpace(part)) {
			return false
		}
	}
	return true
}

// singleConditionHolds checks one operator+version fragment.
func singleConditionHolds(version, cond string) bool {
	cond = strings.TrimSpace(cond)
	var op, verStr string
	for _, prefix := range []string{"<=", ">=", "<", ">", "==", "="} {
		if strings.HasPrefix(cond, prefix) {
			op = prefix
			verStr = strings.TrimSpace(cond[len(prefix):])
			break
		}
	}
	if op == "" {
		// No operator: treat as exact equality.
		op = "="
		verStr = cond
	}

	cmp := compareVersions(version, verStr)
	switch op {
	case "<":
		return cmp < 0
	case "<=":
		return cmp <= 0
	case ">":
		return cmp > 0
	case ">=":
		return cmp >= 0
	case "=", "==":
		return cmp == 0
	}
	return false
}

// compareVersions compares two semver-ish strings numerically.
// Returns -1, 0, or +1. Non-numeric segments fall back to string comparison.
func compareVersions(a, b string) int {
	a = strings.TrimPrefix(strings.TrimSpace(a), "v")
	b = strings.TrimPrefix(strings.TrimSpace(b), "v")
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")

	// Pad to equal length.
	for len(aParts) < len(bParts) {
		aParts = append(aParts, "0")
	}
	for len(bParts) < len(aParts) {
		bParts = append(bParts, "0")
	}

	for i := range aParts {
		av, ae := parseInt(aParts[i])
		bv, be := parseInt(bParts[i])
		if ae != nil || be != nil {
			// Fall back to lexicographic for non-numeric segments.
			if aParts[i] < bParts[i] {
				return -1
			}
			if aParts[i] > bParts[i] {
				return 1
			}
			continue
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}

func parseInt(s string) (int64, error) {
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("non-digit")
		}
		n = n*10 + int64(c-'0')
	}
	if len(s) == 0 {
		return 0, fmt.Errorf("empty")
	}
	return n, nil
}

// ---- severity mapping -------------------------------------------------------

// ghsaSeverityToFinding maps GHSA severity strings to Finding.Severity values.
// critical and high → "error"; medium → "warning"; low/unknown → "info".
func ghsaSeverityToFinding(ghsaSev string) string {
	switch strings.ToLower(ghsaSev) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "info"
	}
}

// ---- GHSA live fetcher ------------------------------------------------------

// GHSAFetcher implements Fetcher using the GitHub Advisory Database REST API.
type GHSAFetcher struct {
	client *ghapi.Client
}

// NewGHSAFetcher constructs a live fetcher; returns an error when no auth is
// available (same behaviour as ghapi.New).
func NewGHSAFetcher() (*GHSAFetcher, error) {
	c, err := ghapi.New()
	if err != nil {
		return nil, err
	}
	return &GHSAFetcher{client: c}, nil
}

// ghsaAdvisory is the minimal shape of a GitHub Advisory Database record
// returned by GET /advisories?ecosystem=actions&affects=owner/repo.
type ghsaAdvisory struct {
	GHSAID      string  `json:"ghsa_id"`
	CVEID       string  `json:"cve_id"`
	Severity    string  `json:"severity"`
	CVSSScore   float64 `json:"cvss_score"`
	Summary     string  `json:"summary"`
	HTMLURL     string  `json:"html_url"`
	Identifiers []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"identifiers"`
	Vulnerabilities []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		VulnerableVersionRange string `json:"vulnerable_version_range"`
		FirstPatchedVersion    string `json:"first_patched_version"`
	} `json:"vulnerabilities"`
	CVSS struct {
		Score float64 `json:"score"`
	} `json:"cvss"`
}

// Advisories queries the GitHub Advisory DB for a specific actions package.
func (f *GHSAFetcher) Advisories(owner, repo string) ([]Advisory, error) {
	pkg := fmt.Sprintf("%s/%s", owner, repo)
	path := fmt.Sprintf("/advisories?ecosystem=actions&affects=%s&per_page=100", pkg)

	body, err := f.client.Get(context.Background(), path)
	if err != nil {
		return nil, fmt.Errorf("ghsa fetch %s: %w", pkg, err)
	}

	var raw []ghsaAdvisory
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("ghsa parse %s: %w", pkg, err)
	}

	out := make([]Advisory, 0, len(raw))
	for _, r := range raw {
		a := Advisory{
			GHSAID:    r.GHSAID,
			CVEID:     r.CVEID,
			Severity:  r.Severity,
			CVSSScore: r.CVSSScore,
			Title:     r.Summary,
			URL:       r.HTMLURL,
		}
		// Prefer CVSS score from nested object when top-level is zero.
		if a.CVSSScore == 0 && r.CVSS.Score != 0 {
			a.CVSSScore = r.CVSS.Score
		}
		// Pick first vulnerability that targets the actions ecosystem.
		for _, v := range r.Vulnerabilities {
			if strings.EqualFold(v.Package.Ecosystem, "actions") &&
				strings.EqualFold(v.Package.Name, pkg) {
				a.VulnerableRange = v.VulnerableVersionRange
				a.PatchedVersion = v.FirstPatchedVersion
				break
			}
		}
		out = append(out, a)
	}
	return out, nil
}

// ---- Scan -------------------------------------------------------------------

// Scan is the primary entry point: scans dir for pinned actions, fetches
// advisories, and returns a slice of Findings. An offline run (opts.Offline)
// skips the live GHSA fetch and relies solely on the static known-bad list.
func Scan(opts Options) ([]Finding, error) {
	if opts.Dir == "" {
		opts.Dir = ".github/workflows"
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 4
	}
	opts = applyOptionDefaults(opts)

	pins, err := collectPinned(opts.Dir)
	if err != nil {
		return nil, err
	}

	var findings []Finding
	var mu sync.Mutex

	// Apply static known-bad list first (no network required).
	for _, pin := range pins {
		for _, kb := range knownBad {
			if matchesPattern(pin.uses, kb.Pattern) {
				mu.Lock()
				findings = append(findings, Finding{
					File:     pin.file,
					Line:     pin.line,
					Uses:     pin.uses,
					Version:  versionOf(pin),
					Advisory: kb.CVE,
					Severity: "error",
					Kind:     "ghsa",
					Title:    kb.Reason,
					URL:      "",
				})
				mu.Unlock()
			}
		}
		// Also check caller-supplied deny patterns from .ghactor.yml.
		for _, pat := range opts.DenyActions {
			if matchesPattern(pin.uses, pat) {
				mu.Lock()
				findings = append(findings, Finding{
					File:     pin.file,
					Line:     pin.line,
					Uses:     pin.uses,
					Version:  versionOf(pin),
					Advisory: "deny-list",
					Severity: "error",
					Kind:     "ghsa",
					Title:    fmt.Sprintf("action matches deny_actions pattern %q", pat),
					URL:      "",
				})
				mu.Unlock()
			}
		}
	}

	if opts.Offline {
		return findings, nil
	}

	// Deduplicate by owner/repo — shared between GHSA and repo-meta checks.
	type repoKey struct{ owner, repo string }
	repoToPins := map[repoKey][]pinnedAction{}
	for _, p := range pins {
		k := repoKey{p.owner, p.repo}
		repoToPins[k] = append(repoToPins[k], p)
	}

	// ---- GHSA advisory checks -------------------------------------------------

	// Resolve fetcher.
	fetcher := opts.Fetcher
	if fetcher == nil {
		live, err := NewGHSAFetcher()
		if err != nil {
			return nil, fmt.Errorf("ghsa fetcher: %w", err)
		}
		fetcher = live
	}

	// Worker pool for GHSA.
	type job struct {
		key  repoKey
		pins []pinnedAction
	}
	ghsaJobs := make(chan job, len(repoToPins))
	for k, ps := range repoToPins {
		ghsaJobs <- job{k, ps}
	}
	close(ghsaJobs)

	var wg sync.WaitGroup
	sem := make(chan struct{}, opts.Concurrency)

	for j := range ghsaJobs {
		j := j
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			advisories, err := fetcher.Advisories(j.key.owner, j.key.repo)
			if err != nil {
				// Non-fatal: log to stderr and continue.
				fmt.Fprintf(os.Stderr, "ghactor audit: advisory lookup %s/%s: %v\n",
					j.key.owner, j.key.repo, err)
				return
			}

			for _, pin := range j.pins {
				ver := versionOf(pin)
				for _, adv := range advisories {
					if !advisoryMatchesPin(adv, ver) {
						continue
					}
					id := adv.GHSAID
					if id == "" {
						id = adv.CVEID
					}
					f := Finding{
						File:     pin.file,
						Line:     pin.line,
						Uses:     pin.uses,
						Version:  ver,
						Advisory: id,
						CVSS:     adv.CVSSScore,
						Severity: ghsaSeverityToFinding(adv.Severity),
						Kind:     "ghsa",
						Title:    adv.Title,
						URL:      adv.URL,
					}
					mu.Lock()
					findings = append(findings, f)
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()

	// ---- Repo-metadata checks (archived / missing) ----------------------------

	if opts.CheckArchival || opts.CheckMissing {
		metaFetcher := opts.RepoMeta
		if metaFetcher == nil {
			metaFetcher = NewDefaultRepoMetaFetcher()
		}

		type metaJob struct {
			key  repoKey
			pins []pinnedAction
		}
		metaJobs := make(chan metaJob, len(repoToPins))
		for k, ps := range repoToPins {
			metaJobs <- metaJob{k, ps}
		}
		close(metaJobs)

		for mj := range metaJobs {
			mj := mj
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()

				archived, exists, archivedAt, err := metaFetcher.RepoMeta(mj.key.owner, mj.key.repo)
				if err != nil {
					fmt.Fprintf(os.Stderr, "ghactor audit: repo-meta %s/%s: %v\n",
						mj.key.owner, mj.key.repo, err)
					return
				}

				// Use the representative (first) pin for location info.
				rep := mj.pins[0]

				if !exists && opts.CheckMissing {
					mu.Lock()
					findings = append(findings, Finding{
						File:     rep.file,
						Line:     rep.line,
						Uses:     rep.uses,
						Version:  versionOf(rep),
						Severity: "error",
						Kind:     "missing",
						Title:    fmt.Sprintf("%s/%s: repository not found (deleted or renamed)", mj.key.owner, mj.key.repo),
					})
					mu.Unlock()
					return // if missing, archived is meaningless
				}

				if archived && opts.CheckArchival {
					mu.Lock()
					findings = append(findings, Finding{
						File:       rep.file,
						Line:       rep.line,
						Uses:       rep.uses,
						Version:    versionOf(rep),
						Severity:   "warning",
						Kind:       "archived",
						ArchivedAt: archivedAt,
						Title:      fmt.Sprintf("%s/%s: repository is archived (no security patches)", mj.key.owner, mj.key.repo),
					})
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
	}

	return findings, nil
}

// applyOptionDefaults is a no-op placeholder kept for future use.
// CheckArchival and CheckMissing are explicit opt-in flags; Cmd() sets them
// to true by default and exposes --no-archival / --no-missing to opt out.
// Callers constructing Options directly must set the flags they want.
func applyOptionDefaults(opts Options) Options {
	return opts
}

// advisoryMatchesPin returns true when the advisory's vulnerable range covers
// the pin's resolved version, or when version is unknown but an advisory
// exists (conservative: flag it).
func advisoryMatchesPin(adv Advisory, version string) bool {
	if adv.VulnerableRange == "" {
		// Advisory without a range: always flag (conservative).
		return true
	}
	if version == "unknown-version" {
		// Cannot confirm safety; flag conservatively.
		return true
	}
	if versionInRange(version, adv.VulnerableRange) {
		// Within vulnerable range.
		if adv.PatchedVersion != "" && versionInRange(version, ">= "+adv.PatchedVersion) {
			return false // already patched
		}
		return true
	}
	return false
}

// versionOf returns the human-readable version for a pin: the inline tag
// comment if present, otherwise "unknown-version".
func versionOf(p pinnedAction) string {
	if p.tag != "" {
		return p.tag
	}
	return "unknown-version"
}

// matchesPattern reports whether uses matches a glob-style pattern.
// Supports trailing * wildcard on the ref portion.
func matchesPattern(uses, pattern string) bool {
	// Exact match.
	if uses == pattern {
		return true
	}
	// Wildcard: "owner/repo@*" matches any ref.
	if strings.HasSuffix(pattern, "@*") {
		prefix := pattern[:len(pattern)-1] // strip the trailing *
		return strings.HasPrefix(uses, prefix)
	}
	// Prefix match without ref ("owner/repo").
	if !strings.Contains(pattern, "@") {
		base, _, ok := strings.Cut(uses, "@")
		if ok && strings.EqualFold(base, pattern) {
			return true
		}
	}
	return false
}

// ---- fail-on level ----------------------------------------------------------

type failLevel int

const (
	failNone    failLevel = 0
	failInfo    failLevel = 1
	failWarning failLevel = 2
	failError   failLevel = 3
)

func parseFailOn(s string) failLevel {
	switch strings.ToLower(s) {
	case "info":
		return failInfo
	case "warning":
		return failWarning
	case "error":
		return failError
	default:
		return failNone
	}
}

// shouldFail returns true when any finding's severity meets or exceeds level.
func shouldFail(findings []Finding, level failLevel) bool {
	if level == failNone {
		return false
	}
	for _, f := range findings {
		if findingSeverityLevel(f.Severity) >= level {
			return true
		}
	}
	return false
}

func findingSeverityLevel(sev string) failLevel {
	switch sev {
	case "error":
		return failError
	case "warning":
		return failWarning
	case "info":
		return failInfo
	}
	return failNone
}

// ---- Cobra command ----------------------------------------------------------

// Cmd returns the `audit` cobra subcommand. Wire it via:
//
//	rootCmd.AddCommand(audit.Cmd())
func Cmd() *cobra.Command {
	var (
		dir        string
		jsonOut    bool
		failOn     string
		jobs       int
		offline    bool
		noArchival bool
		noMissing  bool
	)

	cRed    := color.New(color.FgRed, color.Bold).SprintFunc()
	cYellow := color.New(color.FgYellow).SprintFunc()
	cBlue   := color.New(color.FgBlue).SprintFunc()
	cDim    := color.New(color.Faint).SprintFunc()

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Cross-check pinned actions against the GitHub Advisory Database (GHSA)",
		Long: `audit scans workflow files for pinned actions (SHA refs) and queries the
GitHub Advisory Database to flag versions with known vulnerabilities.

It also checks a static deny-list, any deny_actions patterns in .ghactor.yml,
and (by default) whether each action repo is archived or has been deleted.

Exit codes:
  0  clean (no findings at the --fail-on threshold)
  1  findings at or above the --fail-on threshold
  2  fatal error (config, network, etc.)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load optional .ghactor.yml for deny_actions.
			cfg, _ := config.LoadAuto(dir)
			var denyPatterns []string
			if cfg != nil {
				denyPatterns = cfg.DenyActions
			}

			// Archival/missing checks are enabled by default; flags opt out.
			opts := Options{
				Dir:           dir,
				Concurrency:   jobs,
				DenyActions:   denyPatterns,
				Offline:       offline,
				CheckArchival: !noArchival,
				CheckMissing:  !noMissing,
			}

			findings, err := Scan(opts)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ghactor audit: %v\n", err)
				os.Exit(2)
			}

			if jsonOut {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				if err := enc.Encode(findings); err != nil {
					return err
				}
			} else {
				if len(findings) == 0 {
					fmt.Println(cBlue("audit:"), "no findings")
				} else {
					for _, f := range findings {
						var sev string
						switch f.Severity {
						case "error":
							sev = cRed("error")
						case "warning":
							sev = cYellow("warning")
						default:
							sev = cBlue("info")
						}
						loc := fmt.Sprintf("%s:%d", f.File, f.Line)

						switch f.Kind {
						case "archived":
							label := f.Uses
							ts := ""
							if f.ArchivedAt != "" {
								ts = fmt.Sprintf("  (on %s)", f.ArchivedAt)
							}
							fmt.Printf("%s  %s  archived  %-40s%s\n", cDim(loc), sev, label, ts)
						case "missing":
							fmt.Printf("%s  %s  missing   %-40s  (repo not found)\n", cDim(loc), sev, f.Uses)
						default:
							// ghsa finding — original format preserved.
							fmt.Printf("%s  %s  %s\n", cDim(loc), sev, f.Uses)
							fmt.Printf("  advisory : %s\n", f.Advisory)
							if f.Version != "" && f.Version != "unknown-version" {
								fmt.Printf("  version  : %s\n", f.Version)
							} else {
								fmt.Printf("  version  : unknown (add # <tag> comment)\n")
							}
							fmt.Printf("  title    : %s\n", f.Title)
							if f.CVSS > 0 {
								fmt.Printf("  cvss     : %.1f\n", f.CVSS)
							}
							if f.URL != "" {
								fmt.Printf("  url      : %s\n", f.URL)
							}
							fmt.Println()
						}
					}

					var errs, warns, infos int
					for _, f := range findings {
						switch f.Severity {
						case "error":
							errs++
						case "warning":
							warns++
						default:
							infos++
						}
					}
					fmt.Printf("%s  %d error(s)  %d warning(s)  %d info(s)\n",
						cBlue("audit summary:"), errs, warns, infos)
				}
			}

			level := parseFailOn(failOn)
			if shouldFail(findings, level) {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&dir, "dir", "d", ".github/workflows", "workflow directory to scan")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit findings as a JSON array")
	cmd.Flags().StringVar(&failOn, "fail-on", "error", "exit 1 when findings reach this level (error|warning|info|none)")
	cmd.Flags().IntVar(&jobs, "jobs", 4, "number of concurrent advisory lookups")
	cmd.Flags().BoolVar(&offline, "offline", false, "skip live GHSA fetch and repo-meta checks; use only static deny list")
	cmd.Flags().BoolVar(&noArchival, "no-archival", false, "disable check for archived action repositories")
	cmd.Flags().BoolVar(&noMissing, "no-missing", false, "disable check for deleted/renamed action repositories (404)")

	return cmd
}
