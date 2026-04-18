package audit

import (
	"os"
	"path/filepath"
	"testing"
)

// ---- mock Fetcher -----------------------------------------------------------

type mockFetcher struct {
	advisories map[string][]Advisory // key: "owner/repo"
	err        map[string]error
}

func (m *mockFetcher) Advisories(owner, repo string) ([]Advisory, error) {
	key := owner + "/" + repo
	if m.err != nil {
		if e, ok := m.err[key]; ok {
			return nil, e
		}
	}
	return m.advisories[key], nil
}

// ---- helpers ----------------------------------------------------------------

// writeWorkflow creates a temporary directory with a single workflow YAML that
// contains the given `uses:` line (with an optional trailing comment).
func writeWorkflow(t *testing.T, usesLine string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), ".github", "workflows")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	content := `name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - ` + usesLine + "\n"
	if err := os.WriteFile(filepath.Join(dir, "ci.yml"), []byte(content), 0o644); err != nil {
		t.Fatalf("write workflow: %v", err)
	}
	return dir
}

const (
	// A realistic 40-char SHA used in tests.
	testSHA = "4b0e3b8c1234567890abcdef1234567890abcdef"
)

// ---- tests ------------------------------------------------------------------

// TestNoAdvisories: when the fetcher returns no advisories, Scan returns zero findings.
func TestNoAdvisories(t *testing.T) {
	dir := writeWorkflow(t, "uses: actions/checkout@"+testSHA+" # v4.1.0")
	fetcher := &mockFetcher{
		advisories: map[string][]Advisory{
			"actions/checkout": {},
		},
	}
	findings, err := Scan(Options{Dir: dir, Fetcher: fetcher, Concurrency: 1})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}

// TestVulnerableRangeMatch: an advisory whose range covers the pinned version → finding.
func TestVulnerableRangeMatch(t *testing.T) {
	dir := writeWorkflow(t, "uses: actions/checkout@"+testSHA+" # v3.5.0")
	fetcher := &mockFetcher{
		advisories: map[string][]Advisory{
			"actions/checkout": {
				{
					GHSAID:          "GHSA-1234-5678-abcd",
					Severity:        "high",
					CVSSScore:       8.1,
					Title:           "Dangerous code execution",
					URL:             "https://github.com/advisories/GHSA-1234-5678-abcd",
					VulnerableRange: ">= 3.0, < 4.0",
					PatchedVersion:  "4.0.0",
				},
			},
		},
	}
	findings, err := Scan(Options{Dir: dir, Fetcher: fetcher, Concurrency: 1})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Advisory != "GHSA-1234-5678-abcd" {
		t.Errorf("wrong advisory ID: %q", f.Advisory)
	}
	if f.Version != "v3.5.0" {
		t.Errorf("wrong version: %q", f.Version)
	}
	if f.Severity != "error" {
		t.Errorf("expected error severity for high GHSA, got %q", f.Severity)
	}
	if f.CVSS != 8.1 {
		t.Errorf("expected CVSS 8.1, got %v", f.CVSS)
	}
}

// TestPatchedVersionNoFinding: an advisory whose patched version is <= the pin → no finding.
func TestPatchedVersionNoFinding(t *testing.T) {
	// Pin is v4.1.0, advisory covers < 4.0 — already patched.
	dir := writeWorkflow(t, "uses: actions/checkout@"+testSHA+" # v4.1.0")
	fetcher := &mockFetcher{
		advisories: map[string][]Advisory{
			"actions/checkout": {
				{
					GHSAID:          "GHSA-9999-aaaa-bbbb",
					Severity:        "critical",
					CVSSScore:       9.5,
					Title:           "Old vulnerability",
					URL:             "https://github.com/advisories/GHSA-9999-aaaa-bbbb",
					VulnerableRange: "< 4.0",
					PatchedVersion:  "4.0.0",
				},
			},
		},
	}
	findings, err := Scan(Options{Dir: dir, Fetcher: fetcher, Concurrency: 1})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings (version is patched), got %d: %+v", len(findings), findings)
	}
}

// TestSeverityMapping: checks that all four GHSA severity levels map correctly.
func TestSeverityMapping(t *testing.T) {
	tests := []struct {
		ghsaSev    string
		wantFinSev string
	}{
		{"critical", "error"},
		{"high", "error"},
		{"medium", "warning"},
		{"low", "info"},
		{"unknown", "info"},
		{"", "info"},
	}
	for _, tc := range tests {
		t.Run(tc.ghsaSev, func(t *testing.T) {
			got := ghsaSeverityToFinding(tc.ghsaSev)
			if got != tc.wantFinSev {
				t.Errorf("ghsaSeverityToFinding(%q) = %q, want %q", tc.ghsaSev, got, tc.wantFinSev)
			}
		})
	}
}

// TestUnknownVersionFlaggedConservatively: a pin without a tag comment and an
// advisory with a non-empty range → finding (conservative).
func TestUnknownVersionFlaggedConservatively(t *testing.T) {
	// No tag comment — version will be "unknown-version".
	dir := writeWorkflow(t, "uses: actions/setup-node@"+testSHA)
	fetcher := &mockFetcher{
		advisories: map[string][]Advisory{
			"actions/setup-node": {
				{
					GHSAID:          "GHSA-xxxx-yyyy-zzzz",
					Severity:        "medium",
					Title:           "Possible injection",
					URL:             "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
					VulnerableRange: "< 3.0",
				},
			},
		},
	}
	findings, err := Scan(Options{Dir: dir, Fetcher: fetcher, Concurrency: 1})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for unknown version, got %d", len(findings))
	}
	if findings[0].Version != "unknown-version" {
		t.Errorf("expected unknown-version, got %q", findings[0].Version)
	}
	if findings[0].Severity != "warning" {
		t.Errorf("expected warning severity for medium, got %q", findings[0].Severity)
	}
}

// TestOfflineSkipsLiveFetch: --offline skips the Fetcher entirely.
func TestOfflineSkipsLiveFetch(t *testing.T) {
	dir := writeWorkflow(t, "uses: actions/checkout@"+testSHA+" # v4.1.0")
	// This fetcher panics if called.
	panicking := &panicFetcher{}
	findings, err := Scan(Options{Dir: dir, Fetcher: panicking, Offline: true, Concurrency: 1})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	// Static known-bad list is empty, so no findings expected.
	if len(findings) != 0 {
		t.Errorf("expected 0 findings offline, got %d", len(findings))
	}
}

type panicFetcher struct{}

func (p *panicFetcher) Advisories(_, _ string) ([]Advisory, error) {
	panic("fetcher should not be called in offline mode")
}

// ---- fake RepoMetaFetcher ---------------------------------------------------

// fakeRepoMeta is a map-driven stub for RepoMetaFetcher.
// Key: "owner/repo"
// Value: repoMetaResult
type repoMetaResult struct {
	archived   bool
	exists     bool
	archivedAt string
}

type fakeRepoMeta struct {
	repos  map[string]repoMetaResult
	calls  int // how many times RepoMeta was called (for dedup assertions)
}

func (f *fakeRepoMeta) RepoMeta(owner, repo string) (bool, bool, string, error) {
	f.calls++
	key := owner + "/" + repo
	r, ok := f.repos[key]
	if !ok {
		// Default: active repo, exists.
		return false, true, "", nil
	}
	return r.archived, r.exists, r.archivedAt, nil
}

// noOpMetaFetcher returns active/exists for all repos.
type noOpMetaFetcher struct{}

func (n *noOpMetaFetcher) RepoMeta(_, _ string) (bool, bool, string, error) {
	return false, true, "", nil
}

// panicMetaFetcher panics if called — used to assert checks were skipped.
type panicMetaFetcher struct{}

func (p *panicMetaFetcher) RepoMeta(_, _ string) (bool, bool, string, error) {
	panic("RepoMeta should not be called")
}

// ---- repo-meta tests --------------------------------------------------------

// TestArchivedRepo: an archived repo → Finding with Kind=archived, severity=warning.
func TestArchivedRepo(t *testing.T) {
	dir := writeWorkflow(t, "uses: actions/create-release@"+testSHA+" # v1.0.0")
	meta := &fakeRepoMeta{
		repos: map[string]repoMetaResult{
			"actions/create-release": {archived: true, exists: true, archivedAt: "2022-04-15T00:00:00Z"},
		},
	}
	findings, err := Scan(Options{
		Dir:           dir,
		Fetcher:       &mockFetcher{advisories: map[string][]Advisory{}},
		RepoMeta:      meta,
		CheckArchival: true,
		CheckMissing:  true,
		Concurrency:   1,
	})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	var archived []Finding
	for _, f := range findings {
		if f.Kind == "archived" {
			archived = append(archived, f)
		}
	}
	if len(archived) != 1 {
		t.Fatalf("expected 1 archived finding, got %d: %+v", len(archived), findings)
	}
	f := archived[0]
	if f.Severity != "warning" {
		t.Errorf("archived finding severity = %q, want warning", f.Severity)
	}
	if f.ArchivedAt != "2022-04-15T00:00:00Z" {
		t.Errorf("archived_at = %q, want 2022-04-15T00:00:00Z", f.ArchivedAt)
	}
}

// TestMissingRepo: a 404 repo → Finding with Kind=missing, severity=error.
func TestMissingRepo(t *testing.T) {
	dir := writeWorkflow(t, "uses: foo/bar@"+testSHA+" # v2.0.0")
	meta := &fakeRepoMeta{
		repos: map[string]repoMetaResult{
			"foo/bar": {archived: false, exists: false},
		},
	}
	findings, err := Scan(Options{
		Dir:           dir,
		Fetcher:       &mockFetcher{advisories: map[string][]Advisory{}},
		RepoMeta:      meta,
		CheckArchival: true,
		CheckMissing:  true,
		Concurrency:   1,
	})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	var missing []Finding
	for _, f := range findings {
		if f.Kind == "missing" {
			missing = append(missing, f)
		}
	}
	if len(missing) != 1 {
		t.Fatalf("expected 1 missing finding, got %d: %+v", len(missing), findings)
	}
	if missing[0].Severity != "error" {
		t.Errorf("missing finding severity = %q, want error", missing[0].Severity)
	}
}

// TestActiveRepo: an active repo → no archived/missing findings.
func TestActiveRepo(t *testing.T) {
	dir := writeWorkflow(t, "uses: actions/checkout@"+testSHA+" # v4.1.0")
	meta := &fakeRepoMeta{
		repos: map[string]repoMetaResult{
			"actions/checkout": {archived: false, exists: true},
		},
	}
	findings, err := Scan(Options{
		Dir:           dir,
		Fetcher:       &mockFetcher{advisories: map[string][]Advisory{}},
		RepoMeta:      meta,
		CheckArchival: true,
		CheckMissing:  true,
		Concurrency:   1,
	})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	for _, f := range findings {
		if f.Kind == "archived" || f.Kind == "missing" {
			t.Errorf("unexpected repo-meta finding for active repo: %+v", f)
		}
	}
}

// TestNoArchivalFlag: CheckArchival=false suppresses archived findings.
func TestNoArchivalFlag(t *testing.T) {
	dir := writeWorkflow(t, "uses: actions/create-release@"+testSHA+" # v1.0.0")
	meta := &fakeRepoMeta{
		repos: map[string]repoMetaResult{
			"actions/create-release": {archived: true, exists: true, archivedAt: "2022-04-15T00:00:00Z"},
		},
	}
	findings, err := Scan(Options{
		Dir:           dir,
		Fetcher:       &mockFetcher{advisories: map[string][]Advisory{}},
		RepoMeta:      meta,
		CheckArchival: false,
		CheckMissing:  true,
		Concurrency:   1,
	})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	for _, f := range findings {
		if f.Kind == "archived" {
			t.Errorf("expected no archived finding when CheckArchival=false, got: %+v", f)
		}
	}
}

// TestNoMissingFlag: CheckMissing=false suppresses missing findings.
func TestNoMissingFlag(t *testing.T) {
	dir := writeWorkflow(t, "uses: foo/bar@"+testSHA+" # v2.0.0")
	meta := &fakeRepoMeta{
		repos: map[string]repoMetaResult{
			"foo/bar": {archived: false, exists: false},
		},
	}
	findings, err := Scan(Options{
		Dir:           dir,
		Fetcher:       &mockFetcher{advisories: map[string][]Advisory{}},
		RepoMeta:      meta,
		CheckArchival: true,
		CheckMissing:  false,
		Concurrency:   1,
	})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	for _, f := range findings {
		if f.Kind == "missing" {
			t.Errorf("expected no missing finding when CheckMissing=false, got: %+v", f)
		}
	}
}

// TestRepoMetaDedup: the same action used in 3 workflow files → only 1 meta fetch.
func TestRepoMetaDedup(t *testing.T) {
	// Write 3 workflow files all using the same action.
	base := t.TempDir()
	wfDir := base + "/.github/workflows"
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	sha := testSHA
	for _, name := range []string{"a.yml", "b.yml", "c.yml"} {
		content := "name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: org/shared-action@" + sha + " # v1.0.0\n"
		if err := os.WriteFile(wfDir+"/"+name, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	meta := &fakeRepoMeta{
		repos: map[string]repoMetaResult{
			"org/shared-action": {archived: true, exists: true, archivedAt: "2023-01-01T00:00:00Z"},
		},
	}
	findings, err := Scan(Options{
		Dir:           wfDir,
		Fetcher:       &mockFetcher{advisories: map[string][]Advisory{}},
		RepoMeta:      meta,
		CheckArchival: true,
		CheckMissing:  true,
		Concurrency:   1,
	})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if meta.calls != 1 {
		t.Errorf("expected 1 RepoMeta call (dedup), got %d", meta.calls)
	}
	var archived []Finding
	for _, f := range findings {
		if f.Kind == "archived" {
			archived = append(archived, f)
		}
	}
	if len(archived) != 1 {
		t.Errorf("expected 1 archived finding (dedup), got %d", len(archived))
	}
}

// TestOfflineSkipsRepoMetaChecks: --offline skips RepoMeta entirely.
func TestOfflineSkipsRepoMetaChecks(t *testing.T) {
	dir := writeWorkflow(t, "uses: actions/checkout@"+testSHA+" # v4.1.0")
	findings, err := Scan(Options{
		Dir:           dir,
		Fetcher:       &panicFetcher{},
		RepoMeta:      &panicMetaFetcher{},
		CheckArchival: true,
		CheckMissing:  true,
		Offline:       true,
		Concurrency:   1,
	})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings in offline mode, got %d", len(findings))
	}
}

// TestJSONBackwardCompat: a GHSA-only run produces findings without kind/archived_at
// when the advisory is a legacy finding (Kind would be "ghsa" with omitempty — but
// since Kind is set to "ghsa" it will appear; verify the shape is stable for consumers
// that only care about existing fields).
func TestJSONBackwardCompat(t *testing.T) {
	dir := writeWorkflow(t, "uses: actions/checkout@"+testSHA+" # v3.5.0")
	fetcher := &mockFetcher{
		advisories: map[string][]Advisory{
			"actions/checkout": {
				{
					GHSAID:          "GHSA-1234-5678-abcd",
					Severity:        "high",
					CVSSScore:       8.1,
					Title:           "Test vuln",
					URL:             "https://github.com/advisories/GHSA-1234-5678-abcd",
					VulnerableRange: ">= 3.0, < 4.0",
					PatchedVersion:  "4.0.0",
				},
			},
		},
	}
	findings, err := Scan(Options{
		Dir:           dir,
		Fetcher:       fetcher,
		RepoMeta:      &noOpMetaFetcher{},
		CheckArchival: true,
		CheckMissing:  true,
		Concurrency:   1,
	})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	// Verify existing fields are present and correct.
	if f.Advisory != "GHSA-1234-5678-abcd" {
		t.Errorf("advisory = %q", f.Advisory)
	}
	if f.CVSS != 8.1 {
		t.Errorf("cvss = %v", f.CVSS)
	}
	if f.Severity != "error" {
		t.Errorf("severity = %q", f.Severity)
	}
	if f.Kind != "ghsa" {
		t.Errorf("kind = %q, want ghsa", f.Kind)
	}
	// New fields must be zero/empty for GHSA findings.
	if f.ArchivedAt != "" {
		t.Errorf("archived_at should be empty for ghsa finding, got %q", f.ArchivedAt)
	}
}

// TestNonPinnedRefsIgnored: action refs that are branch/tag (not SHA) are skipped.
func TestNonPinnedRefsIgnored(t *testing.T) {
	dir := writeWorkflow(t, "uses: actions/checkout@v4")
	fetcher := &mockFetcher{advisories: map[string][]Advisory{}}
	findings, err := Scan(Options{Dir: dir, Fetcher: fetcher, Concurrency: 1})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-pinned ref, got %d", len(findings))
	}
}

// TestDenyActionsPattern: a pattern in DenyActions generates an error finding.
func TestDenyActionsPattern(t *testing.T) {
	dir := writeWorkflow(t, "uses: evil-corp/bad-action@"+testSHA+" # v1.0.0")
	fetcher := &mockFetcher{
		advisories: map[string][]Advisory{
			"evil-corp/bad-action": {},
		},
	}
	findings, err := Scan(Options{
		Dir:         dir,
		Fetcher:     fetcher,
		DenyActions: []string{"evil-corp/bad-action@*"},
		Concurrency: 1,
	})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for deny pattern, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != "error" {
		t.Errorf("deny-list finding should be error, got %q", findings[0].Severity)
	}
	if findings[0].Advisory != "deny-list" {
		t.Errorf("deny-list advisory ID wrong: %q", findings[0].Advisory)
	}
}

// TestMultipleAdvisories: two advisories for one action → two findings.
func TestMultipleAdvisories(t *testing.T) {
	dir := writeWorkflow(t, "uses: org/action@"+testSHA+" # v2.3.0")
	fetcher := &mockFetcher{
		advisories: map[string][]Advisory{
			"org/action": {
				{
					GHSAID:          "GHSA-aaaa-1111-bbbb",
					Severity:        "high",
					Title:           "First vuln",
					VulnerableRange: ">= 2.0, < 3.0",
				},
				{
					GHSAID:          "GHSA-cccc-2222-dddd",
					Severity:        "medium",
					Title:           "Second vuln",
					VulnerableRange: ">= 2.3, < 2.5",
				},
			},
		},
	}
	findings, err := Scan(Options{Dir: dir, Fetcher: fetcher, Concurrency: 1})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(findings), findings)
	}
}

// ---- unit tests for helper functions ----------------------------------------

func TestVersionInRange(t *testing.T) {
	tests := []struct {
		version string
		r       string
		want    bool
	}{
		{"v3.5.0", ">= 3.0, < 4.0", true},
		{"v4.1.0", ">= 3.0, < 4.0", false},
		{"v4.0.0", ">= 3.0, < 4.0", false},
		{"v2.9.9", ">= 3.0, < 4.0", false},
		{"v4.0.0", ">= 3.0, <= 4.0", true},
		{"v3.0.0", ">= 3.0", true},
		{"v2.9", ">= 3.0", false},
		{"v3.0.0", "< 3.0", false},
		{"v2.9.9", "< 3.0", true},
		{"46", "< 46", false},
		{"45", "< 46", true},
		{"46", "<= 46", true},
		{"", "< 46", false},
		{"unknown-version", "< 46", false},
		{"v1.0.0", "", false},
	}
	for _, tc := range tests {
		got := versionInRange(tc.version, tc.r)
		if got != tc.want {
			t.Errorf("versionInRange(%q, %q) = %v, want %v", tc.version, tc.r, got, tc.want)
		}
	}
}

func TestSplitUses(t *testing.T) {
	tests := []struct {
		uses        string
		wantOwner   string
		wantRepo    string
		wantRef     string
		wantOK      bool
	}{
		{"actions/checkout@v4", "actions", "checkout", "v4", true},
		{"actions/checkout@" + testSHA, "actions", "checkout", testSHA, true},
		{"org/repo/subdir@v1", "org", "repo", "v1", true},
		{"no-at-sign", "", "", "", false},
		{"onlyone", "", "", "", false},
	}
	for _, tc := range tests {
		owner, repo, ref, ok := splitUses(tc.uses)
		if ok != tc.wantOK {
			t.Errorf("splitUses(%q) ok=%v, want %v", tc.uses, ok, tc.wantOK)
			continue
		}
		if owner != tc.wantOwner || repo != tc.wantRepo || ref != tc.wantRef {
			t.Errorf("splitUses(%q) = (%q,%q,%q), want (%q,%q,%q)",
				tc.uses, owner, repo, ref, tc.wantOwner, tc.wantRepo, tc.wantRef)
		}
	}
}

func TestMatchesPattern(t *testing.T) {
	sha := testSHA
	tests := []struct {
		uses    string
		pattern string
		want    bool
	}{
		{"tj-actions/changed-files@" + sha, "tj-actions/changed-files@*", true},
		{"other/action@" + sha, "tj-actions/changed-files@*", false},
		{"actions/checkout@" + sha, "actions/checkout", true},
		{"actions/checkout@" + sha, "actions/setup-node", false},
		{"actions/checkout@" + sha, "actions/checkout@" + sha, true},
	}
	for _, tc := range tests {
		got := matchesPattern(tc.uses, tc.pattern)
		if got != tc.want {
			t.Errorf("matchesPattern(%q, %q) = %v, want %v", tc.uses, tc.pattern, got, tc.want)
		}
	}
}

func TestParseFailOn(t *testing.T) {
	tests := []struct {
		in   string
		want failLevel
	}{
		{"error", failError},
		{"warning", failWarning},
		{"info", failInfo},
		{"none", failNone},
		{"ERROR", failError},
		{"", failNone},
	}
	for _, tc := range tests {
		got := parseFailOn(tc.in)
		if got != tc.want {
			t.Errorf("parseFailOn(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestShouldFail(t *testing.T) {
	findings := []Finding{
		{Severity: "warning"},
	}
	if shouldFail(findings, failError) {
		t.Error("warning finding should not trigger fail-on=error")
	}
	if !shouldFail(findings, failWarning) {
		t.Error("warning finding should trigger fail-on=warning")
	}
	if !shouldFail(findings, failInfo) {
		t.Error("warning finding should trigger fail-on=info")
	}
	if shouldFail(findings, failNone) {
		t.Error("fail-on=none should never trigger")
	}
}
