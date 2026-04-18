package sarifdiff

import (
	"encoding/json"
	"testing"
)

// testdataPath returns an absolute-ish relative path for test fixtures.
// go test sets the working directory to the package directory, so
// "testdata/..." always resolves correctly.
func td(name string) string { return "testdata/" + name }

// ---------------------------------------------------------------------------
// LoadFile
// ---------------------------------------------------------------------------

func TestLoadFile_Baseline(t *testing.T) {
	results, err := LoadFile(td("baseline.sarif"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := len(results), 3; got != want {
		t.Fatalf("got %d results, want %d", got, want)
	}
}

func TestLoadFile_RuleIndexFallback(t *testing.T) {
	// baseline.sarif has one result using ruleIndex (not ruleId).
	results, err := LoadFile(td("baseline.sarif"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Second result uses ruleIndex:1 which maps to GHA019.
	var found bool
	for _, r := range results {
		if r.RuleID == "GHA019" {
			found = true
			break
		}
	}
	if !found {
		t.Error("ruleIndex fallback: expected RuleID GHA019 to be resolved from ruleIndex")
	}
}

func TestLoadFile_Malformed(t *testing.T) {
	_, err := LoadFile(td("malformed.sarif"))
	if err == nil {
		t.Fatal("expected error for malformed SARIF, got nil")
	}
}

func TestLoadFile_Missing(t *testing.T) {
	_, err := LoadFile(td("does-not-exist.sarif"))
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoadFile_Empty(t *testing.T) {
	results, err := LoadFile(td("empty.sarif"))
	if err != nil {
		t.Fatalf("unexpected error on empty SARIF: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

// ---------------------------------------------------------------------------
// Compare — default (line-insensitive)
// ---------------------------------------------------------------------------

// Fixtures:
//   baseline.sarif  — GHA004@deploy:34, GHA019@release:12, GHA005@deploy:1
//   pr.sarif        — GHA004@deploy:38 (same finding, shifted line), GHA019@release:12 (unchanged), GHA007@ci:18 (new)
//
// Expected:
//   New:       [GHA007]
//   Fixed:     [GHA005]
//   Unchanged: [GHA004, GHA019]  (GHA004 line shift ignored by default)

func TestCompare_DefaultLineSensitive(t *testing.T) {
	old, err := LoadFile(td("baseline.sarif"))
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}
	pr, err := LoadFile(td("pr.sarif"))
	if err != nil {
		t.Fatalf("load pr: %v", err)
	}

	d := Compare(old, pr, Options{})

	if got, want := len(d.New), 1; got != want {
		t.Errorf("New: got %d, want %d — %v", got, want, d.New)
	}
	if got, want := len(d.Fixed), 1; got != want {
		t.Errorf("Fixed: got %d, want %d — %v", got, want, d.Fixed)
	}
	if got, want := len(d.Unchanged), 2; got != want {
		t.Errorf("Unchanged: got %d, want %d — %v", got, want, d.Unchanged)
	}

	// Validate specific results.
	if len(d.New) > 0 && d.New[0].RuleID != "GHA007" {
		t.Errorf("New[0]: got RuleID %q, want GHA007", d.New[0].RuleID)
	}
	if len(d.Fixed) > 0 && d.Fixed[0].RuleID != "GHA005" {
		t.Errorf("Fixed[0]: got RuleID %q, want GHA005", d.Fixed[0].RuleID)
	}
}

// ---------------------------------------------------------------------------
// Compare — line-sensitive
// ---------------------------------------------------------------------------

// With LineSensitive=true the GHA004 finding (line 34 → 38) should appear as
// both Fixed (old) and New (new), so:
//   New:       [GHA004@38, GHA007]
//   Fixed:     [GHA004@34, GHA005]
//   Unchanged: [GHA019]

func TestCompare_LineSensitive(t *testing.T) {
	old, err := LoadFile(td("baseline.sarif"))
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}
	pr, err := LoadFile(td("pr.sarif"))
	if err != nil {
		t.Fatalf("load pr: %v", err)
	}

	d := Compare(old, pr, Options{LineSensitive: true})

	if got, want := len(d.New), 2; got != want {
		t.Errorf("New: got %d, want %d — %v", got, want, d.New)
	}
	if got, want := len(d.Fixed), 2; got != want {
		t.Errorf("Fixed: got %d, want %d — %v", got, want, d.Fixed)
	}
	if got, want := len(d.Unchanged), 1; got != want {
		t.Errorf("Unchanged: got %d, want %d — %v", got, want, d.Unchanged)
	}
}

// ---------------------------------------------------------------------------
// Compare — empty inputs
// ---------------------------------------------------------------------------

func TestCompare_BothEmpty(t *testing.T) {
	old, _ := LoadFile(td("empty.sarif"))
	pr, _ := LoadFile(td("empty.sarif"))
	d := Compare(old, pr, Options{})
	if len(d.New)+len(d.Fixed)+len(d.Unchanged) != 0 {
		t.Errorf("expected all empty partitions, got %+v", d)
	}
}

func TestCompare_OldEmpty(t *testing.T) {
	old, _ := LoadFile(td("empty.sarif"))
	pr, _ := LoadFile(td("pr.sarif"))
	d := Compare(old, pr, Options{})
	if len(d.New) != len(pr) {
		t.Errorf("all new results should be New; got %d New, want %d", len(d.New), len(pr))
	}
	if len(d.Fixed)+len(d.Unchanged) != 0 {
		t.Errorf("expected 0 Fixed+Unchanged when old is empty")
	}
}

func TestCompare_NewEmpty(t *testing.T) {
	old, _ := LoadFile(td("baseline.sarif"))
	empty, _ := LoadFile(td("empty.sarif"))
	d := Compare(old, empty, Options{})
	if len(d.Fixed) != len(old) {
		t.Errorf("all old results should be Fixed; got %d Fixed, want %d", len(d.Fixed), len(old))
	}
	if len(d.New)+len(d.Unchanged) != 0 {
		t.Errorf("expected 0 New+Unchanged when new is empty")
	}
}

// ---------------------------------------------------------------------------
// Merge
// ---------------------------------------------------------------------------

func TestMerge_Dedup(t *testing.T) {
	// merge_a has GHA004@triage:10, GHA005@triage:1
	// merge_b has GHA004@triage:10 (same fingerprint), GHA007@release:22
	// merged should have 3 unique results (GHA004 deduped).
	data, err := Merge([]string{td("merge_a.sarif"), td("merge_b.sarif")})
	if err != nil {
		t.Fatalf("merge error: %v", err)
	}

	// Parse the output as a SARIF file to count results.
	results, err := parseBytes("merged", data)
	if err != nil {
		t.Fatalf("parse merged: %v", err)
	}
	if got, want := len(results), 3; got != want {
		t.Errorf("merged result count: got %d, want %d", got, want)
	}

	// Validate it is valid JSON at least.
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("merged output is not valid JSON: %v", err)
	}
}

func TestMerge_SingleFile(t *testing.T) {
	data, err := Merge([]string{td("baseline.sarif")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	results, err := parseBytes("single", data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got, want := len(results), 3; got != want {
		t.Errorf("single-file merge: got %d results, want %d", got, want)
	}
}

func TestMerge_Empty(t *testing.T) {
	_, err := Merge([]string{})
	if err == nil {
		t.Fatal("expected error for empty path list")
	}
}

func TestMerge_MalformedInput(t *testing.T) {
	_, err := Merge([]string{td("malformed.sarif")})
	if err == nil {
		t.Fatal("expected error for malformed SARIF in merge")
	}
}

// ---------------------------------------------------------------------------
// Normalisation
// ---------------------------------------------------------------------------

func TestNormalizeMessage(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "SHA replaced",
			input: "pinned to abcdef1234567890abcdef1234567890abcdef12",
			want:  "pinned to <SHA>",
		},
		{
			name:  "semver tag replaced",
			input: "action actions/checkout@v3.2.1 is not pinned",
			want:  "action actions/checkout@<TAG> is not pinned",
		},
		{
			name:  "line marker in message",
			input: "found issue at line 42 in file",
			want:  "found issue at <N> in file",
		},
		{
			name:  "duration",
			input: "request took 120ms to complete",
			want:  "request took <DUR> to complete",
		},
		{
			name:  "whitespace collapse",
			input: "  foo   bar  ",
			want:  "foo bar",
		},
		{
			name:  "identical messages unchanged",
			input: "missing top-level permissions block",
			want:  "missing top-level permissions block",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeMessage(tt.input)
			if got != tt.want {
				t.Errorf("normalizeMessage(%q)\n  got  %q\n  want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeFile(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{".github/workflows/ci.yml", ".github/workflows/ci.yml"},
		{"./.github/workflows/ci.yml", ".github/workflows/ci.yml"},
		{"/.github/workflows/ci.yml", ".github/workflows/ci.yml"},
		{`.github\workflows\ci.yml`, ".github/workflows/ci.yml"},
	}
	for _, tt := range tests {
		if got := normalizeFile(tt.input); got != tt.want {
			t.Errorf("normalizeFile(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Fingerprint stability
// ---------------------------------------------------------------------------

// The same logical finding at different lines must produce the same fingerprint
// when LineSensitive is false.
func TestFingerprint_LineShiftIgnored(t *testing.T) {
	a := Result{RuleID: "GHA004", File: ".github/workflows/deploy.yml", Line: 34, Message: "Untrusted context"}
	b := Result{RuleID: "GHA004", File: ".github/workflows/deploy.yml", Line: 99, Message: "Untrusted context"}

	if fingerprint(a, false) != fingerprint(b, false) {
		t.Error("fingerprints differ for line-shifted result when LineSensitive=false")
	}
	if fingerprint(a, true) == fingerprint(b, true) {
		t.Error("fingerprints should differ for line-shifted result when LineSensitive=true")
	}
}
