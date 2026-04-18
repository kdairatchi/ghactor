package baseline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kdairatchi/ghactor/internal/lint"
)

// ---------------------------------------------------------------------------
// helper constructors
// ---------------------------------------------------------------------------

func issue(file, kind, msg string, line int) lint.Issue {
	return lint.Issue{
		File:     file,
		Line:     line,
		Col:      1,
		Kind:     kind,
		Severity: lint.SevError,
		Message:  msg,
		Source:   "ghactor",
	}
}

// ---------------------------------------------------------------------------
// normalizeMessage
// ---------------------------------------------------------------------------

func TestNormalizeMessage(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "strips line markers",
			input: "error at line:42 in file",
			want:  "error at line in file",
		},
		{
			name:  "replaces 40-char hex SHA",
			input: "commit a3f2b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0 is bad",
			want:  "commit <sha> is bad",
		},
		{
			name:  "replaces semver",
			input: "action pinned to 1.2.3 is outdated",
			want:  "action pinned to <ver> is outdated",
		},
		{
			name:  "collapses whitespace runs",
			input: "too   many   spaces",
			want:  "too many spaces",
		},
		{
			name:  "strips leading/trailing whitespace",
			input: "  leading and trailing  ",
			want:  "leading and trailing",
		},
		{
			name:  "no changes on clean message",
			input: "action uses unpinned ref",
			want:  "action uses unpinned ref",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeMessage(tc.input)
			if got != tc.want {
				t.Errorf("normalizeMessage(%q)\n got  %q\n want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// FingerprintIssue
// ---------------------------------------------------------------------------

func TestFingerprintIssue(t *testing.T) {
	base := issue("workflows/ci.yml", "GHA001", "action uses unpinned ref", 10)

	t.Run("same issue twice produces identical fingerprint", func(t *testing.T) {
		h1 := FingerprintIssue(base)
		h2 := FingerprintIssue(base)
		if h1 != h2 {
			t.Errorf("expected same hash, got %q and %q", h1, h2)
		}
	})

	t.Run("different line number produces same fingerprint", func(t *testing.T) {
		shifted := base
		shifted.Line = 99
		if FingerprintIssue(base) != FingerprintIssue(shifted) {
			t.Error("expected same fingerprint regardless of line number change")
		}
	})

	t.Run("different col number produces same fingerprint", func(t *testing.T) {
		shifted := base
		shifted.Col = 42
		if FingerprintIssue(base) != FingerprintIssue(shifted) {
			t.Error("expected same fingerprint regardless of col change")
		}
	})

	t.Run("version suffix normalised away", func(t *testing.T) {
		v1 := issue("workflows/ci.yml", "GHA001", "action pinned to 1.0.0 is outdated", 10)
		v2 := issue("workflows/ci.yml", "GHA001", "action pinned to 2.3.4 is outdated", 10)
		if FingerprintIssue(v1) != FingerprintIssue(v2) {
			t.Error("expected same fingerprint after version normalisation")
		}
	})

	t.Run("different rule produces different fingerprint", func(t *testing.T) {
		other := base
		other.Kind = "GHA002"
		if FingerprintIssue(base) == FingerprintIssue(other) {
			t.Error("expected different fingerprints for different rules")
		}
	})

	t.Run("different file produces different fingerprint", func(t *testing.T) {
		other := base
		other.File = "workflows/deploy.yml"
		if FingerprintIssue(base) == FingerprintIssue(other) {
			t.Error("expected different fingerprints for different files")
		}
	})

	t.Run("different message produces different fingerprint", func(t *testing.T) {
		other := base
		other.Message = "completely different message"
		if FingerprintIssue(base) == FingerprintIssue(other) {
			t.Error("expected different fingerprints for different messages")
		}
	})

	t.Run("SHA in message normalised", func(t *testing.T) {
		sha1 := issue("workflows/ci.yml", "GHA001", "commit a3f2b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0 found", 5)
		sha2 := issue("workflows/ci.yml", "GHA001", "commit 0000000000000000000000000000000000000000 found", 5)
		if FingerprintIssue(sha1) != FingerprintIssue(sha2) {
			t.Error("expected same fingerprint when only SHA differs")
		}
	})
}

// ---------------------------------------------------------------------------
// Save / Load round-trip
// ---------------------------------------------------------------------------

func TestSaveLoadRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "baseline.json")

	issues := []lint.Issue{
		issue("workflows/ci.yml", "GHA001", "unpinned action", 5),
		issue("workflows/deploy.yml", "GHA003", "write-all permissions", 12),
	}

	original := &File{
		Version:      fileVersion,
		Generated:    time.Now().UTC().Truncate(time.Second),
		Generator:    generatorTag,
		Fingerprints: buildFingerprints(issues),
	}

	if err := Save(path, original); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.Version != original.Version {
		t.Errorf("Version: got %d want %d", loaded.Version, original.Version)
	}
	if loaded.Generator != original.Generator {
		t.Errorf("Generator: got %q want %q", loaded.Generator, original.Generator)
	}
	if len(loaded.Fingerprints) != len(original.Fingerprints) {
		t.Errorf("Fingerprints count: got %d want %d", len(loaded.Fingerprints), len(original.Fingerprints))
	}
	for i, fp := range loaded.Fingerprints {
		if fp.Hash != original.Fingerprints[i].Hash {
			t.Errorf("Fingerprint[%d] hash mismatch: got %q want %q", i, fp.Hash, original.Fingerprints[i].Hash)
		}
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/path/baseline.json")
	if err == nil {
		t.Error("expected error loading nonexistent file, got nil")
	}
}

func TestLoadCorruptJSON(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "bad.json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Error("expected error parsing corrupt JSON, got nil")
	}
}

// ---------------------------------------------------------------------------
// Filter
// ---------------------------------------------------------------------------

func TestFilter(t *testing.T) {
	known := issue("workflows/ci.yml", "GHA001", "unpinned action", 5)
	alsoKnown := issue("workflows/ci.yml", "GHA001", "unpinned action", 7) // same fingerprint, shifted line
	newIssue := issue("workflows/ci.yml", "GHA003", "write-all permissions", 20)
	unrelated := issue("workflows/other.yml", "GHA002", "secret in env", 3)

	f := &File{
		Version:      fileVersion,
		Generated:    time.Now().UTC(),
		Generator:    generatorTag,
		Fingerprints: buildFingerprints([]lint.Issue{known}),
	}

	t.Run("known issue is suppressed", func(t *testing.T) {
		suppressed, newOnes := Filter([]lint.Issue{known}, f)
		if len(suppressed) != 1 {
			t.Errorf("expected 1 suppressed, got %d", len(suppressed))
		}
		if len(newOnes) != 0 {
			t.Errorf("expected 0 new, got %d", len(newOnes))
		}
	})

	t.Run("shifted-line duplicate is also suppressed", func(t *testing.T) {
		suppressed, newOnes := Filter([]lint.Issue{alsoKnown}, f)
		if len(suppressed) != 1 {
			t.Errorf("expected 1 suppressed for shifted issue, got %d", len(suppressed))
		}
		if len(newOnes) != 0 {
			t.Errorf("expected 0 new for shifted issue, got %d", len(newOnes))
		}
	})

	t.Run("new issue is not suppressed", func(t *testing.T) {
		suppressed, newOnes := Filter([]lint.Issue{newIssue}, f)
		if len(suppressed) != 0 {
			t.Errorf("expected 0 suppressed, got %d", len(suppressed))
		}
		if len(newOnes) != 1 {
			t.Errorf("expected 1 new, got %d", len(newOnes))
		}
	})

	t.Run("mixed batch partitioned correctly", func(t *testing.T) {
		all := []lint.Issue{known, alsoKnown, newIssue, unrelated}
		suppressed, newOnes := Filter(all, f)
		// known and alsoKnown share the same hash → both suppressed
		if len(suppressed) != 2 {
			t.Errorf("expected 2 suppressed, got %d", len(suppressed))
		}
		if len(newOnes) != 2 {
			t.Errorf("expected 2 new, got %d", len(newOnes))
		}
	})

	t.Run("empty baseline suppresses nothing", func(t *testing.T) {
		empty := &File{Version: fileVersion, Fingerprints: nil}
		suppressed, newOnes := Filter([]lint.Issue{known, newIssue}, empty)
		if len(suppressed) != 0 {
			t.Errorf("expected 0 suppressed against empty baseline, got %d", len(suppressed))
		}
		if len(newOnes) != 2 {
			t.Errorf("expected 2 new against empty baseline, got %d", len(newOnes))
		}
	})

	t.Run("empty issue list returns empty slices", func(t *testing.T) {
		suppressed, newOnes := Filter(nil, f)
		if suppressed != nil || newOnes != nil {
			t.Error("expected nil slices for empty input")
		}
	})
}

// ---------------------------------------------------------------------------
// buildFingerprints
// ---------------------------------------------------------------------------

func TestBuildFingerprints(t *testing.T) {
	t.Run("deduplicates identical issues", func(t *testing.T) {
		iss := issue("workflows/ci.yml", "GHA001", "unpinned action", 5)
		fps := buildFingerprints([]lint.Issue{iss, iss, iss})
		if len(fps) != 1 {
			t.Errorf("expected 1 unique fingerprint, got %d", len(fps))
		}
	})

	t.Run("shifted line deduplicates into one fingerprint", func(t *testing.T) {
		a := issue("workflows/ci.yml", "GHA001", "unpinned action", 5)
		b := issue("workflows/ci.yml", "GHA001", "unpinned action", 6)
		fps := buildFingerprints([]lint.Issue{a, b})
		if len(fps) != 1 {
			t.Errorf("expected 1 deduplicated fingerprint, got %d", len(fps))
		}
	})

	t.Run("result is sorted by file then rule", func(t *testing.T) {
		issues := []lint.Issue{
			issue("z.yml", "GHA002", "msg b", 1),
			issue("a.yml", "GHA001", "msg a", 1),
			issue("a.yml", "GHA002", "msg c", 1),
		}
		fps := buildFingerprints(issues)
		if len(fps) != 3 {
			t.Fatalf("expected 3 fingerprints, got %d", len(fps))
		}
		if fps[0].File != "a.yml" || fps[1].File != "a.yml" || fps[2].File != "z.yml" {
			t.Errorf("unexpected sort order: %v", fps)
		}
	})

	t.Run("empty input returns nil slice", func(t *testing.T) {
		fps := buildFingerprints(nil)
		if fps != nil {
			t.Errorf("expected nil for empty input, got %v", fps)
		}
	})
}

// ---------------------------------------------------------------------------
// severityLevel
// ---------------------------------------------------------------------------

func TestSeverityLevel(t *testing.T) {
	tests := []struct {
		sev  string
		want int
	}{
		{"error", 3},
		{"ERROR", 3},
		{"warning", 2},
		{"Warning", 2},
		{"info", 1},
		{"INFO", 1},
		{"none", 0},
		{"", 0},
		{"unknown", 0},
	}
	for _, tc := range tests {
		t.Run(tc.sev, func(t *testing.T) {
			got := severityLevel(tc.sev)
			if got != tc.want {
				t.Errorf("severityLevel(%q) = %d, want %d", tc.sev, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// JSON schema validation
// ---------------------------------------------------------------------------

func TestSaveProducesValidJSON(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "baseline.json")

	f := &File{
		Version:   fileVersion,
		Generated: time.Now().UTC(),
		Generator: generatorTag,
		Fingerprints: []Fingerprint{
			{File: "a.yml", Rule: "GHA001", Hash: "deadbeef"},
		},
	}
	if err := Save(path, f); err != nil {
		t.Fatalf("Save: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, data)
	}

	for _, key := range []string{"version", "generated", "generator", "fingerprints"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing key %q in JSON output", key)
		}
	}
}
