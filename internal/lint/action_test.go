package lint

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kdairatchi/ghactor/internal/workflow"
)

// ---- helpers ----------------------------------------------------------------

// loadAction parses a composite action fixture by path. Fails the test on error.
func loadAction(t *testing.T, path string) *workflow.ActionFile {
	t.Helper()
	af, err := workflow.LoadActionFile(path)
	if err != nil {
		t.Fatalf("LoadActionFile(%s): %v", path, err)
	}
	return af
}

// lintActionFile runs the applicable rule subset against a single ActionFile
// and returns all Issues. It mirrors what LintActions does per file.
func lintActionFile(t *testing.T, af *workflow.ActionFile) []Issue {
	t.Helper()
	if af.Synth == nil {
		return nil
	}
	wf := af.AsWorkflowFile()
	if wf == nil {
		return nil
	}
	var out []Issue
	for _, r := range Rules {
		if !applicableActionRuleIDs[r.ID] {
			continue
		}
		out = append(out, r.Check(wf)...)
	}
	return out
}

// ---- fixture-level tests ----------------------------------------------------

func TestActionFixture_InjectionHasGHA004(t *testing.T) {
	af := loadAction(t, "testdata/action_injection.yml")
	issues := lintActionFile(t, af)

	found := false
	for _, iss := range issues {
		if iss.Kind == "GHA004" {
			found = true
			t.Logf("GHA004 at line=%d col=%d: %s", iss.Line, iss.Col, iss.Message)
		}
	}
	if !found {
		t.Errorf("expected GHA004 in action_injection.yml; got: %+v", issues)
	}
}

func TestActionFixture_InjectionHasGHA001(t *testing.T) {
	af := loadAction(t, "testdata/action_injection.yml")
	issues := lintActionFile(t, af)

	found := false
	for _, iss := range issues {
		if iss.Kind == "GHA001" {
			found = true
			t.Logf("GHA001 at line=%d col=%d: %s", iss.Line, iss.Col, iss.Message)
		}
	}
	if !found {
		t.Errorf("expected GHA001 (unpinned @v4) in action_injection.yml; got: %+v", issues)
	}
}

func TestActionFixture_GoodIsClean(t *testing.T) {
	af := loadAction(t, "testdata/action_good.yml")
	issues := lintActionFile(t, af)
	if len(issues) != 0 {
		t.Errorf("expected no issues in action_good.yml, got: %+v", issues)
	}
}

// TestActionFixture_GHA004_Position verifies that the GHA004 finding points at
// the step node line (line 10 in action_injection.yml — the "- shell: bash" item).
func TestActionFixture_GHA004_Position(t *testing.T) {
	af := loadAction(t, "testdata/action_injection.yml")
	issues := lintActionFile(t, af)

	for _, iss := range issues {
		if iss.Kind != "GHA004" {
			continue
		}
		// The composite step node "- shell: bash" starts at line 10 in the fixture.
		if iss.Line != 10 {
			t.Errorf("GHA004 line = %d, want 10 (the composite step node line)", iss.Line)
		}
		return
	}
	t.Error("GHA004 not found in action_injection.yml")
}

func TestActionFixture_NonApplicableRulesAbsent(t *testing.T) {
	// Workflow-level rules that must never appear for composite actions.
	excluded := map[string]bool{
		"GHA002": true,
		"GHA003": true,
		"GHA005": true,
		"GHA009": true,
		"GHA011": true,
		"GHA015": true,
		"GHA016": true,
		"GHA017": true,
		"GHA019": true,
	}

	for _, path := range []string{"testdata/action_injection.yml", "testdata/action_good.yml"} {
		af := loadAction(t, path)
		issues := lintActionFile(t, af)
		for _, iss := range issues {
			if excluded[iss.Kind] {
				t.Errorf("%s: rule %s should not fire on composite actions, got: %+v",
					filepath.Base(path), iss.Kind, iss)
			}
		}
	}
}

// ---- LintActions integration tests (temp dirs with properly-named files) ---

// writeTempAction writes content as action.yml inside a freshly created
// subdirectory of dir and returns the directory path.
func writeTempAction(t *testing.T, parentDir, subName, content string) string {
	t.Helper()
	sub := filepath.Join(parentDir, subName)
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("MkdirAll %s: %v", sub, err)
	}
	p := filepath.Join(sub, "action.yml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile %s: %v", p, err)
	}
	return sub
}

const injectionActionContent = `name: bad-action
description: demonstrates GHA004 in a composite action
inputs:
  user_input:
    description: untrusted input
    required: true
runs:
  using: composite
  steps:
    - shell: bash
      run: echo "hi ${{ inputs.user_input }}"
    - uses: actions/checkout@v4
`

const goodActionContent = `name: good-action
description: safe composite action
inputs:
  user_input:
    description: untrusted input
    required: true
runs:
  using: composite
  steps:
    - shell: bash
      env:
        USER_INPUT: ${{ inputs.user_input }}
      run: echo "hi $USER_INPUT"
    - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4
`

func TestLintActions_InjectionFindsGHA004(t *testing.T) {
	root := t.TempDir()
	writeTempAction(t, root, "bad", injectionActionContent)

	issues, err := LintActions(root, nil)
	if err != nil {
		t.Fatalf("LintActions: %v", err)
	}
	found := false
	for _, iss := range issues {
		if iss.Kind == "GHA004" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected GHA004; got: %+v", issues)
	}
}

func TestLintActions_GoodActionIsClean(t *testing.T) {
	root := t.TempDir()
	writeTempAction(t, root, "good", goodActionContent)

	issues, err := LintActions(root, nil)
	if err != nil {
		t.Fatalf("LintActions: %v", err)
	}
	if len(issues) != 0 {
		t.Errorf("expected no issues; got: %+v", issues)
	}
}

func TestLintActions_DisabledRule(t *testing.T) {
	root := t.TempDir()
	writeTempAction(t, root, "bad", injectionActionContent)

	issues, err := LintActions(root, []string{"GHA004"})
	if err != nil {
		t.Fatalf("LintActions: %v", err)
	}
	for _, iss := range issues {
		if iss.Kind == "GHA004" {
			t.Errorf("GHA004 should be suppressed when disabled, got: %+v", iss)
		}
	}
}

func TestLintActions_EmptyDir(t *testing.T) {
	issues, err := LintActions(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("LintActions on empty dir: %v", err)
	}
	if len(issues) != 0 {
		t.Errorf("expected no issues, got: %+v", issues)
	}
}

func TestLintActions_SkipsWorkflowsDir(t *testing.T) {
	root := t.TempDir()
	// Place an action.yml under .github/workflows/ — must be skipped.
	wfDir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wfDir, "action.yml"), []byte(injectionActionContent), 0o644); err != nil {
		t.Fatal(err)
	}
	// Also place a legitimate composite action at the root level.
	writeTempAction(t, root, "ok-action", goodActionContent)

	actions, err := workflow.LoadActions(root)
	if err != nil {
		t.Fatalf("LoadActions: %v", err)
	}
	for _, a := range actions {
		if a.Path != "" {
			norm := filepath.ToSlash(a.Path)
			if containsSegment(norm, ".github/workflows") {
				t.Errorf("should have skipped .github/workflows path: %s", a.Path)
			}
		}
	}
}

func TestLintActions_SortOrder(t *testing.T) {
	root := t.TempDir()
	writeTempAction(t, root, "a-action", injectionActionContent)
	writeTempAction(t, root, "b-action", injectionActionContent)

	issues, err := LintActions(root, nil)
	if err != nil {
		t.Fatalf("LintActions: %v", err)
	}
	for i := 1; i < len(issues); i++ {
		a, b := issues[i-1], issues[i]
		if a.File > b.File {
			t.Errorf("sort violation at [%d]: %q > %q", i, a.File, b.File)
		}
		if a.File == b.File && a.Line > b.Line {
			t.Errorf("sort violation at [%d]: line %d > %d in %s", i, a.Line, b.Line, a.File)
		}
		if a.File == b.File && a.Line == b.Line && a.Col > b.Col {
			t.Errorf("sort violation at [%d]: col %d > %d in %s", i, a.Col, b.Col, a.File)
		}
	}
}

// containsSegment reports whether the forward-slash path contains the given
// contiguous segment, handling prefix/suffix boundaries.
func containsSegment(path, seg string) bool {
	return len(path) >= len(seg) &&
		(path == seg ||
			len(path) > len(seg) && (path[len(path)-len(seg)-1] == '/' && path[len(path)-len(seg):] == seg ||
				filepath.ToSlash(path)[:len(seg)+1] == seg+"/") ||
			containsSubstring(path, "/"+seg+"/") ||
			containsSubstring(path, "/"+seg))
}

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && func() bool {
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}()
}
