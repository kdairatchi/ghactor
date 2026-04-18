package lint

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kdairatchi/ghactor/internal/config"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// writeWorkflowDir writes a minimal .github/workflows directory in a temp dir
// with a single workflow file and returns the dir and the workflow path.
func writeWorkflowDir(t *testing.T, workflowName, workflowYAML string) (dir string, wfPath string) {
	t.Helper()
	root := t.TempDir()
	wfDir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	wfPath = filepath.Join(wfDir, workflowName)
	if err := os.WriteFile(wfPath, []byte(workflowYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	return wfDir, wfPath
}

// writeConfig writes a .ghactor.yml in root and loads it.
func writeConfig(t *testing.T, root, content string) *config.File {
	t.Helper()
	p := filepath.Join(root, ".ghactor.yml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := config.Load(p)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return f
}

// minimal workflow that reliably fires GHA005 (missing-timeout) and GHA002 (missing-permissions).
const wfMissingTimeout = `name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4
`

// ---------------------------------------------------------------------------
// Integration: severity override changes issue severity
// ---------------------------------------------------------------------------

func TestSeverityOverrideDowngrade(t *testing.T) {
	// GHA005 default is SevInfo.  Override to warning should produce SevWarning.
	wfDir, _ := writeWorkflowDir(t, "ci.yml", wfMissingTimeout)
	root := filepath.Dir(filepath.Dir(wfDir)) // two levels up from .github/workflows

	cfg := writeConfig(t, root, `
version: 1
rules:
  GHA005:
    severity: warning
`)

	issues, err := RunWithOptions(Options{
		Dir:              wfDir,
		IgnoreActionlint: true,
		Config:           cfg,
	})
	if err != nil {
		t.Fatalf("RunWithOptions: %v", err)
	}

	found := false
	for _, iss := range issues {
		if iss.Kind == "GHA005" {
			found = true
			if iss.Severity != SevWarning {
				t.Errorf("GHA005: expected SevWarning, got %q", iss.Severity)
			}
		}
	}
	if !found {
		t.Error("expected GHA005 to fire, but no issue found")
	}
}

func TestSeverityOverrideUpgrade(t *testing.T) {
	// GHA005 default is SevInfo. Override to error should produce SevError.
	wfDir, _ := writeWorkflowDir(t, "ci.yml", wfMissingTimeout)
	root := filepath.Dir(filepath.Dir(wfDir))

	cfg := writeConfig(t, root, `
version: 1
rules:
  GHA005:
    severity: error
`)

	issues, err := RunWithOptions(Options{
		Dir:              wfDir,
		IgnoreActionlint: true,
		Config:           cfg,
	})
	if err != nil {
		t.Fatalf("RunWithOptions: %v", err)
	}

	found := false
	for _, iss := range issues {
		if iss.Kind == "GHA005" {
			found = true
			if iss.Severity != SevError {
				t.Errorf("GHA005: expected SevError, got %q", iss.Severity)
			}
		}
	}
	if !found {
		t.Error("expected GHA005 to fire, but no issue found")
	}
}

// ---------------------------------------------------------------------------
// Integration: severity "off" suppresses the issue entirely
// ---------------------------------------------------------------------------

func TestSeverityOffSuppressesIssue(t *testing.T) {
	wfDir, _ := writeWorkflowDir(t, "ci.yml", wfMissingTimeout)
	root := filepath.Dir(filepath.Dir(wfDir))

	cfg := writeConfig(t, root, `
version: 1
rules:
  GHA005:
    severity: off
`)

	issues, err := RunWithOptions(Options{
		Dir:              wfDir,
		IgnoreActionlint: true,
		Config:           cfg,
	})
	if err != nil {
		t.Fatalf("RunWithOptions: %v", err)
	}

	for _, iss := range issues {
		if iss.Kind == "GHA005" {
			t.Errorf("GHA005 should be suppressed by severity:off, but got issue: %+v", iss)
		}
	}
}

func TestSeverityDisabledAliasOff(t *testing.T) {
	// "disabled" is an alias for "off".
	wfDir, _ := writeWorkflowDir(t, "ci.yml", wfMissingTimeout)
	root := filepath.Dir(filepath.Dir(wfDir))

	cfg := writeConfig(t, root, `
version: 1
rules:
  GHA005:
    severity: disabled
`)

	issues, err := RunWithOptions(Options{
		Dir:              wfDir,
		IgnoreActionlint: true,
		Config:           cfg,
	})
	if err != nil {
		t.Fatalf("RunWithOptions: %v", err)
	}

	for _, iss := range issues {
		if iss.Kind == "GHA005" {
			t.Errorf("GHA005 should be suppressed by severity:disabled, got issue: %+v", iss)
		}
	}
}

// ---------------------------------------------------------------------------
// Integration: per-path override narrows suppression to one file
// ---------------------------------------------------------------------------

func TestPerPathOverrideNarrowsToOneFile(t *testing.T) {
	// Write two workflow files: ci.yml and release.yml, both fire GHA005.
	root := t.TempDir()
	wfDir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"ci.yml", "release.yml"} {
		if err := os.WriteFile(filepath.Join(wfDir, name), []byte(wfMissingTimeout), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Override suppresses GHA005 only for release.yml — use the path relative
	// to the config root, which is the repo root (parent of .github/).
	cfg := writeConfig(t, root, `
version: 1
overrides:
  - paths: [".github/workflows/release.yml"]
    rules:
      GHA005:
        severity: off
`)

	issues, err := RunWithOptions(Options{
		Dir:              wfDir,
		IgnoreActionlint: true,
		Config:           cfg,
	})
	if err != nil {
		t.Fatalf("RunWithOptions: %v", err)
	}

	ciHasGHA005 := false
	releaseHasGHA005 := false
	for _, iss := range issues {
		if iss.Kind != "GHA005" {
			continue
		}
		base := filepath.Base(iss.File)
		switch base {
		case "ci.yml":
			ciHasGHA005 = true
		case "release.yml":
			releaseHasGHA005 = true
		}
	}

	if !ciHasGHA005 {
		t.Error("ci.yml: expected GHA005 to fire (no override), but it did not")
	}
	if releaseHasGHA005 {
		t.Error("release.yml: expected GHA005 to be suppressed by per-path override, but it fired")
	}
}

// ---------------------------------------------------------------------------
// Integration: no config short-circuits to default behavior (no panic)
// ---------------------------------------------------------------------------

func TestNoConfigUsesDefaults(t *testing.T) {
	wfDir, _ := writeWorkflowDir(t, "ci.yml", wfMissingTimeout)

	issues, err := RunWithOptions(Options{
		Dir:              wfDir,
		IgnoreActionlint: true,
		Config:           nil,
	})
	if err != nil {
		t.Fatalf("RunWithOptions: %v", err)
	}

	found := false
	for _, iss := range issues {
		if iss.Kind == "GHA005" {
			found = true
			if iss.Severity != SevInfo {
				t.Errorf("GHA005 default severity: expected SevInfo, got %q", iss.Severity)
			}
		}
	}
	if !found {
		t.Error("expected GHA005 to fire with default severity")
	}
}
