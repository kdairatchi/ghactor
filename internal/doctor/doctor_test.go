package doctor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kdairatchi/ghactor/internal/lint"
)

// minimalWorkflow is a valid, pinned, permissioned workflow used in tests.
const minimalWorkflow = `name: ci
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4
`

func setupWorkflowDir(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	wfDir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(wfDir, "ci.yml"), []byte(minimalWorkflow), 0o644); err != nil {
		t.Fatalf("write workflow: %v", err)
	}
	return wfDir
}

func setupWorkflowDirWithConfig(t *testing.T) (wfDir string, root string) {
	t.Helper()
	root = t.TempDir()
	wfDir = filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(wfDir, "ci.yml"), []byte(minimalWorkflow), 0o644); err != nil {
		t.Fatalf("write workflow: %v", err)
	}
	cfgContent := "version: 1\n"
	if err := os.WriteFile(filepath.Join(root, ".ghactor.yml"), []byte(cfgContent), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return wfDir, root
}

func TestScanJSONShape(t *testing.T) {
	wfDir := setupWorkflowDir(t)
	r, err := Scan(wfDir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	// Existing keys that consumers depend on must still be present.
	for _, key := range []string{"dir", "workflows", "jobs", "steps", "issues", "by_rule", "by_severity"} {
		if _, ok := m[key]; !ok {
			t.Errorf("missing key %q in JSON output", key)
		}
	}
	// score must be present (injected via MarshalJSON).
	if _, ok := m["score"]; !ok {
		t.Errorf("missing key %q in JSON output", "score")
	}
	// config_path must be present.
	if _, ok := m["config_path"]; !ok {
		t.Errorf("missing key %q in JSON output", "config_path")
	}
	// health_score must NOT appear (dead field removed).
	if _, ok := m["health_score"]; ok {
		t.Errorf("dead field health_score must not appear in JSON output")
	}
}

func TestScanConfigPathAbsent(t *testing.T) {
	wfDir := setupWorkflowDir(t)
	r, err := Scan(wfDir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if r.ConfigPath != "" {
		t.Errorf("ConfigPath = %q, want empty string when no .ghactor.yml exists", r.ConfigPath)
	}
	b, _ := json.Marshal(r)
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if v, ok := m["config_path"]; !ok || v != "" {
		t.Errorf("JSON config_path = %v, want empty string", v)
	}
}

func TestScanConfigPathPresent(t *testing.T) {
	wfDir, root := setupWorkflowDirWithConfig(t)
	r, err := Scan(wfDir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	expectedPath := filepath.Join(root, ".ghactor.yml")
	if r.ConfigPath != expectedPath {
		t.Errorf("ConfigPath = %q, want %q", r.ConfigPath, expectedPath)
	}
	b, _ := json.Marshal(r)
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if v, ok := m["config_path"]; !ok || v != expectedPath {
		t.Errorf("JSON config_path = %v, want %q", v, expectedPath)
	}
}

func TestScoreIsConsistentWithJSON(t *testing.T) {
	wfDir := setupWorkflowDir(t)
	r, err := Scan(wfDir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	s := r.Score()
	b, _ := json.Marshal(r)
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	jsonScore := int(m["score"].(float64))
	if jsonScore != s {
		t.Errorf("JSON score %d != Score() %d — single source of truth violated", jsonScore, s)
	}
}

func TestConfigPathInTextOutput(t *testing.T) {
	// Verify ConfigPath is populated so the text renderer can emit "config:" line.
	wfDir, root := setupWorkflowDirWithConfig(t)
	r, err := Scan(wfDir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	expectedPath := filepath.Join(root, ".ghactor.yml")
	if !strings.HasSuffix(r.ConfigPath, ".ghactor.yml") {
		t.Errorf("ConfigPath = %q, expected suffix .ghactor.yml (full expected: %q)", r.ConfigPath, expectedPath)
	}
}

func TestScoreEdgeCases(t *testing.T) {
	t.Run("zero_steps_returns_100", func(t *testing.T) {
		r := &Report{
			Steps:      0,
			BySeverity: map[lint.Severity]int{},
		}
		if got := r.Score(); got != 100 {
			t.Errorf("Score() = %d, want 100", got)
		}
	})

	t.Run("floor_at_zero", func(t *testing.T) {
		r := &Report{
			Steps: 1,
			BySeverity: map[lint.Severity]int{
				lint.SevError: 20,
			},
		}
		if got := r.Score(); got != 0 {
			t.Errorf("Score() = %d, want 0", got)
		}
	})

	t.Run("mixed_severity_penalty", func(t *testing.T) {
		r := &Report{
			Steps: 1,
			BySeverity: map[lint.Severity]int{
				lint.SevError:   1, // -10
				lint.SevWarning: 2, // -6
				lint.SevInfo:    3, // -3
			},
		}
		want := 100 - 10 - 6 - 3 // = 81
		if got := r.Score(); got != want {
			t.Errorf("Score() = %d, want %d", got, want)
		}
	})
}
