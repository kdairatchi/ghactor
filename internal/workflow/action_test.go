package workflow_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kdairatchi/ghactor/internal/workflow"
)

// dockerActionYAML is a minimal non-composite action used to verify that
// LoadActionFile parses the Using field and leaves Synth nil.
const dockerActionYAML = `
name: docker-action
runs:
  using: docker
  image: Dockerfile
`

// compositeActionYAML mirrors the injection fixture used by the lint tests.
const compositeActionYAML = `
name: my-composite
inputs:
  user_input:
    description: untrusted
    required: true
runs:
  using: composite
  steps:
    - shell: bash
      run: echo "hi ${{ inputs.user_input }}"
    - uses: actions/checkout@v4
`

func writeTemp(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("writeTemp %s: %v", p, err)
	}
	return p
}

func TestLoadActionFile_Composite(t *testing.T) {
	dir := t.TempDir()
	p := writeTemp(t, dir, "action.yml", compositeActionYAML)

	af, err := workflow.LoadActionFile(p)
	if err != nil {
		t.Fatalf("LoadActionFile: %v", err)
	}

	if af.Using != "composite" {
		t.Errorf("Using = %q, want %q", af.Using, "composite")
	}
	if af.Name != "my-composite" {
		t.Errorf("Name = %q, want %q", af.Name, "my-composite")
	}
	if af.Synth == nil {
		t.Fatal("Synth is nil for composite action")
	}

	job, ok := af.Synth.Jobs["composite"]
	if !ok {
		t.Fatal("synthetic workflow has no 'composite' job")
	}
	if len(job.Steps) != 2 {
		t.Errorf("step count = %d, want 2", len(job.Steps))
	}

	// First step should have a non-zero line number from the yaml.Node tree.
	if job.Steps[0].Line == 0 {
		t.Error("step[0].Line is 0 — attachCompositeStepPositions did not run")
	}
	if job.Steps[0].Run == "" {
		t.Error("step[0].Run is empty")
	}
}

func TestLoadActionFile_Docker(t *testing.T) {
	dir := t.TempDir()
	p := writeTemp(t, dir, "action.yml", dockerActionYAML)

	af, err := workflow.LoadActionFile(p)
	if err != nil {
		t.Fatalf("LoadActionFile: %v", err)
	}
	if af.Using != "docker" {
		t.Errorf("Using = %q, want %q", af.Using, "docker")
	}
	if af.Synth != nil {
		t.Error("Synth should be nil for docker action")
	}
}

func TestLoadActionFile_Inputs(t *testing.T) {
	dir := t.TempDir()
	p := writeTemp(t, dir, "action.yml", compositeActionYAML)

	af, err := workflow.LoadActionFile(p)
	if err != nil {
		t.Fatalf("LoadActionFile: %v", err)
	}
	if len(af.Inputs) != 1 || af.Inputs[0] != "user_input" {
		t.Errorf("Inputs = %v, want [user_input]", af.Inputs)
	}
}

func TestAsWorkflowFile(t *testing.T) {
	dir := t.TempDir()
	p := writeTemp(t, dir, "action.yml", compositeActionYAML)

	af, err := workflow.LoadActionFile(p)
	if err != nil {
		t.Fatalf("LoadActionFile: %v", err)
	}

	wf := af.AsWorkflowFile()
	if wf == nil {
		t.Fatal("AsWorkflowFile returned nil for composite action")
	}
	if wf.Path != p {
		t.Errorf("Path = %q, want %q", wf.Path, p)
	}
	if wf.WF == nil {
		t.Error("WF is nil")
	}
	if _, ok := wf.WF.Jobs["composite"]; !ok {
		t.Error("no 'composite' job in synthesized workflow")
	}
}

func TestAsWorkflowFile_NonComposite(t *testing.T) {
	dir := t.TempDir()
	p := writeTemp(t, dir, "action.yml", dockerActionYAML)

	af, err := workflow.LoadActionFile(p)
	if err != nil {
		t.Fatalf("LoadActionFile: %v", err)
	}
	if af.AsWorkflowFile() != nil {
		t.Error("AsWorkflowFile should return nil for docker action")
	}
}

func TestLoadActions_FindsCompositesOnly(t *testing.T) {
	// Directory layout:
	//   <tmp>/
	//     action.yml                       (composite) — should be found
	//     subdir/action.yml                (composite) — should be found
	//     docker-action/action.yml         (docker)    — found but Synth=nil
	//     .github/workflows/action.yml     (composite) — must be skipped
	dir := t.TempDir()

	writeTemp(t, dir, "action.yml", compositeActionYAML)

	subdir := filepath.Join(dir, "subdir")
	if err := os.Mkdir(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTemp(t, subdir, "action.yml", compositeActionYAML)

	dockerDir := filepath.Join(dir, "docker-action")
	if err := os.Mkdir(dockerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTemp(t, dockerDir, "action.yml", dockerActionYAML)

	wfDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTemp(t, wfDir, "action.yml", compositeActionYAML)

	actions, err := workflow.LoadActions(dir)
	if err != nil {
		t.Fatalf("LoadActions: %v", err)
	}

	// Exactly 3 files: root, subdir, docker-action — not the .github/workflows one.
	if len(actions) != 3 {
		t.Errorf("got %d actions, want 3", len(actions))
		for _, a := range actions {
			t.Logf("  %s (using=%s)", a.Path, a.Using)
		}
	}

	// None should be from .github/workflows.
	for _, a := range actions {
		if strings.Contains(filepath.ToSlash(a.Path), ".github/workflows") {
			t.Errorf("should have skipped workflow-dir file: %s", a.Path)
		}
	}

	// Count composites vs non-composites.
	var composites, others int
	for _, a := range actions {
		if a.Synth != nil {
			composites++
		} else {
			others++
		}
	}
	if composites != 2 {
		t.Errorf("composite count = %d, want 2", composites)
	}
	if others != 1 {
		t.Errorf("non-composite count = %d, want 1", others)
	}
}

func TestLoadActions_StepCount(t *testing.T) {
	dir := t.TempDir()
	writeTemp(t, dir, "action.yml", compositeActionYAML)

	actions, err := workflow.LoadActions(dir)
	if err != nil {
		t.Fatalf("LoadActions: %v", err)
	}
	if len(actions) != 1 {
		t.Fatalf("got %d actions, want 1", len(actions))
	}
	af := actions[0]
	if af.Synth == nil {
		t.Fatal("Synth is nil")
	}
	job := af.Synth.Jobs["composite"]
	if len(job.Steps) != 2 {
		t.Errorf("step count = %d, want 2", len(job.Steps))
	}
}
