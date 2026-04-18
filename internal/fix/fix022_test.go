package fix

import (
	"strings"
	"testing"
)

func TestAddShellToSteps_InjectsShell(t *testing.T) {
	// Step with run: and no shell: gets shell: bash injected.
	src := `name: test
on: [push]
jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
    steps:
      - name: checkout
        uses: actions/checkout@v4
      - name: build
        run: go build ./...
      - name: already-shelled
        run: echo ok
        shell: bash
`
	out, changes := addShellToSteps("w.yml", []byte(src), "bash")
	if len(changes) != 1 {
		t.Fatalf("expected 1 change (build step), got %d: %v", len(changes), changes)
	}
	if changes[0].Rule != "GHA022" {
		t.Errorf("want Rule GHA022, got %q", changes[0].Rule)
	}
	s := string(out)

	// shell: bash should appear before run: in the build step.
	shellIdx := strings.Index(s, "        shell: bash\n        run: go build")
	if shellIdx < 0 {
		t.Errorf("shell: bash not inserted before run: in build step:\n%s", s)
	}

	// uses: step should not have shell: injected.
	if strings.Count(s, "shell: bash") != 2 { // one injected + one original
		t.Errorf("expected exactly 2 occurrences of 'shell: bash', got %d:\n%s",
			strings.Count(s, "shell: bash"), s)
	}
}

func TestAddShellToSteps_WFDefaultShell_NoOp(t *testing.T) {
	// Workflow-level defaults.run.shell is set: nothing is injected.
	src := `name: test
on: [push]
defaults:
  run:
    shell: bash
jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
    steps:
      - name: build
        run: go build ./...
`
	out, changes := addShellToSteps("w.yml", []byte(src), "bash")
	if len(changes) != 0 {
		t.Errorf("expected 0 changes when wf default shell is set, got %d", len(changes))
	}
	if string(out) != src {
		t.Error("source should be unchanged")
	}
}

func TestAddShellToSteps_JobDefaultShell_NoOp(t *testing.T) {
	// Job-level defaults.run.shell is set: nothing is injected for that job.
	src := `name: test
on: [push]
jobs:
  test:
    runs-on: ${{ matrix.os }}
    defaults:
      run:
        shell: bash
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
    steps:
      - name: build
        run: go build ./...
`
	out, changes := addShellToSteps("w.yml", []byte(src), "bash")
	if len(changes) != 0 {
		t.Errorf("expected 0 changes when job default shell is set, got %d", len(changes))
	}
	if string(out) != src {
		t.Error("source should be unchanged")
	}
}

func TestAddShellToSteps_UsesStepNotTouched(t *testing.T) {
	src := `name: test
on: [push]
jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
    steps:
      - uses: actions/checkout@v4
`
	out, changes := addShellToSteps("w.yml", []byte(src), "bash")
	if len(changes) != 0 {
		t.Errorf("expected 0 changes for uses-only steps, got %d", len(changes))
	}
	if string(out) != src {
		t.Error("source should be unchanged")
	}
}

func TestAddShellToSteps_CustomShell(t *testing.T) {
	src := `name: test
on: [push]
jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
    steps:
      - name: build
        run: go build ./...
`
	out, changes := addShellToSteps("w.yml", []byte(src), "pwsh")
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
	if !strings.Contains(string(out), "shell: pwsh") {
		t.Errorf("expected shell: pwsh in output:\n%s", string(out))
	}
}

func TestAddShellToSteps_Idempotent(t *testing.T) {
	src := `name: test
on: [push]
jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
    steps:
      - name: build
        run: go build ./...
`
	out1, changes1 := addShellToSteps("w.yml", []byte(src), "bash")
	if len(changes1) == 0 {
		t.Fatal("first pass should produce changes")
	}
	_, changes2 := addShellToSteps("w.yml", out1, "bash")
	if len(changes2) != 0 {
		t.Errorf("second pass should produce no changes (idempotent), got %d", len(changes2))
	}
}
