package watch

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

// ---------------------------------------------------------------------------
// fakeSource — injectable event source for unit tests
// ---------------------------------------------------------------------------

type fakeSource struct {
	events chan fsnotify.Event
	errors chan error
	added  []string
	mu     sync.Mutex
	closed bool
}

func newFakeSource() *fakeSource {
	return &fakeSource{
		events: make(chan fsnotify.Event, 64),
		errors: make(chan error, 4),
	}
}

func (f *fakeSource) Events() <-chan fsnotify.Event { return f.events }
func (f *fakeSource) Errors() <-chan error          { return f.errors }
func (f *fakeSource) Add(path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.added = append(f.added, path)
	return nil
}
func (f *fakeSource) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed = true
		close(f.events)
		close(f.errors)
	}
	return nil
}

// send pushes an event without blocking (buffer is large).
func (f *fakeSource) send(op fsnotify.Op, name string) {
	f.events <- fsnotify.Event{Op: op, Name: name}
}

// ---------------------------------------------------------------------------
// lintCounter — intercepts runLoop's lint calls so we can count invocations
// without touching the filesystem.
//
// Because runLoop calls lint.RunWithOptions internally, we instead exercise
// the debounce/filter logic through handleEvent + armTimer, and count armTimer
// calls as a proxy for "lint would run". For the debounce test we need to
// observe the actual timer firings, so we wrap the whole loop around a real
// temp dir that has at least one YAML file.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// makeWorkflowDir creates a temp dir with a minimal valid workflow YAML.
func makeWorkflowDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	wfDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Write a minimal but valid workflow so lint.RunWithOptions doesn't error.
	const yaml = `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`
	if err := os.WriteFile(filepath.Join(wfDir, "ci.yml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	return wfDir
}

// ---------------------------------------------------------------------------
// Test 1: Debounce — 5 events within debounce window → lint fires exactly once
// ---------------------------------------------------------------------------

func TestDebounce(t *testing.T) {
	dir := makeWorkflowDir(t)

	var lintCount atomic.Int32

	// We'll observe lint calls by counting timerFired channel drains.
	// Instead of intercepting lint, we count how many times the debounce
	// fires by running the loop with a short debounce and a controlled source.

	src := newFakeSource()
	var buf bytes.Buffer

	opts := Options{
		Dir:      dir,
		Debounce: 150 * time.Millisecond,
		Out:      &buf,
	}

	done := make(chan error, 1)
	go func() {
		done <- runLoop(opts, dir, src)
	}()

	// Give the goroutine time to start and print the initial pass header.
	time.Sleep(30 * time.Millisecond)

	// Fire 5 events in rapid succession (well within debounce window).
	for range 5 {
		src.send(fsnotify.Write, filepath.Join(dir, "ci.yml"))
	}

	// Wait for the debounce to expire and lint to run.
	time.Sleep(400 * time.Millisecond)

	// Now shut down.
	src.events <- fsnotify.Event{} // zero event triggers nothing; close instead
	// Close to terminate loop.
	src.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runLoop did not terminate in time")
	}

	output := buf.String()
	// Count occurrences of the "changed" marker — each debounce fire adds one.
	changeCount := strings.Count(output, "changed")
	_ = lintCount
	if changeCount != 1 {
		t.Errorf("expected 1 debounced lint run, got %d; output:\n%s", changeCount, output)
	}
}

// ---------------------------------------------------------------------------
// Test 2: YAML filter — non-YAML events do NOT trigger lint
// ---------------------------------------------------------------------------

func TestYAMLFilter(t *testing.T) {
	dir := makeWorkflowDir(t)
	src := newFakeSource()
	var buf bytes.Buffer

	opts := Options{
		Dir:      dir,
		Debounce: 100 * time.Millisecond,
		Out:      &buf,
	}

	done := make(chan error, 1)
	go func() {
		done <- runLoop(opts, dir, src)
	}()

	time.Sleep(30 * time.Millisecond)

	// Send events for non-YAML files.
	src.send(fsnotify.Write, filepath.Join(dir, "README.md"))
	src.send(fsnotify.Write, filepath.Join(dir, "script.sh"))
	src.send(fsnotify.Create, filepath.Join(dir, "notes.txt"))

	// Wait longer than debounce to ensure nothing fires.
	time.Sleep(300 * time.Millisecond)

	src.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runLoop did not terminate in time")
	}

	output := buf.String()
	// The initial pass header is printed; subsequent "changed" lines should NOT appear.
	changeCount := strings.Count(output, "changed")
	if changeCount != 0 {
		t.Errorf("expected 0 lint runs for non-YAML events, got %d; output:\n%s", changeCount, output)
	}
}

// ---------------------------------------------------------------------------
// Test 3: Atomic replace — RENAME→CREATE re-arms watcher and fires lint once
// ---------------------------------------------------------------------------

func TestAtomicReplace(t *testing.T) {
	dir := makeWorkflowDir(t)
	src := newFakeSource()
	var buf bytes.Buffer

	opts := Options{
		Dir:      dir,
		Debounce: 150 * time.Millisecond,
		Out:      &buf,
	}

	done := make(chan error, 1)
	go func() {
		done <- runLoop(opts, dir, src)
	}()

	time.Sleep(30 * time.Millisecond)

	yamlPath := filepath.Join(dir, "ci.yml")

	// Simulate vim's write: RENAME on old inode, then CREATE on new inode.
	src.send(fsnotify.Rename, yamlPath)
	time.Sleep(5 * time.Millisecond)
	src.send(fsnotify.Create, yamlPath)

	// Wait for debounce + lint.
	time.Sleep(400 * time.Millisecond)

	src.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runLoop did not terminate in time")
	}

	output := buf.String()

	// Exactly one "changed" line from the CREATE event.
	changeCount := strings.Count(output, "changed")
	if changeCount != 1 {
		t.Errorf("expected 1 lint run after atomic replace, got %d; output:\n%s", changeCount, output)
	}

	// The fake source should have received an Add call for the new inode.
	src.mu.Lock()
	addedPaths := append([]string(nil), src.added...)
	src.mu.Unlock()

	reAdded := false
	for _, p := range addedPaths {
		if p == yamlPath {
			reAdded = true
			break
		}
	}
	if !reAdded {
		t.Errorf("expected watcher to be re-armed for %s after CREATE; added paths: %v", yamlPath, addedPaths)
	}
}

// ---------------------------------------------------------------------------
// Test 4: Initial pass — lint is called once before any events arrive
// ---------------------------------------------------------------------------

func TestInitialPass(t *testing.T) {
	dir := makeWorkflowDir(t)
	src := newFakeSource()
	var buf bytes.Buffer

	opts := Options{
		Dir:      dir,
		Debounce: 250 * time.Millisecond,
		Out:      &buf,
	}

	done := make(chan error, 1)
	go func() {
		done <- runLoop(opts, dir, src)
	}()

	// Give just enough time for the initial pass to print, but not long enough
	// for any spurious event to fire.
	time.Sleep(200 * time.Millisecond)

	src.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runLoop did not terminate in time")
	}

	output := buf.String()

	// The initial pass should produce either "no issues found" or issue lines.
	// The key signal is that the "watching" header appeared before any event.
	if !strings.Contains(output, "watching") {
		t.Errorf("expected initial 'watching' header; output:\n%s", output)
	}
	// And some lint result (no issues OR issue lines) — presence of checkmark
	// or ERROR/WARN/INFO indicates a pass ran.
	hasResult := strings.Contains(output, "no issues found") ||
		strings.Contains(output, "ERROR") ||
		strings.Contains(output, "WARN") ||
		strings.Contains(output, "INFO")
	if !hasResult {
		t.Errorf("expected initial lint result in output; output:\n%s", output)
	}
}

// ---------------------------------------------------------------------------
// Test 5: Integration — write file, check output, send SIGINT, assert clean exit
// ---------------------------------------------------------------------------

func TestIntegration_WriteAndSignal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SIGINT not supported on windows")
	}

	wfDir := makeWorkflowDir(t)

	var buf bytes.Buffer
	opts := Options{
		Dir:      wfDir,
		Debounce: 80 * time.Millisecond,
		Out:      &buf,
	}

	// Use a real fsnotify watcher for this integration test.
	src, err := newFSNotifySource(wfDir)
	if err != nil {
		t.Fatalf("newFSNotifySource: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- runLoop(opts, wfDir, src)
	}()

	// Wait for initial pass.
	time.Sleep(150 * time.Millisecond)

	// Write a workflow with a known issue (untrusted context in run step — GHA004).
	const badWorkflow = `name: Bad
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - name: echo title
        run: echo "${{ github.event.issue.title }}"
`
	yamlPath := filepath.Join(wfDir, "ci.yml")
	if err := os.WriteFile(yamlPath, []byte(badWorkflow), 0o644); err != nil {
		t.Fatal(err)
	}

	// Wait for debounce + lint.
	time.Sleep(400 * time.Millisecond)

	// Send SIGINT to self.
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGINT); err != nil {
		t.Fatalf("kill: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("runLoop returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runLoop did not terminate within 2s after SIGINT")
	}

	output := buf.String()

	// Should contain at least one "changed" entry from the file write.
	if !strings.Contains(output, "changed") {
		t.Errorf("expected 'changed' in output after file write; output:\n%s", output)
	}
	// Should contain "stopped" from the SIGINT handler.
	if !strings.Contains(output, "stopped") {
		t.Errorf("expected 'stopped' in output after SIGINT; output:\n%s", output)
	}
}

// ---------------------------------------------------------------------------
// Cmd smoke test — verify flag registration does not panic
// ---------------------------------------------------------------------------

func TestCmdFlags(t *testing.T) {
	cmd := Cmd()
	if cmd == nil {
		t.Fatal("Cmd() returned nil")
	}
	for _, name := range []string{"dir", "disable", "only-ghactor", "debounce", "clear"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("flag --%s not registered", name)
		}
	}
}

// ---------------------------------------------------------------------------
// isYAML unit test
// ---------------------------------------------------------------------------

func TestIsYAML(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"ci.yml", true},
		{"ci.yaml", true},
		{"CI.YML", true},
		{"README.md", false},
		{"script.sh", false},
		{"noext", false},
		{".yml", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isYAML(tc.name)
			if got != tc.want {
				t.Errorf("isYAML(%q) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

// Ensure the package compiles and fmt is satisfied.
var _ = fmt.Sprintf
