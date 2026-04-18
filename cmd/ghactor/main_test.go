package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// binaryPath holds the path to the compiled ghactor binary built in TestMain.
var binaryPath string

// TestMain compiles the binary once into a temp directory and runs all tests
// against that binary, ensuring integration tests exercise the real CLI.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "ghactor-integ-*")
	if err != nil {
		panic("failed to create temp dir: " + err.Error())
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "ghactor")
	cmd := exec.Command("go", "build", "-o", binaryPath, ".")
	cmd.Dir = filepath.Join(mustWD(), "")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		panic("failed to build ghactor: " + err.Error())
	}

	os.Exit(m.Run())
}

func mustWD() string {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return wd
}

// run executes the ghactor binary with the provided arguments and returns
// the combined stdout, stderr, and exit code.
func run(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(binaryPath, args...)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	stdout = outBuf.String()
	stderr = errBuf.String()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("exec error: %v", err)
		}
	}
	return stdout, stderr, code
}

// fixtureDir returns the absolute path to a named testdata fixture.
func fixtureDir(name string) string {
	wd := mustWD()
	return filepath.Join(wd, "testdata", name, ".github", "workflows")
}

func TestLintClean(t *testing.T) {
	dir := fixtureDir("clean")
	stdout, _, code := run(t, "lint", "--dir", dir, "--only-ghactor", "--fail-on", "error")
	if code != 0 {
		t.Fatalf("expected exit 0 on clean fixture, got %d\nstdout: %s", code, stdout)
	}
}

func TestLintBadHasViolations(t *testing.T) {
	dir := fixtureDir("bad")
	stdout, _, code := run(t, "lint", "--dir", dir, "--only-ghactor", "--fail-on", "warning")
	if code == 0 {
		t.Fatalf("expected non-zero exit on bad fixture, got 0\nstdout: %s", stdout)
	}
	if !strings.Contains(stdout, "GHA001") {
		t.Errorf("expected stdout to contain GHA001 (unpinned-action)\nstdout: %s", stdout)
	}
}

func TestLintJSONOutput(t *testing.T) {
	dir := fixtureDir("bad")
	stdout, _, _ := run(t, "lint", "--dir", dir, "--only-ghactor", "--json")
	if !json.Valid([]byte(stdout)) {
		t.Fatalf("--json output is not valid JSON:\n%s", stdout)
	}
	// Must decode to a non-nil slice (bad fixture has violations).
	var issues []map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &issues); err != nil {
		t.Fatalf("unmarshal JSON: %v\nstdout: %s", err, stdout)
	}
	if len(issues) == 0 {
		t.Errorf("expected at least one issue in JSON output, got none")
	}
}

func TestFixDryRun(t *testing.T) {
	// Copy bad fixture to a temp dir so we don't mutate testdata.
	src := filepath.Join(mustWD(), "testdata", "bad", ".github", "workflows", "x.yml")
	content, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	dir := t.TempDir()
	wfDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(wfDir, "x.yml")
	if err := os.WriteFile(dst, content, 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, _, _ := run(t, "fix", "--dir", wfDir, "--dry-run")

	// Dry run must report at least one planned change.
	if !strings.Contains(stdout, "GHA002") && !strings.Contains(stdout, "change") {
		t.Errorf("expected dry-run output to mention planned changes\nstdout: %s", stdout)
	}

	// The file must be unchanged.
	after, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if string(after) != string(content) {
		t.Errorf("dry-run must not modify file; diff detected")
	}
}

func TestDoctorScore(t *testing.T) {
	dir := fixtureDir("clean")
	stdout, _, code := run(t, "doctor", "--dir", dir)
	if code != 0 {
		t.Fatalf("doctor exited %d\nstdout: %s", code, stdout)
	}
	if !strings.Contains(stdout, "score") {
		t.Errorf("expected 'score' in doctor output\nstdout: %s", stdout)
	}
}
