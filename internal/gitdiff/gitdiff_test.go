package gitdiff_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/kdairatchi/ghactor/internal/gitdiff"
)

// skipOnWindows marks the test as skipped on Windows where git path handling
// and shell-out behaviour differ from Linux/macOS.
func skipOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("git shell-out tests are skipped on Windows")
	}
}

// mustGit runs a git command inside dir or fails the test.
func mustGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// initRepo creates a fresh git repo in dir with the minimum identity config
// needed to commit.
func initRepo(t *testing.T, dir string) {
	t.Helper()
	mustGit(t, dir, "init", "-b", "main")
	mustGit(t, dir, "config", "user.email", "test@example.com")
	mustGit(t, dir, "config", "user.name", "Test")
}

// writeFile writes content to path (creating dirs) and returns the path.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile %s: %v", path, err)
	}
}

// cdRepo changes the process working directory to dir for the duration of the
// test. git shell-outs inherit the process cwd.
func cdRepo(t *testing.T, dir string) {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir %s: %v", dir, err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(orig); err != nil {
			t.Logf("warning: could not restore cwd: %v", err)
		}
	})
}

// TestChangedSince_EmptyRef verifies that an empty ref returns nil, nil.
func TestChangedSince_EmptyRef(t *testing.T) {
	changed, err := gitdiff.ChangedSince("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed != nil {
		t.Errorf("expected nil map for empty ref, got %v", changed)
	}
}

// TestChangedSince_NotARepo verifies graceful nil return outside any repo.
func TestChangedSince_NotARepo(t *testing.T) {
	skipOnWindows(t)

	// Use /tmp (guaranteed non-repo on Linux CI).
	dir := t.TempDir()
	cdRepo(t, dir)

	changed, err := gitdiff.ChangedSince("main")
	if err != nil {
		t.Fatalf("expected nil error outside repo, got: %v", err)
	}
	if changed != nil {
		t.Errorf("expected nil map outside repo, got %v", changed)
	}
}

// TestChangedSince_UnknownRef verifies an error is returned for a bad ref.
func TestChangedSince_UnknownRef(t *testing.T) {
	skipOnWindows(t)

	dir := t.TempDir()
	initRepo(t, dir)
	writeFile(t, filepath.Join(dir, "a.yml"), "name: a\n")
	mustGit(t, dir, "add", ".")
	mustGit(t, dir, "commit", "-m", "init")
	cdRepo(t, dir)

	_, err := gitdiff.ChangedSince("nonexistent-branch-xyz")
	if err == nil {
		t.Fatal("expected error for unknown ref, got nil")
	}
	// Error must mention "revision not found" per the spec.
	if msg := err.Error(); len(msg) == 0 {
		t.Error("error message should not be empty")
	}
}

// TestChangedSince_CommittedChanges verifies that a file modified on the
// current branch (relative to main) appears in the changed set, while an
// untouched file does not.
func TestChangedSince_CommittedChanges(t *testing.T) {
	skipOnWindows(t)

	dir := t.TempDir()
	initRepo(t, dir)

	// Commit a.yml and b.yml on main.
	writeFile(t, filepath.Join(dir, "a.yml"), "name: a\n")
	writeFile(t, filepath.Join(dir, "b.yml"), "name: b\n")
	mustGit(t, dir, "add", ".")
	mustGit(t, dir, "commit", "-m", "init")

	// Branch off, modify only a.yml.
	mustGit(t, dir, "checkout", "-b", "feature")
	writeFile(t, filepath.Join(dir, "a.yml"), "name: a-modified\n")
	mustGit(t, dir, "add", "a.yml")
	mustGit(t, dir, "commit", "-m", "update a")

	cdRepo(t, dir)

	changed, err := gitdiff.ChangedSince("main")
	if err != nil {
		t.Fatalf("ChangedSince: %v", err)
	}
	if !changed["a.yml"] {
		t.Errorf("expected a.yml in changed set, got %v", changed)
	}
	if changed["b.yml"] {
		t.Errorf("b.yml should NOT be in changed set, got %v", changed)
	}
}

// TestChangedSince_UntrackedFile verifies that a new, unstaged file appears
// in the changed set.
func TestChangedSince_UntrackedFile(t *testing.T) {
	skipOnWindows(t)

	dir := t.TempDir()
	initRepo(t, dir)

	// Initial commit so HEAD exists.
	writeFile(t, filepath.Join(dir, "existing.yml"), "name: existing\n")
	mustGit(t, dir, "add", ".")
	mustGit(t, dir, "commit", "-m", "init")

	// Add c.yml without staging it.
	writeFile(t, filepath.Join(dir, "c.yml"), "name: c\n")

	cdRepo(t, dir)

	changed, err := gitdiff.ChangedSince("HEAD")
	if err != nil {
		t.Fatalf("ChangedSince: %v", err)
	}
	if !changed["c.yml"] {
		t.Errorf("expected c.yml (untracked) in changed set, got %v", changed)
	}
}

// TestChangedSince_StagedFile verifies that a staged but uncommitted file
// appears in the changed set.
func TestChangedSince_StagedFile(t *testing.T) {
	skipOnWindows(t)

	dir := t.TempDir()
	initRepo(t, dir)

	writeFile(t, filepath.Join(dir, "existing.yml"), "name: existing\n")
	mustGit(t, dir, "add", ".")
	mustGit(t, dir, "commit", "-m", "init")

	// Stage a new file but do not commit.
	writeFile(t, filepath.Join(dir, "staged.yml"), "name: staged\n")
	mustGit(t, dir, "add", "staged.yml")

	cdRepo(t, dir)

	changed, err := gitdiff.ChangedSince("HEAD")
	if err != nil {
		t.Fatalf("ChangedSince: %v", err)
	}
	if !changed["staged.yml"] {
		t.Errorf("expected staged.yml in changed set, got %v", changed)
	}
}

// TestChangedSince_HeadRef verifies that passing "HEAD" as the ref returns
// only staged/unstaged/untracked changes, not committed ones.
func TestChangedSince_HeadRef(t *testing.T) {
	skipOnWindows(t)

	dir := t.TempDir()
	initRepo(t, dir)

	writeFile(t, filepath.Join(dir, "a.yml"), "name: a\n")
	mustGit(t, dir, "add", ".")
	mustGit(t, dir, "commit", "-m", "init")

	// Committed file — should NOT appear for HEAD ref.
	writeFile(t, filepath.Join(dir, "committed.yml"), "name: c\n")
	mustGit(t, dir, "add", "committed.yml")
	mustGit(t, dir, "commit", "-m", "add committed")

	// Untracked file — should appear.
	writeFile(t, filepath.Join(dir, "new_untracked.yml"), "name: new\n")

	cdRepo(t, dir)

	changed, err := gitdiff.ChangedSince("HEAD")
	if err != nil {
		t.Fatalf("ChangedSince(HEAD): %v", err)
	}
	// committed.yml was committed before HEAD; only untracked should appear.
	if changed["committed.yml"] {
		t.Errorf("committed.yml should not appear for HEAD ref, got %v", changed)
	}
	if !changed["new_untracked.yml"] {
		t.Errorf("expected new_untracked.yml (untracked) in changed set for HEAD ref, got %v", changed)
	}
}

// TestChangedSince_NoCommits verifies that a repo with no commits returns
// untracked files and no error.
func TestChangedSince_NoCommits(t *testing.T) {
	skipOnWindows(t)

	dir := t.TempDir()
	initRepo(t, dir)

	writeFile(t, filepath.Join(dir, "new.yml"), "name: new\n")

	cdRepo(t, dir)

	// With no commits, HEAD does not exist; the function must not error.
	changed, err := gitdiff.ChangedSince("HEAD")
	if err != nil {
		t.Fatalf("unexpected error in repo with no commits: %v", err)
	}
	// new.yml is untracked — it should appear.
	if !changed["new.yml"] {
		t.Errorf("expected new.yml in changed set (no commits), got %v", changed)
	}
}
