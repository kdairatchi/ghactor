package main

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

// initTempRepo creates a temporary git repository with an initial commit and
// returns its path. It skips the test if git is not available.
func initTempRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dir := t.TempDir()

	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		// Supply git identity for the commit step.
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test",
			"GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=test",
			"GIT_COMMITTER_EMAIL=test@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}

	run("init")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "test")

	// Create an initial commit so the repo is not empty.
	readme := dir + "/README.md"
	if err := os.WriteFile(readme, []byte("# test\n"), 0o644); err != nil {
		t.Fatalf("write README: %v", err)
	}
	run("add", "README.md")
	run("commit", "-m", "init")

	return dir
}

// TestGitCleanTreeCheck_clean verifies that a clean working tree returns nil.
func TestGitCleanTreeCheck_clean(t *testing.T) {
	dir := initTempRepo(t)
	if err := gitCleanTreeCheck(dir); err != nil {
		t.Fatalf("expected nil on clean tree, got: %v", err)
	}
}

// TestGitCleanTreeCheck_dirty verifies that an uncommitted file returns an error.
func TestGitCleanTreeCheck_dirty(t *testing.T) {
	dir := initTempRepo(t)

	// Write an untracked file to make the tree dirty.
	if err := os.WriteFile(dir+"/untracked.txt", []byte("dirty\n"), 0o644); err != nil {
		t.Fatalf("write untracked file: %v", err)
	}

	err := gitCleanTreeCheck(dir)
	if err == nil {
		t.Fatal("expected non-nil error on dirty tree, got nil")
	}
	if !strings.Contains(err.Error(), "uncommitted changes") {
		t.Errorf("error message should mention uncommitted changes, got: %q", err.Error())
	}
}

// TestGitCleanTreeCheck_staged verifies that a staged-but-not-committed file
// also counts as uncommitted changes.
func TestGitCleanTreeCheck_staged(t *testing.T) {
	dir := initTempRepo(t)

	newFile := dir + "/staged.txt"
	if err := os.WriteFile(newFile, []byte("staged\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	cmd := exec.Command("git", "add", "staged.txt")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v\n%s", err, out)
	}

	if err := gitCleanTreeCheck(dir); err == nil {
		t.Fatal("expected error for staged changes, got nil")
	}
}

var branchNameRe = regexp.MustCompile(`^ghactor/[a-z]+-\d{8}-\d{6}$`)

// TestBranchName verifies the format and that two calls at different times
// produce different names (or at least the format is correct).
func TestBranchName(t *testing.T) {
	for _, prefix := range []string{"update", "fix"} {
		t.Run(prefix, func(t *testing.T) {
			name := branchName(prefix)
			if !branchNameRe.MatchString(name) {
				t.Errorf("branchName(%q) = %q; want match %s", prefix, name, branchNameRe)
			}
			if !strings.HasPrefix(name, "ghactor/"+prefix+"-") {
				t.Errorf("expected prefix ghactor/%s-, got %q", prefix, name)
			}
		})
	}
}

// TestBranchNameUniqueness verifies two calls separated by a second differ.
// This is skipped in short mode to avoid a 1-second sleep in CI.
func TestBranchNameUniqueness(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sleep-based uniqueness test in short mode")
	}
	a := branchName("update")
	time.Sleep(1100 * time.Millisecond)
	b := branchName("update")
	if a == b {
		t.Errorf("expected unique branch names across seconds, both = %q", a)
	}
}

// TestUniqueFIles verifies deduplication while preserving order.
func TestUniqueFiles(t *testing.T) {
	in := []string{"a.yml", "b.yml", "a.yml", "c.yml", "b.yml"}
	got := uniqueFiles(in)
	want := []string{"a.yml", "b.yml", "c.yml"}
	if len(got) != len(want) {
		t.Fatalf("uniqueFiles(%v) = %v; want %v", in, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("index %d: got %q want %q", i, got[i], want[i])
		}
	}
}

// TestFixPRBody verifies the body contains the expected sections.
func TestFixPRBody(t *testing.T) {
	rules := []string{"GHA002", "GHA005", "GHA002"}
	files := []string{".github/workflows/ci.yml", ".github/workflows/deploy.yml"}
	body := fixPRBody(rules, files)

	checks := []string{
		"## ghactor fix",
		"### Rules applied",
		"- GHA002",
		"- GHA005",
		"### Files touched",
		"`.github/workflows/ci.yml`",
		"`.github/workflows/deploy.yml`",
	}
	for _, want := range checks {
		if !strings.Contains(body, want) {
			t.Errorf("fixPRBody output missing %q\noutput:\n%s", want, body)
		}
	}

	// GHA002 appears once in rules despite being in input twice.
	count := strings.Count(body, "GHA002")
	if count != 1 {
		t.Errorf("expected GHA002 deduplicated to 1 occurrence, got %d", count)
	}
}
