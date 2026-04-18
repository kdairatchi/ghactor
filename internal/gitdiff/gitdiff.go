// Package gitdiff exposes the set of workspace-relative paths changed between
// a git ref and the working tree.
package gitdiff

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// ChangedSince returns paths (relative to repo root, forward slashes) that
// differ between ref and the current working tree, including staged and
// unstaged modifications plus untracked files tracked by .gitignore rules.
//
// If ref is empty or git is unavailable, returns nil, nil (caller should
// treat as "no filter — lint everything").
//
// Errors only for ref resolution failures (unknown ref, not a repo).
func ChangedSince(ref string) (map[string]bool, error) {
	if ref == "" {
		return nil, nil
	}

	// Check git is available; also validates we are inside a repo.
	root, err := repoRoot()
	if err != nil {
		// Not a git repo or git not installed — gracefully no-op.
		return nil, nil
	}

	result := make(map[string]bool)

	// Resolve the merge-base between HEAD and ref, unless ref IS HEAD.
	// When ref == "HEAD" the committed diff is empty; still collect staged/unstaged.
	isHead := strings.ToUpper(strings.TrimSpace(ref)) == "HEAD"

	if !isHead {
		base, err := mergeBase(ref)
		if err != nil {
			return nil, fmt.Errorf("revision not found: %w", err)
		}

		// Committed changes: <merge-base>..HEAD.
		committed, err := gitDiffNames(base, "HEAD")
		if err != nil {
			return nil, fmt.Errorf("git diff committed: %w", err)
		}
		addPaths(result, root, committed)
	}

	// Staged + unstaged changes (diff against HEAD).
	working, err := gitDiffNamesHead()
	if err != nil {
		// HEAD may not exist yet (empty repo) — treat as empty.
		working = nil
	}
	addPaths(result, root, working)

	// Untracked files not yet staged.
	untracked, err := gitUntrackedFiles()
	if err == nil {
		addPaths(result, root, untracked)
	}

	return result, nil
}

// repoRoot returns the absolute path of the git repo root, or an error if
// the current directory is not inside a git repository or git is unavailable.
func repoRoot() (string, error) {
	out, err := runGit("rev-parse", "--show-toplevel")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// mergeBase returns the merge-base commit SHA between HEAD and ref.
func mergeBase(ref string) (string, error) {
	out, err := runGit("merge-base", "HEAD", ref)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// gitDiffNames returns paths changed between two tree-ish objects.
// Only includes Added, Copied, Modified, Renamed, and Type-changed files.
func gitDiffNames(from, to string) ([]string, error) {
	out, err := runGit("diff", "--name-only", "--diff-filter=ACMRT", from, to)
	if err != nil {
		return nil, err
	}
	return splitLines(out), nil
}

// gitDiffNamesHead returns staged and unstaged paths relative to HEAD.
func gitDiffNamesHead() ([]string, error) {
	out, err := runGit("diff", "--name-only", "--diff-filter=ACMRT", "HEAD")
	if err != nil {
		return nil, err
	}
	return splitLines(out), nil
}

// gitUntrackedFiles returns untracked paths that are not git-ignored.
func gitUntrackedFiles() ([]string, error) {
	out, err := runGit("ls-files", "--others", "--exclude-standard")
	if err != nil {
		return nil, err
	}
	return splitLines(out), nil
}

// addPaths normalises each raw git-output path (relative to repo root) and
// adds the forward-slash form to the set. Paths produced by git are already
// root-relative; we just normalise OS separators.
func addPaths(set map[string]bool, _ string, paths []string) {
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// git always emits forward slashes on all platforms for --name-only
		// output, but normalise to be safe.
		set[filepath.ToSlash(p)] = true
	}
}

// splitLines splits a command's stdout on newlines, discarding empty strings.
func splitLines(s string) []string {
	raw := strings.Split(s, "\n")
	out := make([]string, 0, len(raw))
	for _, line := range raw {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// runGit executes a git sub-command and returns its combined stdout, or an
// error wrapping the stderr message.
func runGit(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), msg)
	}
	return stdout.String(), nil
}
