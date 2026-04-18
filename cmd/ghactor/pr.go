package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// uniqueFiles returns a deduplicated, order-preserving list of file paths.
func uniqueFiles(files []string) []string {
	seen := make(map[string]bool, len(files))
	out := make([]string, 0, len(files))
	for _, f := range files {
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}

// runPR is the shared PR orchestration used by both update --pr and fix --pr.
// It expects that changes have already been applied to disk.
//
//   - repoDir is the repository root (used as Dir for git commands).
//   - files is the list of modified workflow files (may contain duplicates).
//   - branchPrefix is either "update" or "fix".
//   - title is the PR title.
//   - body is the Markdown PR body.
//
// It returns the PR URL on success.
func runPR(repoDir string, files []string, branchPrefix, title, body string) (string, error) {
	files = uniqueFiles(files)

	branch := branchName(branchPrefix)
	if err := gitCheckoutBranch(repoDir, branch); err != nil {
		return "", err
	}

	msg := fmt.Sprintf("ghactor: %s workflows", branchPrefix)
	if err := gitCommitFiles(repoDir, files, msg); err != nil {
		return "", err
	}

	if err := gitPushSetUpstream(repoDir, branch); err != nil {
		return "", err
	}

	url, err := ghPRCreate(repoDir, title, body)
	if err != nil {
		return "", err
	}
	return url, nil
}

// fixPRBody produces a brief Markdown body for a fix --pr PR.
// It lists the rules applied and files touched.
func fixPRBody(rules []string, files []string) string {
	var b strings.Builder
	b.WriteString("## ghactor fix\n\n")
	b.WriteString("### Rules applied\n\n")
	seen := make(map[string]bool)
	for _, r := range rules {
		if !seen[r] {
			seen[r] = true
			b.WriteString("- " + r + "\n")
		}
	}
	b.WriteString("\n### Files touched\n\n")
	for _, f := range uniqueFiles(files) {
		b.WriteString("- `" + f + "`\n")
	}
	return b.String()
}

// repoRoot returns the absolute path to the git repository root by running
// `git rev-parse --show-toplevel` in the current working directory.
func repoRoot() (string, error) {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse --show-toplevel: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// branchName returns a branch name in the form ghactor/<prefix>-YYYYMMDD-HHMMSS.
func branchName(prefix string) string {
	return fmt.Sprintf("ghactor/%s-%s", prefix, time.Now().UTC().Format("20060102-150405"))
}

// gitCleanTreeCheck returns a non-nil error when the working tree has any
// uncommitted changes. It shells out to `git status --porcelain` so that it
// behaves identically to what a human would see.
func gitCleanTreeCheck(repoDir string) error {
	cmd := exec.Command("git", "status", "--porcelain")
	cmd.Dir = repoDir
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("git status: %w", err)
	}
	if len(bytes.TrimSpace(out)) > 0 {
		return fmt.Errorf("uncommitted changes — commit or stash first")
	}
	return nil
}

// gitCheckoutBranch creates and switches to a new branch.
func gitCheckoutBranch(repoDir, branch string) error {
	cmd := exec.Command("git", "checkout", "-b", branch)
	cmd.Dir = repoDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git checkout -b %s: %w\n%s", branch, err, string(out))
	}
	return nil
}

// gitCommitFiles stages only the provided files, then commits with the given
// message plus a body that lists the changed files.
func gitCommitFiles(repoDir string, files []string, message string) error {
	if len(files) == 0 {
		return fmt.Errorf("no files to commit")
	}

	// Stage only the specific workflow files — no git add -A.
	addArgs := append([]string{"add", "--"}, files...)
	addCmd := exec.Command("git", addArgs...)
	addCmd.Dir = repoDir
	if out, err := addCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git add: %w\n%s", err, string(out))
	}

	body := "Changed files:\n"
	for _, f := range files {
		body += "  " + f + "\n"
	}
	fullMsg := message + "\n\n" + body

	commitCmd := exec.Command("git", "commit", "-m", fullMsg)
	commitCmd.Dir = repoDir
	if out, err := commitCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git commit: %w\n%s", err, string(out))
	}
	return nil
}

// gitPushSetUpstream pushes the branch and sets the upstream tracking reference.
func gitPushSetUpstream(repoDir, branch string) error {
	cmd := exec.Command("git", "push", "-u", "origin", branch)
	cmd.Dir = repoDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git push: %w\n%s", err, string(out))
	}
	return nil
}

// ghPRCreate calls `gh pr create` with a title and a body sourced from a
// temporary file. It returns the PR URL printed by gh.
func ghPRCreate(repoDir, title, body string) (string, error) {
	f, err := os.CreateTemp("", "ghactor-pr-body-*.md")
	if err != nil {
		return "", fmt.Errorf("create pr body tempfile: %w", err)
	}
	defer os.Remove(f.Name())

	if _, err := f.WriteString(body); err != nil {
		f.Close()
		return "", fmt.Errorf("write pr body: %w", err)
	}
	f.Close()

	cmd := exec.Command("gh", "pr", "create",
		"--title", title,
		"--body-file", f.Name(),
	)
	cmd.Dir = repoDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("gh pr create: %w\n%s", err, string(out))
	}
	return strings.TrimSpace(string(out)), nil
}
