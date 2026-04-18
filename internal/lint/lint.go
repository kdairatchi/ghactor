// Package lint wraps rhysd/actionlint and layers ghactor's own security rules on top.
package lint

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kdairatchi/ghactor/internal/config"
	"github.com/kdairatchi/ghactor/internal/pin"
	"github.com/kdairatchi/ghactor/internal/workflow"
	"github.com/rhysd/actionlint"
)

// applyConfigSeverity takes an Issue that has already passed rule-disable
// checks, consults the config for a severity override, and returns the
// (possibly mutated) issue plus a boolean indicating whether the issue should
// be kept.  A severity of "off" means drop the issue entirely.
//
// cfg may be nil; in that case the issue is returned unchanged and kept==true.
func applyConfigSeverity(iss Issue, cfg *config.File, relPath string) (Issue, bool) {
	if cfg == nil {
		return iss, true
	}
	sev := cfg.ResolvedSeverity(iss.Kind, relPath)
	switch sev {
	case "":
		// No override — keep the rule's compiled-in default.
		return iss, true
	case "off":
		return iss, false
	default:
		iss.Severity = Severity(sev)
		return iss, true
	}
}

type Severity string

const (
	SevError   Severity = "error"
	SevWarning Severity = "warning"
	SevInfo    Severity = "info"
)

type Issue struct {
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Col      int      `json:"col"`
	Kind     string   `json:"kind"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
	Source   string   `json:"source"` // "actionlint" or "ghactor"
}

type Options struct {
	Dir              string
	DisabledRules    []string
	IgnoreActionlint bool
	Config           *config.File      // optional
	Resolver         *pin.Resolver     // optional; nil skips GHA008
	ChangedFiles     map[string]bool   // if non-nil, lint only paths contained here (repo-root-relative, forward slashes)
}

func Run(dir string) ([]Issue, error) {
	return RunWithOptions(Options{Dir: dir})
}

func RunWithOptions(opts Options) ([]Issue, error) {
	if opts.Dir == "" {
		opts.Dir = ".github/workflows"
	}

	// Validate config against known rule IDs and emit warnings for typos.
	if opts.Config != nil {
		knownIDs := make([]string, len(Rules))
		for i, r := range Rules {
			knownIDs[i] = r.ID
		}
		// optRules may add GHA008/GHA010 depending on resolver; include them
		// conservatively so users who reference them don't get spurious warnings.
		optKnown := []string{"GHA008", "GHA010"}
		knownIDs = append(knownIDs, optKnown...)
		opts.Config.Validate(knownIDs, os.Stderr)
	}
	info, err := os.Stat(opts.Dir)
	if err != nil {
		return nil, fmt.Errorf("workflows dir: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", opts.Dir)
	}

	files, err := collectYAMLFiles(opts.Dir)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no workflow files under %s", opts.Dir)
	}

	// --since filter: when ChangedFiles is non-nil, drop any file whose
	// repo-root-relative path is not in the set. Resolve the git root once
	// here and reuse it for both the actionlint file list and the workflow
	// custom-rule loop. If we cannot resolve the git root we conservatively
	// treat all files as out-of-scope (fail closed).
	var (
		gitRoot    string
		gitRootErr error
	)
	if opts.ChangedFiles != nil {
		gitRoot, gitRootErr = gitRepoRoot()
		var filtered []string
		if gitRootErr == nil {
			for _, f := range files {
				rel, err := repoRelPath(gitRoot, f)
				if err != nil {
					continue
				}
				if opts.ChangedFiles[rel] {
					filtered = append(filtered, f)
				}
			}
		}
		// gitRootErr != nil → filtered stays nil → all files dropped (defensive).
		files = filtered
	}

	if len(files) == 0 {
		// Either no workflows exist or all were filtered out by --since.
		return nil, nil
	}

	var out []Issue

	if !opts.IgnoreActionlint {
		al, err := runActionlint(files)
		if err != nil {
			return nil, fmt.Errorf("actionlint: %w", err)
		}
		out = append(out, al...)
	}

	wfs, err := workflow.LoadDir(opts.Dir)
	if err != nil {
		return nil, fmt.Errorf("parse workflows: %w", err)
	}

	// Apply ChangedFiles filter to the loaded workflow set so the custom-rule
	// loop only visits files that passed the earlier actionlint filter.
	// Reuse the gitRoot already resolved above.
	if opts.ChangedFiles != nil {
		if gitRootErr == nil {
			var kept []*workflow.File
			for _, wf := range wfs {
				rel, err := repoRelPath(gitRoot, wf.Path)
				if err != nil {
					continue
				}
				if opts.ChangedFiles[rel] {
					kept = append(kept, wf)
				}
			}
			wfs = kept
		} else {
			wfs = nil
		}
	}

	var denyPatterns []string
	var allowPatterns []string
	if opts.Config != nil {
		denyPatterns = opts.Config.DenyActions
		allowPatterns = opts.Config.AllowActions
	}
	activeRules := append(Rules[:len(Rules):len(Rules)], optRules(opts.Resolver, denyPatterns)...)
	if r := optAllowlistRule(allowPatterns); r != nil {
		activeRules = append(activeRules, *r)
	}

	disabled := toSet(opts.DisabledRules)
	for _, wf := range wfs {
		relPath := wf.Path
		if opts.Config != nil {
			if rp, err := filepath.Rel(opts.Config.Root, wf.Path); err == nil {
				relPath = rp
			}
		}
		for _, r := range activeRules {
			if disabled[r.ID] {
				continue
			}
			if opts.Config != nil && opts.Config.RuleFor(r.ID, relPath).Disabled {
				continue
			}
			for _, iss := range r.Check(wf) {
				if opts.Config != nil {
					if iss.Kind == "GHA001" || iss.Kind == "GHA006" || iss.Kind == "GHA007" {
						if uses := extractUsesFromMessage(iss.Message); uses != "" && opts.Config.TrustsAction(uses) {
							continue
						}
					}
				}
				iss, keep := applyConfigSeverity(iss, opts.Config, relPath)
				if !keep {
					continue
				}
				out = append(out, iss)
			}
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].Col < out[j].Col
	})
	return out, nil
}

func runActionlint(files []string) ([]Issue, error) {
	linter, err := actionlint.NewLinter(io.Discard, &actionlint.LinterOptions{})
	if err != nil {
		return nil, err
	}
	errs, err := linter.LintFiles(files, nil)
	if err != nil {
		return nil, err
	}
	out := make([]Issue, 0, len(errs))
	for _, e := range errs {
		kind := e.Kind
		if kind == "" {
			kind = "actionlint"
		}
		out = append(out, Issue{
			File:     e.Filepath,
			Line:     e.Line,
			Col:      e.Column,
			Kind:     kind,
			Severity: SevError,
			Message:  e.Message,
			Source:   "actionlint",
		})
	}
	return out, nil
}

func collectYAMLFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext == ".yml" || ext == ".yaml" {
			files = append(files, p)
		}
		return nil
	})
	return files, err
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[strings.TrimSpace(x)] = true
	}
	return m
}

// gitRepoRoot returns the absolute path of the current git repository root.
// It shells out to "git rev-parse --show-toplevel". Returns an error when git
// is unavailable or the cwd is not inside a repository.
func gitRepoRoot() (string, error) {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// repoRelPath returns the repo-root-relative path of absPath using forward
// slashes, suitable for comparison with ChangedFiles keys.
func repoRelPath(root, absPath string) (string, error) {
	// Make absPath absolute if it is not already (it may be relative to cwd).
	if !filepath.IsAbs(absPath) {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		absPath = filepath.Join(cwd, absPath)
	}
	rel, err := filepath.Rel(root, absPath)
	if err != nil {
		return "", err
	}
	return filepath.ToSlash(rel), nil
}

// extractUsesFromMessage pulls a quoted `uses:` value from a rule message (used for trusted-actions filtering).
func extractUsesFromMessage(msg string) string {
	i := strings.Index(msg, `"`)
	if i < 0 {
		return ""
	}
	j := strings.Index(msg[i+1:], `"`)
	if j < 0 {
		return ""
	}
	return msg[i+1 : i+1+j]
}

// Counts summarizes an issue set.
func Counts(iss []Issue) (errors, warnings, info int) {
	for _, i := range iss {
		switch i.Severity {
		case SevError:
			errors++
		case SevWarning:
			warnings++
		default:
			info++
		}
	}
	return
}
