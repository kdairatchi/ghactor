package lint

import (
	"fmt"
	"path/filepath"
	"sort"

	"github.com/kdairatchi/ghactor/internal/workflow"
)

// applicableActionRuleIDs is the set of ghactor rule IDs that are meaningful
// for composite actions. Rules that are workflow-level concepts
// (permissions, pull_request_target, timeout, reusable workflow, PRT
// artifact, concurrency, OIDC subject) are intentionally excluded.
//
// Included:
//   GHA001 — unpinned action (composite steps can reference third-party actions)
//   GHA004 — script injection (the primary motivation for this linter)
//   GHA006 — floating-latest (floating ref in a composite step uses:)
//   GHA007 — unversioned action (missing @ref in composite step)
//   GHA012 — curl-pipe-shell (dangerous installer pattern in run: blocks)
//   GHA014 — legacy-set-env (::set-env / ::add-path in run: blocks)
//   GHA018 — github-env-smuggling (untrusted expr written to $GITHUB_ENV)
//
// Excluded (not applicable to composite actions):
//   GHA002 — missing-permissions (no GITHUB_TOKEN in composite actions)
//   GHA003 — pull-request-target-checkout (no on: triggers in an action)
//   GHA005 — missing-timeout (no job timeout-minutes in composite actions)
//   GHA009 — reusable-workflow-unpinned (no jobs.<id>.uses in composite actions)
//   GHA011 — persist-credentials-on-prt (pull_request_target not applicable)
//   GHA013 — cache-key-untrusted (requires github.event.* context, not available)
//   GHA015 — prt-artifact-upload (no pull_request_target context)
//   GHA016 — self-hosted-public (no runs-on in composite actions)
//   GHA017 — missing-concurrency-deploy (no concurrency: in composite actions)
//   GHA019 — oidc-no-subject (no id-token: write in composite actions)
var applicableActionRuleIDs = map[string]bool{
	"GHA001": true,
	"GHA004": true,
	"GHA006": true,
	"GHA007": true,
	"GHA012": true,
	"GHA014": true,
	"GHA018": true,
}

// ActionOptions configures LintActionsWithOptions.
type ActionOptions struct {
	// Dir is the root directory to walk for action.yml files. Defaults to ".".
	Dir string
	// DisabledRules is the set of rule IDs to suppress.
	DisabledRules []string
	// ChangedFiles, when non-nil, restricts linting to composite actions whose
	// repo-root-relative path is contained in the map. Semantics match
	// Options.ChangedFiles in RunWithOptions.
	ChangedFiles map[string]bool
}

// LintActions runs the subset of ghactor security rules that apply to
// composite actions under dir. It does NOT invoke actionlint — actionlint
// does not understand action.yml files.
//
// Rules applied: GHA001, GHA004, GHA006, GHA007, GHA012, GHA014, GHA018.
//
// disabled is a slice of rule IDs to suppress (same format as RunWithOptions).
// Issues are returned sorted by file path, line, and column.
func LintActions(dir string, disabled []string) ([]Issue, error) {
	return LintActionsWithOptions(ActionOptions{Dir: dir, DisabledRules: disabled})
}

// LintActionsWithOptions is like LintActions but accepts the full ActionOptions
// struct, which allows passing ChangedFiles for --since filtering.
func LintActionsWithOptions(opts ActionOptions) ([]Issue, error) {
	if opts.Dir == "" {
		opts.Dir = "."
	}

	actions, err := workflow.LoadActions(opts.Dir)
	if err != nil {
		return nil, fmt.Errorf("load composite actions: %w", err)
	}

	disabledSet := toSet(opts.DisabledRules)

	// Filter the global Rules slice to only the applicable subset.
	var activeRules []Rule
	for _, r := range Rules {
		if !applicableActionRuleIDs[r.ID] {
			continue
		}
		if disabledSet[r.ID] {
			continue
		}
		activeRules = append(activeRules, r)
	}

	// Resolve git root once if we need ChangedFiles filtering.
	var gitRoot string
	var gitRootErr error
	if opts.ChangedFiles != nil {
		gitRoot, gitRootErr = gitRepoRoot()
	}

	var out []Issue
	for _, af := range actions {
		if af.Synth == nil {
			// Non-composite action (docker, node20, etc.); skip rule checks.
			continue
		}

		// --since filter: check whether this action file is in the changed set.
		if opts.ChangedFiles != nil {
			if gitRootErr != nil {
				// Cannot resolve root — conservatively skip all (defensive).
				continue
			}
			rel, err := repoRelPath(gitRoot, af.Path)
			if err != nil {
				continue
			}
			// Also check the directory-level path (action.yml lives at
			// <dir>/action.yml; users may pass the directory in ChangedFiles).
			dirRel := filepath.ToSlash(filepath.Dir(rel))
			if !opts.ChangedFiles[rel] && !opts.ChangedFiles[dirRel] {
				continue
			}
		}

		wf := af.AsWorkflowFile()
		if wf == nil {
			continue
		}
		for _, r := range activeRules {
			out = append(out, r.Check(wf)...)
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
