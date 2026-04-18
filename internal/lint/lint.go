// Package lint wraps rhysd/actionlint and layers ghactor's own security rules on top.
package lint

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kdairatchi/ghactor/internal/config"
	"github.com/kdairatchi/ghactor/internal/pin"
	"github.com/kdairatchi/ghactor/internal/workflow"
	"github.com/rhysd/actionlint"
)

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
	Config           *config.File  // optional
	Resolver         *pin.Resolver // optional; nil skips GHA008
}

func Run(dir string) ([]Issue, error) {
	return RunWithOptions(Options{Dir: dir})
}

func RunWithOptions(opts Options) ([]Issue, error) {
	if opts.Dir == "" {
		opts.Dir = ".github/workflows"
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

	var denyPatterns []string
	if opts.Config != nil {
		denyPatterns = opts.Config.DenyActions
	}
	activeRules := append(Rules[:len(Rules):len(Rules)], optRules(opts.Resolver, denyPatterns)...)

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
					if cfgRule := opts.Config.RuleFor(r.ID, relPath); cfgRule.Severity != "" {
						iss.Severity = Severity(cfgRule.Severity)
					}
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
