package workflow

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ActionFile represents a parsed action.yml / action.yaml file.
// Only composite actions (runs.using == "composite") get a non-nil Synth field.
type ActionFile struct {
	// Path is the absolute or relative path to the action.yml file.
	Path string
	// Source is the raw file bytes.
	Source []byte
	// Root is the top-level yaml.Node from the parse.
	Root *yaml.Node
	// Synth is a synthetic Workflow with a single job "composite" whose Steps
	// hold the composite action's runs.steps[]. Nil for non-composite actions.
	Synth *Workflow
	// Using is the value of runs.using (e.g. "composite", "docker", "node20").
	Using string
	// Name is the value of the top-level name: field.
	Name string
	// Inputs holds the declared input names. These are the keys under top-level
	// inputs:, recorded for future tainted-input analysis.
	Inputs []string
}

// compositeActionYAML is used solely to unmarshal the minimal fields we need
// from an action.yml without touching the existing Workflow type.
type compositeActionYAML struct {
	Name   string            `yaml:"name"`
	Inputs map[string]interface{} `yaml:"inputs"`
	Runs   struct {
		Using string  `yaml:"using"`
		Steps []*Step `yaml:"steps"`
	} `yaml:"runs"`
}

// LoadActionFile parses a single action.yml / action.yaml and returns an
// ActionFile. For composite actions (runs.using == "composite") the Synth
// field is populated with a synthetic Workflow so existing rule functions
// can operate on composite steps without modification.
func LoadActionFile(path string) (*ActionFile, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(src, &root); err != nil {
		return nil, fmt.Errorf("%s: yaml parse: %w", path, err)
	}

	var raw compositeActionYAML
	if err := yaml.Unmarshal(src, &raw); err != nil {
		return nil, fmt.Errorf("%s: yaml unmarshal: %w", path, err)
	}

	af := &ActionFile{
		Path:   path,
		Source: src,
		Root:   &root,
		Using:  strings.ToLower(strings.TrimSpace(raw.Runs.Using)),
		Name:   raw.Name,
	}

	for k := range raw.Inputs {
		af.Inputs = append(af.Inputs, k)
	}

	if af.Using != "composite" {
		return af, nil
	}

	// Build the synthetic Workflow: a single job named "composite" whose steps
	// are the composite action's runs.steps[].
	synth := &Workflow{
		Name: raw.Name,
		Jobs: map[string]*Job{
			"composite": {
				Steps: raw.Runs.Steps,
			},
		},
	}

	// Attach line/col from the yaml.Node tree, mirroring attachStepPositions
	// but walking runs.steps instead of jobs.<id>.steps.
	attachCompositeStepPositions(&root, synth)

	af.Synth = synth
	return af, nil
}

// attachCompositeStepPositions walks the yaml.Node tree to populate Line/Col
// and RawNode on each step in the synthetic "composite" job.
func attachCompositeStepPositions(root *yaml.Node, synth *Workflow) {
	if synth == nil || len(root.Content) == 0 {
		return
	}
	top := root.Content[0]
	runsNode := mapNode(top, "runs")
	if runsNode == nil {
		return
	}
	stepsNode := mapNode(runsNode, "steps")
	if stepsNode == nil {
		return
	}
	job := synth.Jobs["composite"]
	if job == nil {
		return
	}
	for idx, s := range stepsNode.Content {
		if idx >= len(job.Steps) {
			break
		}
		if job.Steps[idx] == nil {
			continue
		}
		job.Steps[idx].Line = s.Line
		job.Steps[idx].Col = s.Column
		job.Steps[idx].RawNode = s
	}
}

// AsWorkflowFile adapts a composite ActionFile for use with workflow-level
// lint rules. Returns nil if the action is not composite.
func (a *ActionFile) AsWorkflowFile() *File {
	if a == nil || a.Synth == nil {
		return nil
	}
	return &File{
		Path:   a.Path,
		Source: a.Source,
		Root:   a.Root,
		WF:     a.Synth,
	}
}

// isWorkflowPath returns true when the normalised path contains a
// .github/workflows segment — these are handled by the workflow linter.
func isWorkflowPath(path string) bool {
	normalized := filepath.ToSlash(path)
	return strings.Contains(normalized, ".github/workflows")
}

// LoadActions walks dir recursively, finds every action.yml / action.yaml
// (excluding any file under a .github/workflows/ path segment), and returns
// the parsed ActionFile for each. Non-composite actions are included but have
// Synth == nil; callers can inspect Using to distinguish them.
func LoadActions(dir string) ([]*ActionFile, error) {
	var out []*ActionFile
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		// Only action.yml / action.yaml (case-insensitive base name).
		base := strings.ToLower(filepath.Base(p))
		if base != "action.yml" && base != "action.yaml" {
			return nil
		}
		// Skip files that live under .github/workflows/.
		if isWorkflowPath(p) {
			return nil
		}
		af, err := LoadActionFile(p)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		out = append(out, af)
		return nil
	})
	return out, err
}
