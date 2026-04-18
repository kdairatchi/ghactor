package workflow

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type File struct {
	Path   string
	Source []byte
	Root   *yaml.Node
	WF     *Workflow
}

// ReusableUse records a `jobs.<id>.uses:` call to an external reusable workflow.
type ReusableUse struct {
	Owner string
	Repo  string
	Path  string
	Ref   string
	Line  int
	Col   int
}

type Workflow struct {
	Name        string                 `yaml:"name"`
	On          yaml.Node              `yaml:"on"`
	Permissions yaml.Node              `yaml:"permissions"`
	Jobs        map[string]*Job        `yaml:"jobs"`
	Env         map[string]string      `yaml:"env"`
	Defaults    map[string]interface{} `yaml:"defaults"`
	Reusables   []ReusableUse          `yaml:"-"`
}

type Job struct {
	Name        string            `yaml:"name"`
	RunsOn      yaml.Node         `yaml:"runs-on"`
	Permissions yaml.Node         `yaml:"permissions"`
	TimeoutMin  *int              `yaml:"timeout-minutes"`
	Steps       []*Step           `yaml:"steps"`
	If          string            `yaml:"if"`
	Env         map[string]string `yaml:"env"`
	Uses        string            `yaml:"uses"`
}

type Step struct {
	Name    string            `yaml:"name"`
	Uses    string            `yaml:"uses"`
	Run     string            `yaml:"run"`
	With    map[string]string `yaml:"with"`
	Env     map[string]string `yaml:"env"`
	If      string            `yaml:"if"`
	Shell   string            `yaml:"shell"`
	Line    int               `yaml:"-"`
	Col     int               `yaml:"-"`
	RawNode *yaml.Node        `yaml:"-"`
}

func LoadDir(dir string) ([]*File, error) {
	var files []*File
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}
		f, err := Load(p)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		files = append(files, f)
		return nil
	})
	return files, err
}

func Load(path string) (*File, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(src, &root); err != nil {
		return nil, err
	}
	wf := &Workflow{}
	if err := yaml.Unmarshal(src, wf); err != nil {
		return nil, err
	}
	attachStepPositions(&root, wf)
	attachReusablePositions(&root, wf)
	return &File{Path: path, Source: src, Root: &root, WF: wf}, nil
}

// parseReusableUses splits `owner/repo/.github/workflows/x.yml@ref` into parts.
// Returns zero-value on unrecognised format.
func parseReusableUses(uses string) (owner, repo, path, ref string, ok bool) {
	// Must contain @ for ref.
	atIdx := strings.LastIndex(uses, "@")
	if atIdx < 0 {
		return
	}
	ref = uses[atIdx+1:]
	body := uses[:atIdx] // owner/repo/.github/workflows/x.yml

	// First two slash-separated segments are owner and repo.
	parts := strings.SplitN(body, "/", 3)
	if len(parts) < 3 {
		// External reusable workflows always have owner/repo/path — skip bare actions.
		return
	}
	owner, repo, path = parts[0], parts[1], parts[2]

	// A path that starts with .github/workflows/ is a reusable workflow call.
	// Bare action calls (e.g. actions/checkout) have no such path segment.
	if !strings.HasPrefix(path, ".github/") {
		owner, repo, path = "", "", ""
		return
	}
	ok = true
	return
}

func attachStepPositions(root *yaml.Node, wf *Workflow) {
	if wf == nil || len(root.Content) == 0 {
		return
	}
	top := root.Content[0]
	jobs := mapNode(top, "jobs")
	if jobs == nil {
		return
	}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		jobName := jobs.Content[i].Value
		jobNode := jobs.Content[i+1]
		job, ok := wf.Jobs[jobName]
		if !ok {
			continue
		}
		stepsNode := mapNode(jobNode, "steps")
		if stepsNode == nil {
			continue
		}
		for idx, s := range stepsNode.Content {
			if idx >= len(job.Steps) {
				break
			}
			job.Steps[idx].Line = s.Line
			job.Steps[idx].Col = s.Column
			job.Steps[idx].RawNode = s
		}
	}
}

// attachReusablePositions walks the yaml.Node tree to populate wf.Reusables with
// line/col data for every job-level `uses:` that references a reusable workflow.
func attachReusablePositions(root *yaml.Node, wf *Workflow) {
	if wf == nil || len(root.Content) == 0 {
		return
	}
	top := root.Content[0]
	jobs := mapNode(top, "jobs")
	if jobs == nil {
		return
	}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		jobNode := jobs.Content[i+1]
		// Walk key-value pairs inside the job mapping looking for `uses`.
		if jobNode.Kind != yaml.MappingNode {
			continue
		}
		for j := 0; j+1 < len(jobNode.Content); j += 2 {
			keyNode := jobNode.Content[j]
			valNode := jobNode.Content[j+1]
			if keyNode.Value != "uses" {
				continue
			}
			uses := valNode.Value
			owner, repo, path, ref, ok := parseReusableUses(uses)
			if !ok {
				continue
			}
			wf.Reusables = append(wf.Reusables, ReusableUse{
				Owner: owner,
				Repo:  repo,
				Path:  path,
				Ref:   ref,
				Line:  valNode.Line,
				Col:   valNode.Column,
			})
		}
	}
}

func mapNode(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// Triggers returns the top-level event names (push, pull_request, ...).
func (w *Workflow) Triggers() []string {
	var out []string
	switch w.On.Kind {
	case yaml.ScalarNode:
		out = append(out, w.On.Value)
	case yaml.SequenceNode:
		for _, c := range w.On.Content {
			out = append(out, c.Value)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(w.On.Content); i += 2 {
			out = append(out, w.On.Content[i].Value)
		}
	}
	return out
}

// HasPermissions reports whether a permissions block exists at workflow or job level.
func (w *Workflow) HasPermissions() bool {
	return w.Permissions.Kind != 0
}
