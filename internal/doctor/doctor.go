// Package doctor produces a repo-wide workflow health report.
package doctor

import (
	"encoding/json"

	"github.com/kdairatchi/ghactor/internal/config"
	"github.com/kdairatchi/ghactor/internal/lint"
	"github.com/kdairatchi/ghactor/internal/workflow"
)

// Report holds the results of a Scan. The score field is computed on demand
// via Score() and is injected into JSON output through MarshalJSON — there is
// no stored HealthScore field; Score() is the single source of truth.
type Report struct {
	Dir        string                `json:"dir"`
	ConfigPath string                `json:"config_path"`
	Workflows  int                   `json:"workflows"`
	Jobs       int                   `json:"jobs"`
	Steps      int                   `json:"steps"`
	Issues     []lint.Issue          `json:"issues"`
	ByRule     map[string]int        `json:"by_rule"`
	BySeverity map[lint.Severity]int `json:"by_severity"`
}

// MarshalJSON produces the canonical JSON shape, injecting the computed score
// alongside all other fields so there is a single source of truth.
func (r *Report) MarshalJSON() ([]byte, error) {
	type alias Report // prevent infinite recursion
	type withScore struct {
		alias
		Score int `json:"score"`
	}
	return json.Marshal(withScore{
		alias: alias(*r),
		Score: r.Score(),
	})
}

// Scan loads all workflows under dir, runs lint rules, and returns a Report.
// It also attempts to discover a .ghactor.yml via config.LoadAuto and records
// the config path (empty string when none is found) in Report.ConfigPath.
func Scan(dir string) (*Report, error) {
	wfs, err := workflow.LoadDir(dir)
	if err != nil {
		return nil, err
	}

	cfg, err := config.LoadAuto(dir)
	if err != nil {
		return nil, err
	}
	var configPath string
	if cfg != nil {
		configPath = cfg.Path
	}

	issues, err := lint.RunWithOptions(lint.Options{Dir: dir, Config: cfg})
	if err != nil {
		return nil, err
	}

	r := &Report{
		Dir:        dir,
		ConfigPath: configPath,
		Workflows:  len(wfs),
		ByRule:     map[string]int{},
		BySeverity: map[lint.Severity]int{},
		Issues:     issues,
	}
	for _, wf := range wfs {
		r.Jobs += len(wf.WF.Jobs)
		for _, j := range wf.WF.Jobs {
			r.Steps += len(j.Steps)
		}
	}
	for _, i := range issues {
		r.ByRule[i.Kind]++
		r.BySeverity[i.Severity]++
	}
	return r, nil
}

// Score returns a 0-100 health score: 100 minus weighted penalty per issue.
func (r *Report) Score() int {
	if r.Steps == 0 {
		return 100
	}
	penalty := r.BySeverity[lint.SevError]*10 + r.BySeverity[lint.SevWarning]*3 + r.BySeverity[lint.SevInfo]*1
	score := 100 - penalty
	if score < 0 {
		score = 0
	}
	return score
}
