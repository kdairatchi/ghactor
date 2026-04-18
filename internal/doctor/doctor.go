// Package doctor produces a repo-wide workflow health report.
package doctor

import (
	"github.com/kdairatchi/ghactor/internal/lint"
	"github.com/kdairatchi/ghactor/internal/workflow"
)

type Report struct {
	Dir        string              `json:"dir"`
	Workflows  int                 `json:"workflows"`
	Jobs       int                 `json:"jobs"`
	Steps      int                 `json:"steps"`
	HealthScore int                `json:"score"`
	Issues     []lint.Issue        `json:"issues"`
	ByRule     map[string]int      `json:"by_rule"`
	BySeverity map[lint.Severity]int `json:"by_severity"`
}

func Scan(dir string) (*Report, error) {
	wfs, err := workflow.LoadDir(dir)
	if err != nil {
		return nil, err
	}
	issues, err := lint.RunWithOptions(lint.Options{Dir: dir})
	if err != nil {
		return nil, err
	}
	r := &Report{
		Dir: dir, Workflows: len(wfs),
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
	r.HealthScore = r.Score()
	return r, nil
}

// Score returns a 0-100 health score: 100 - weighted penalty per issue type.
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
