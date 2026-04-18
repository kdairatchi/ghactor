// Package update compares action uses: against latest releases and optionally rewrites them.
package update

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"text/template"

	"github.com/kdairatchi/ghactor/internal/deps"
	"github.com/kdairatchi/ghactor/internal/pin"
	"github.com/kdairatchi/ghactor/internal/workflow"
)

type Update struct {
	File      string // one representative file
	Key       string // owner/repo[/path]
	Owner     string
	Repo      string
	CurRef    string
	CurSHA    string
	LatestTag string
	LatestSHA string
	SameMajor bool
	Drift     bool
	Skip      bool
	Reason    string
	Err       string
}

type site struct {
	file, key, owner, repo, ref string
}

type Options struct {
	Dir         string
	AllowMajor  bool
	Concurrency int
}

func Scan(opts Options, res *pin.Resolver) ([]Update, error) {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 4
	}
	files, err := workflow.LoadDir(opts.Dir)
	if err != nil {
		return nil, err
	}
	sites := collectSites(files)
	updates := make([]Update, len(sites))
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	for i, s := range sites {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, s site) {
			defer wg.Done()
			defer func() { <-sem }()
			updates[i] = inspect(s, res, opts.AllowMajor)
		}(i, s)
	}
	wg.Wait()
	return updates, nil
}

func collectSites(files []*workflow.File) []site {
	seen := map[string]bool{}
	var out []site
	for _, f := range files {
		for _, j := range f.WF.Jobs {
			for _, s := range j.Steps {
				if s == nil || s.Uses == "" {
					continue
				}
				if strings.HasPrefix(s.Uses, "./") || strings.HasPrefix(s.Uses, "docker://") {
					continue
				}
				at := strings.LastIndex(s.Uses, "@")
				if at < 0 {
					continue
				}
				key := s.Uses[:at]
				if seen[key] {
					continue
				}
				seen[key] = true
				parts := strings.SplitN(key, "/", 3)
				if len(parts) < 2 {
					continue
				}
				out = append(out, site{
					file: f.Path, key: key, owner: parts[0], repo: parts[1], ref: s.Uses[at+1:],
				})
			}
		}
	}
	return out
}

func inspect(s site, res *pin.Resolver, allowMajor bool) Update {
	u := Update{File: s.file, Key: s.key, Owner: s.owner, Repo: s.repo, CurRef: s.ref}
	if sha, err := res.Resolve(s.owner, s.repo, s.ref); err == nil {
		u.CurSHA = sha
	}

	tag, err := deps.LatestTag(s.owner, s.repo)
	if err != nil {
		tags, terr := deps.Tags(s.owner, s.repo)
		if terr != nil || len(tags) == 0 {
			u.Reason = "no-release-or-tag"
			u.Err = err.Error()
			return u
		}
		tag = deps.PickHighestSemver(tags)
		u.Reason = "tags-fallback"
	}

	u.LatestTag = tag
	curMaj := deps.LatestMajor(s.ref)
	newMaj := deps.LatestMajor(tag)
	u.SameMajor = curMaj == newMaj
	if !u.SameMajor && !allowMajor {
		u.Skip = true
		if u.Reason == "" {
			u.Reason = "skipped-major"
		}
		return u
	}
	if sha, err := res.Resolve(s.owner, s.repo, tag); err == nil {
		u.LatestSHA = sha
	}
	u.Drift = u.LatestSHA != "" && u.LatestSHA != u.CurSHA
	return u
}

// Apply rewrites each workflow file, pinning each applicable Update to LatestSHA (tagged # LatestTag).
func Apply(dir string, updates []Update, dry bool) ([]pin.Change, error) {
	targets := map[string]pin.Pinned{}
	for _, u := range updates {
		if u.Skip || !u.Drift || u.LatestSHA == "" {
			continue
		}
		targets[u.Key] = pin.Pinned{SHA: u.LatestSHA, Tag: u.LatestTag}
	}
	if len(targets) == 0 {
		return nil, nil
	}
	files, err := workflow.LoadDir(dir)
	if err != nil {
		return nil, err
	}
	var all []pin.Change
	for _, f := range files {
		changes, _, err := pin.RewriteFileTo(f.Path, f.Source, targets, dry)
		if err != nil {
			return all, err
		}
		all = append(all, changes...)
	}
	return all, nil
}

const changelogTmpl = `## Action updates

| Action | From | To | Compare |
|---|---|---|---|
{{- range . }}{{ if and (not .Skip) .Drift }}
| ` + "`{{.Key}}`" + ` | ` + "`{{.CurRef}}`" + ` ({{shortSHA .CurSHA}}) | ` + "`{{.LatestTag}}`" + ` ({{shortSHA .LatestSHA}}) | [{{.CurRef}}…{{.LatestTag}}](https://github.com/{{.Owner}}/{{.Repo}}/compare/{{.CurRef}}...{{.LatestTag}}) |
{{- end }}{{ end }}
{{ with skipped . }}
<details><summary>Skipped major bumps ({{len .}})</summary>

{{ range . }}- ` + "`{{.Key}}`" + ` {{.CurRef}} → {{.LatestTag}} (re-run with --major)
{{ end }}
</details>
{{ end }}
`

// WriteChangelog writes a Markdown summary suitable for a PR body.
func WriteChangelog(w io.Writer, updates []Update) error {
	funcs := template.FuncMap{
		"shortSHA": func(s string) string {
			if len(s) >= 7 {
				return s[:7]
			}
			return s
		},
		"skipped": func(us []Update) []Update {
			var out []Update
			for _, u := range us {
				if u.Skip {
					out = append(out, u)
				}
			}
			return out
		},
	}
	t, err := template.New("cl").Funcs(funcs).Parse(changelogTmpl)
	if err != nil {
		return err
	}
	return t.Execute(w, updates)
}

// WriteChangelogFile is a thin convenience wrapper.
func WriteChangelogFile(path string, updates []Update) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return WriteChangelog(f, updates)
}

// Sentinel so callers can detect "no drift, nothing to do".
var ErrNoDrift = fmt.Errorf("no drift")
