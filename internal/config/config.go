// Package config loads ghactor's optional `.ghactor.yml` repo configuration.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"gopkg.in/yaml.v3"
)

type Severity string // "error" | "warning" | "info" | "none"

type Rule struct {
	Disabled bool     `yaml:"disabled,omitempty"`
	Severity Severity `yaml:"severity,omitempty"`
}

type Override struct {
	Paths   []string        `yaml:"paths"`
	Disable []string        `yaml:"disable,omitempty"`
	Rules   map[string]Rule `yaml:"rules,omitempty"`
}

type File struct {
	Version          int             `yaml:"version"`
	FailOn           Severity        `yaml:"fail-on,omitempty"`
	IgnoreActionlint bool            `yaml:"ignore-actionlint,omitempty"`
	Rules            map[string]Rule `yaml:"rules,omitempty"`
	Overrides        []Override      `yaml:"overrides,omitempty"`
	TrustedActions   []string        `yaml:"trusted-actions,omitempty"`
	DenyActions      []string        `yaml:"deny_actions,omitempty"`

	// Root is the directory the config was discovered from; used for path matching.
	Root string `yaml:"-"`
	Path string `yaml:"-"`
}

var candidates = []string{".ghactor.yml", ".ghactor.yaml", ".github/ghactor.yml"}

// Discover walks up from start until it finds a config file, the repo root (.git), or /.
func Discover(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		for _, name := range candidates {
			p := filepath.Join(dir, name)
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				return p, nil
			}
		}
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return "", nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", nil
		}
		dir = parent
	}
}

func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	f.Path = path
	f.Root = filepath.Dir(path)
	return &f, nil
}

// LoadAuto discovers + loads; returns (nil, nil) if no config found.
func LoadAuto(start string) (*File, error) {
	p, err := Discover(start)
	if err != nil || p == "" {
		return nil, err
	}
	return Load(p)
}

// RuleFor returns the effective rule settings for (id, relPath) after applying overrides.
func (f *File) RuleFor(id, relPath string) Rule {
	if f == nil {
		return Rule{}
	}
	r := f.Rules[id]
	rel := filepath.ToSlash(relPath)
	for _, ov := range f.Overrides {
		if !anyMatch(ov.Paths, rel) {
			continue
		}
		for _, d := range ov.Disable {
			if d == id {
				r.Disabled = true
			}
		}
		if more, ok := ov.Rules[id]; ok {
			if more.Disabled {
				r.Disabled = true
			}
			if more.Severity != "" {
				r.Severity = more.Severity
			}
		}
	}
	return r
}

// TrustsAction returns true if `uses` (`owner/repo[/path]@ref`) is covered by trusted-actions.
func (f *File) TrustsAction(uses string) bool {
	if f == nil {
		return false
	}
	name, ref, _ := strings.Cut(uses, "@")
	for _, pat := range f.TrustedActions {
		patName, patRef, hasRef := strings.Cut(pat, "@")
		ok, _ := doublestar.Match(patName, name)
		if !ok {
			continue
		}
		if !hasRef || patRef == ref {
			return true
		}
	}
	return false
}

func anyMatch(globs []string, p string) bool {
	for _, g := range globs {
		if ok, _ := doublestar.Match(g, p); ok {
			return true
		}
	}
	return false
}
