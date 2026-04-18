// Package config loads ghactor's optional `.ghactor.yml` repo configuration.
package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"gopkg.in/yaml.v3"
)

// Severity is the canonical set of severity values used in config files.
type Severity string

const (
	SevError   Severity = "error"
	SevWarning Severity = "warning"
	SevInfo    Severity = "info"
	// SevOff suppresses the rule entirely for a given scope.
	SevOff Severity = "off"
)

// canonicalSeverity normalises a user-supplied severity string to one of the
// four canonical values ("error", "warning", "info", "off") or returns an
// error for unrecognised strings.  Matching is case-insensitive.
func canonicalSeverity(raw string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "error", "err":
		return SevError, nil
	case "warning", "warn":
		return SevWarning, nil
	case "info", "information", "note":
		return SevInfo, nil
	case "off", "disable", "disabled", "none", "ignore":
		return SevOff, nil
	default:
		return "", fmt.Errorf("unknown severity %q: must be one of error, warning, info, off", raw)
	}
}

// Rule carries per-rule settings that can appear in the top-level `rules:`
// block or inside an `overrides[].rules:` block.
//
// Back-compat: YAML nodes that are plain booleans (e.g. `GHA005: false`) are
// decoded as {Disabled: true} via UnmarshalYAML.
type Rule struct {
	Disabled bool     `yaml:"disabled,omitempty"`
	Severity Severity `yaml:"severity,omitempty"`
}

// UnmarshalYAML decodes a Rule from YAML.  It accepts two forms:
//
//  1. Object form:  { severity: warning, disabled: false }
//  2. Boolean form: false  (legacy — treated as Disabled: true)
//     true  (legacy — treated as Disabled: false, no other effect)
func (r *Rule) UnmarshalYAML(value *yaml.Node) error {
	// Legacy boolean shorthand: `GHA005: false` means disabled.
	if value.Kind == yaml.ScalarNode && value.Tag == "!!bool" {
		v := strings.ToLower(value.Value)
		r.Disabled = (v == "false" || v == "0")
		return nil
	}

	// Object form — use an alias struct to avoid infinite recursion.
	type plain struct {
		Disabled bool   `yaml:"disabled,omitempty"`
		Severity string `yaml:"severity,omitempty"`
	}
	var p plain
	if err := value.Decode(&p); err != nil {
		return err
	}
	r.Disabled = p.Disabled
	if p.Severity != "" {
		canon, err := canonicalSeverity(p.Severity)
		if err != nil {
			return fmt.Errorf("rules[severity]: %w", err)
		}
		r.Severity = canon
	}
	return nil
}

// Override represents a set of rule adjustments that apply only when a
// workflow file path matches one of the listed globs.
type Override struct {
	Paths   []string        `yaml:"paths"`
	Disable []string        `yaml:"disable,omitempty"`
	Rules   map[string]Rule `yaml:"rules,omitempty"`
}

// File is the in-memory representation of `.ghactor.yml`.
type File struct {
	Version          int             `yaml:"version"`
	FailOn           Severity        `yaml:"fail-on,omitempty"`
	IgnoreActionlint bool            `yaml:"ignore-actionlint,omitempty"`
	Rules            map[string]Rule `yaml:"rules,omitempty"`
	Overrides        []Override      `yaml:"overrides,omitempty"`
	TrustedActions   []string        `yaml:"trusted-actions,omitempty"`
	DenyActions      []string        `yaml:"deny_actions,omitempty"`
	AllowActions     []string        `yaml:"allow_actions,omitempty"`

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

// Load reads and parses a config file at path.
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

// Validate checks the loaded config against a set of known rule IDs.  Any
// rule ID referenced in rules: or overrides[].rules: that is not in knownIDs
// is reported as a warning written to w (stderr in production).  Unknown
// severity values are caught earlier at unmarshal time and are hard errors;
// this method only produces soft warnings.
//
// Passing a nil or empty knownIDs slice skips rule-ID validation.
func (f *File) Validate(knownIDs []string, w io.Writer) {
	if f == nil || len(knownIDs) == 0 {
		return
	}
	known := make(map[string]bool, len(knownIDs))
	for _, id := range knownIDs {
		known[id] = true
	}

	// Collect all referenced IDs in insertion order, deduplicating.
	seen := map[string]bool{}
	var unknown []string
	check := func(id string) {
		if known[id] || seen[id] {
			return
		}
		seen[id] = true
		if !known[id] {
			unknown = append(unknown, id)
		}
	}

	for id := range f.Rules {
		check(id)
	}
	for _, ov := range f.Overrides {
		for id := range ov.Rules {
			check(id)
		}
	}

	if len(unknown) == 0 {
		return
	}

	sort.Strings(unknown)
	sorted := make([]string, len(knownIDs))
	copy(sorted, knownIDs)
	sort.Strings(sorted)
	fmt.Fprintf(w, "ghactor: config warning: unknown rule ID(s) in %s: %s\n  known IDs: %s\n",
		f.Path, strings.Join(unknown, ", "), strings.Join(sorted, ", "))
}

// RuleFor returns the effective rule settings for (id, relPath) after
// applying overrides.  Later overrides that match the path win over earlier
// ones, and all overrides win over the top-level rules: block.
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

// ResolvedSeverity returns the canonical effective severity string for (id,
// relPath).  Returns "" when no override applies; the caller should then use
// the rule's compiled-in default severity.
//
// The returned string is one of: "error", "warning", "info", "off", or "".
// "off" means the issue must be suppressed entirely.
func (f *File) ResolvedSeverity(id, relPath string) string {
	if f == nil {
		return ""
	}
	r := f.RuleFor(id, relPath)
	if r.Disabled {
		return string(SevOff)
	}
	return string(r.Severity)
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
