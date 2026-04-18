// Package gen implements the `ghactor gen` command: scaffold hardened GitHub
// Actions workflow templates with pinned SHAs, least-privilege permissions,
// and job-level timeouts baked in from day one.
package gen

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/spf13/cobra"
)

// Template describes a single scaffoldable template.
type Template struct {
	// Name is the CLI identifier (e.g. "ci-go").
	Name string
	// Description is a one-line human-readable summary shown in the list view.
	Description string
	// OutPath is the conventional output path relative to the repo root.
	// Used when --out is not provided and the caller asks for a suggestion.
	OutPath string
	// IsDependabot is true for the dependabot template which writes to
	// .github/dependabot.yml instead of .github/workflows/.
	IsDependabot bool
}

// Options controls rendering behaviour.
type Options struct {
	// Vars holds template variable overrides supplied via --var key=value flags.
	// Keys are compared case-insensitively when building the template data map.
	Vars map[string]string
}

// catalog is the static registry of all shipped templates.
// Templates are intentionally listed in a stable order for deterministic output.
var catalog = []Template{
	{
		Name:        "ci-go",
		Description: "Go test (race detector) + golangci-lint, two-job layout",
		OutPath:     ".github/workflows/ci.yml",
	},
	{
		Name:        "ci-node",
		Description: "Node/pnpm build + test + lint, two-job layout",
		OutPath:     ".github/workflows/ci.yml",
	},
	{
		Name:        "ci-python",
		Description: "Python pytest + ruff check/format, two-job layout",
		OutPath:     ".github/workflows/ci.yml",
	},
	{
		Name:        "codeql",
		Description: "CodeQL analysis with language matrix; security-events:write job-scoped only",
		OutPath:     ".github/workflows/codeql.yml",
	},
	{
		Name:        "release-goreleaser",
		Description: "Tag-triggered GoReleaser release with cosign keyless signing",
		OutPath:     ".github/workflows/release.yml",
	},
	{
		Name:        "attest-release",
		Description: "Tag-triggered release with SLSA build provenance via actions/attest-build-provenance",
		OutPath:     ".github/workflows/release.yml",
	},
	{
		Name:         "dependabot",
		Description:  "Dependabot config for gomod + github-actions + npm on weekly schedule",
		OutPath:      ".github/dependabot.yml",
		IsDependabot: true,
	},
	{
		Name:        "ghactor-self",
		Description: "Run ghactor lint --only-ghactor and upload SARIF to code scanning",
		OutPath:     ".github/workflows/ghactor.yml",
	},
}

// defaults holds sensible variable values used when the caller does not
// supply an override via --var.
var defaults = map[string]string{
	"GoVersion":     "1.23",
	"NodeVersion":   "22",
	"PythonVersion": "3.12",
	"Language":      "go",
	"BinaryName":    "app",
}

// Templates returns the full list of available templates.
func Templates() []Template {
	out := make([]Template, len(catalog))
	copy(out, catalog)
	return out
}

// Render executes the named template with the given options and returns the
// rendered YAML as a string.  If name is unknown it returns an error that
// includes the list of valid names.
func Render(name string, opts Options) (string, error) {
	tmpl, ok := find(name)
	if !ok {
		return "", unknownTemplateError(name)
	}

	raw, err := templateFS.ReadFile(filepath.Join("templates", tmpl.Name+".yml"))
	if err != nil {
		return "", fmt.Errorf("gen: read embedded template %q: %w", name, err)
	}

	data := buildData(opts.Vars)

	// Use [[ ]] delimiters so GitHub Actions ${{ }} expressions pass through
	// unchanged without conflicting with Go's text/template syntax.
	t, err := template.New(name).Delims("[[", "]]").Option("missingkey=zero").Parse(string(raw))
	if err != nil {
		return "", fmt.Errorf("gen: parse template %q: %w", name, err)
	}

	var sb strings.Builder
	if err := t.Execute(&sb, data); err != nil {
		return "", fmt.Errorf("gen: render template %q: %w", name, err)
	}
	return sb.String(), nil
}

// find looks up a template by exact name match (case-insensitive).
func find(name string) (Template, bool) {
	lower := strings.ToLower(name)
	for _, t := range catalog {
		if strings.ToLower(t.Name) == lower {
			return t, true
		}
	}
	return Template{}, false
}

// buildData merges caller-supplied vars on top of the defaults and returns a
// map suitable for use as template data.  Keys are normalised to title-case
// (e.g. "goversion" → "GoVersion") by resolving against the defaults map.
func buildData(overrides map[string]string) map[string]string {
	data := make(map[string]string, len(defaults))
	for k, v := range defaults {
		data[k] = v
	}
	// Apply overrides with case-insensitive key resolution.
	for k, v := range overrides {
		resolved := resolveKey(k)
		data[resolved] = v
	}
	return data
}

// resolveKey maps a caller-supplied key (any case) to the canonical title-case
// key used in templates.  If no canonical match is found the key is used as-is
// so that ad-hoc variables still work.
func resolveKey(k string) string {
	lower := strings.ToLower(k)
	for canon := range defaults {
		if strings.ToLower(canon) == lower {
			return canon
		}
	}
	// Title-case the first letter so {{.myVar}} works from --var myvar=x.
	if len(k) == 0 {
		return k
	}
	return strings.ToUpper(k[:1]) + k[1:]
}

// unknownTemplateError builds a descriptive error listing valid names.
func unknownTemplateError(name string) error {
	names := make([]string, 0, len(catalog))
	for _, t := range catalog {
		names = append(names, t.Name)
	}
	sort.Strings(names)
	return fmt.Errorf("unknown template %q\n\nAvailable templates:\n  %s",
		name, strings.Join(names, "\n  "))
}

// listAll enumerates embedded template files for cross-checking; used in tests.
func listAll() ([]string, error) {
	var names []string
	err := fs.WalkDir(templateFS, "templates", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		base := strings.TrimSuffix(filepath.Base(p), filepath.Ext(p))
		names = append(names, base)
		return nil
	})
	return names, err
}

// Cmd returns the cobra.Command for `ghactor gen`.
func Cmd() *cobra.Command {
	var (
		outPath string
		force   bool
		vars    []string
	)

	cmd := &cobra.Command{
		Use:   "gen [template]",
		Short: "Scaffold hardened GitHub Actions workflows",
		Long: `Scaffold secure, opinionated GitHub Actions workflow YAML with pinned
SHAs, least-privilege permissions, and job-level timeouts.

Without a template argument, lists all available templates.

Examples:
  ghactor gen
  ghactor gen ci-go
  ghactor gen ci-go -o .github/workflows/ci.yml
  ghactor gen ci-go --force
  ghactor gen ci-go --var GoVersion=1.22
  ghactor gen codeql --var Language=javascript
  ghactor gen dependabot -o .github/dependabot.yml`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// No argument: print template list.
			if len(args) == 0 {
				return runList(cmd)
			}

			name := args[0]
			tmpl, ok := find(name)
			if !ok {
				return unknownTemplateError(name)
			}

			parsed, err := parseVars(vars)
			if err != nil {
				return err
			}

			rendered, err := Render(name, Options{Vars: parsed})
			if err != nil {
				return err
			}

			// Determine output destination.
			dest := outPath
			if dest == "" {
				// Print to stdout.
				fmt.Fprint(cmd.OutOrStdout(), rendered)
				return nil
			}

			return writeFile(dest, rendered, force, tmpl)
		},
	}

	cmd.Flags().StringVarP(&outPath, "out", "o", "", "write output to FILE instead of stdout")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite FILE if it already exists (requires --out)")
	cmd.Flags().StringArrayVar(&vars, "var", nil, "template variable override as key=value (repeatable)")

	return cmd
}

// runList prints the table of available templates.
func runList(cmd *cobra.Command) error {
	w := cmd.OutOrStdout()
	fmt.Fprintln(w, "Available templates (ghactor gen <name>):")
	fmt.Fprintln(w)
	for _, t := range catalog {
		fmt.Fprintf(w, "  %-24s  %s\n", t.Name, t.Description)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags: -o FILE (write to path)  --force (overwrite)  --var key=value")
	return nil
}

// parseVars converts []string "key=value" pairs into a map.
func parseVars(raw []string) (map[string]string, error) {
	m := make(map[string]string, len(raw))
	for _, kv := range raw {
		idx := strings.IndexByte(kv, '=')
		if idx < 1 {
			return nil, fmt.Errorf("--var %q: expected key=value format", kv)
		}
		m[kv[:idx]] = kv[idx+1:]
	}
	return m, nil
}

// writeFile writes content to dest, respecting the force flag.
func writeFile(dest, content string, force bool, tmpl Template) error {
	if !force {
		if _, err := os.Stat(dest); err == nil {
			return fmt.Errorf("file already exists: %s (use --force to overwrite)", dest)
		}
	}

	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("gen: create directory %s: %w", dir, err)
	}

	if err := os.WriteFile(dest, []byte(content), 0o644); err != nil {
		return fmt.Errorf("gen: write %s: %w", dest, err)
	}

	fmt.Printf("wrote %s\n", dest)
	if !tmpl.IsDependabot {
		fmt.Printf("tip: run `ghactor lint --dir %s --only-ghactor` to verify\n",
			filepath.Dir(dest))
	}
	return nil
}
