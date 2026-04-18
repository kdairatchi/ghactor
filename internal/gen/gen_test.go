package gen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kdairatchi/ghactor/internal/lint"
)

// TestTemplatesRenderWithoutError verifies every template in the catalog
// renders successfully with default options.
func TestTemplatesRenderWithoutError(t *testing.T) {
	t.Parallel()
	for _, tmpl := range Templates() {
		tmpl := tmpl
		t.Run(tmpl.Name, func(t *testing.T) {
			t.Parallel()
			got, err := Render(tmpl.Name, Options{})
			if err != nil {
				t.Fatalf("Render(%q) error: %v", tmpl.Name, err)
			}
			if strings.TrimSpace(got) == "" {
				t.Fatalf("Render(%q) returned empty output", tmpl.Name)
			}
		})
	}
}

// TestEmbeddedFilesMatchCatalog checks that every embedded .yml file has a
// corresponding catalog entry and vice-versa.
func TestEmbeddedFilesMatchCatalog(t *testing.T) {
	t.Parallel()

	embedded, err := listAll()
	if err != nil {
		t.Fatalf("listAll: %v", err)
	}

	embSet := make(map[string]bool, len(embedded))
	for _, n := range embedded {
		embSet[n] = true
	}

	catSet := make(map[string]bool, len(catalog))
	for _, c := range catalog {
		catSet[c.Name] = true
	}

	for _, c := range catalog {
		if !embSet[c.Name] {
			t.Errorf("catalog entry %q has no embedded template file", c.Name)
		}
	}
	for _, e := range embedded {
		if !catSet[e] {
			t.Errorf("embedded file %q.yml has no catalog entry", e)
		}
	}
}

// lintExemptions lists per-template rule IDs that are structurally unavoidable
// and therefore exempt from the zero-findings gate.  Each entry must include a
// rationale comment so future reviewers understand the decision.
//
// GHA019 (oidc-no-subject) fires on every workflow that includes
// id-token: write, which the release-goreleaser template requires for cosign
// keyless signing.  The sub-claim constraint lives in the cloud provider's IAM
// trust policy — it cannot be expressed inside the workflow YAML itself.
// The finding is an advisory reminder, not a structural defect in the template.
var lintExemptions = map[string][]string{
	"release-goreleaser": {"GHA019"},
	"attest-release":     {"GHA019"}, // same rationale as release-goreleaser — id-token: write is required for Sigstore keyless signing
}

// TestTemplatesPassGhactorLint is the anti-regression gate: every workflow
// template (non-dependabot) must render and produce zero ghactor lint findings,
// modulo the exemptions listed in lintExemptions.
func TestTemplatesPassGhactorLint(t *testing.T) {
	t.Parallel()
	for _, tmpl := range Templates() {
		if tmpl.IsDependabot {
			// dependabot.yml is not a workflow; skip lint.
			continue
		}
		tmpl := tmpl
		t.Run(tmpl.Name, func(t *testing.T) {
			t.Parallel()

			rendered, err := Render(tmpl.Name, Options{})
			if err != nil {
				t.Fatalf("Render(%q): %v", tmpl.Name, err)
			}

			// Write to a temp directory that looks like .github/workflows/.
			tmp := t.TempDir()
			wfDir := filepath.Join(tmp, ".github", "workflows")
			if err := os.MkdirAll(wfDir, 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			dest := filepath.Join(wfDir, tmpl.Name+".yml")
			if err := os.WriteFile(dest, []byte(rendered), 0o644); err != nil {
				t.Fatalf("write workflow: %v", err)
			}

			issues, err := lint.RunWithOptions(lint.Options{
				Dir:              wfDir,
				IgnoreActionlint: true, // ghactor rules only; no actionlint network calls
				DisabledRules:    lintExemptions[tmpl.Name],
			})
			if err != nil {
				t.Fatalf("lint.RunWithOptions: %v", err)
			}

			if len(issues) > 0 {
				t.Errorf("template %q produced %d ghactor lint finding(s):", tmpl.Name, len(issues))
				for _, iss := range issues {
					t.Errorf("  %s:%d:%d [%s] %s (%s)",
						filepath.Base(iss.File), iss.Line, iss.Col,
						iss.Kind, iss.Message, iss.Severity)
				}
			}
		})
	}
}

// TestVarSubstitution verifies that --var overrides are applied to the rendered output.
func TestVarSubstitution(t *testing.T) {
	t.Parallel()

	tests := []struct {
		template string
		varKey   string
		varVal   string
		want     string
	}{
		{
			template: "ci-go",
			varKey:   "GoVersion",
			varVal:   "1.22",
			want:     "1.22",
		},
		{
			template: "ci-node",
			varKey:   "NodeVersion",
			varVal:   "20",
			want:     "20",
		},
		{
			template: "ci-python",
			varKey:   "PythonVersion",
			varVal:   "3.11",
			want:     "3.11",
		},
		{
			template: "codeql",
			varKey:   "Language",
			varVal:   "javascript",
			want:     "javascript",
		},
		{
			template: "ghactor-self",
			varKey:   "GoVersion",
			varVal:   "1.21",
			want:     "1.21",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.template+"/"+tc.varKey, func(t *testing.T) {
			t.Parallel()
			got, err := Render(tc.template, Options{
				Vars: map[string]string{tc.varKey: tc.varVal},
			})
			if err != nil {
				t.Fatalf("Render: %v", err)
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("rendered output does not contain %q\n\nFull output:\n%s", tc.want, got)
			}
		})
	}
}

// TestVarSubstitutionCaseInsensitive confirms that key lookup is case-insensitive.
func TestVarSubstitutionCaseInsensitive(t *testing.T) {
	t.Parallel()
	got, err := Render("ci-go", Options{Vars: map[string]string{"goversion": "1.20"}})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(got, "1.20") {
		t.Errorf("case-insensitive var lookup failed; want 1.20 in output:\n%s", got)
	}
}

// TestWriteFileExistsWithoutForce verifies that writing to an existing file
// without --force returns an error.
func TestWriteFileExistsWithoutForce(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	dest := filepath.Join(tmp, "ci.yml")
	if err := os.WriteFile(dest, []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := writeFile(dest, "new content", false, catalog[0])
	if err == nil {
		t.Fatal("expected error when writing to existing file without --force, got nil")
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Errorf("error message should mention --force; got: %v", err)
	}

	// Confirm original content untouched.
	b, _ := os.ReadFile(dest)
	if string(b) != "existing" {
		t.Errorf("file was modified despite no --force; content: %s", b)
	}
}

// TestWriteFileExistsWithForce verifies that --force overwrites existing files.
func TestWriteFileExistsWithForce(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	dest := filepath.Join(tmp, "ci.yml")
	if err := os.WriteFile(dest, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := writeFile(dest, "new", true, catalog[0]); err != nil {
		t.Fatalf("writeFile with force: %v", err)
	}

	b, _ := os.ReadFile(dest)
	if string(b) != "new" {
		t.Errorf("expected new content after force overwrite; got: %s", b)
	}
}

// TestUnknownTemplateError verifies error message format.
func TestUnknownTemplateError(t *testing.T) {
	t.Parallel()

	_, err := Render("nonexistent-template", Options{})
	if err == nil {
		t.Fatal("expected error for unknown template, got nil")
	}

	msg := err.Error()
	if !strings.Contains(msg, "nonexistent-template") {
		t.Errorf("error should mention the unknown template name; got: %v", err)
	}
	// Should list available templates.
	if !strings.Contains(msg, "ci-go") {
		t.Errorf("error should list available templates; got: %v", err)
	}
}

// TestParseVars verifies the --var flag parser.
func TestParseVars(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     []string
		want    map[string]string
		wantErr bool
	}{
		{
			name: "single",
			raw:  []string{"GoVersion=1.22"},
			want: map[string]string{"GoVersion": "1.22"},
		},
		{
			name: "multiple",
			raw:  []string{"GoVersion=1.22", "Language=javascript"},
			want: map[string]string{"GoVersion": "1.22", "Language": "javascript"},
		},
		{
			name: "value with equals",
			raw:  []string{"key=val=ue"},
			want: map[string]string{"key": "val=ue"},
		},
		{
			name:    "missing equals",
			raw:     []string{"noequals"},
			wantErr: true,
		},
		{
			name:    "empty key",
			raw:     []string{"=value"},
			wantErr: true,
		},
		{
			name: "empty input",
			raw:  nil,
			want: map[string]string{},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseVars(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil (result: %v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Errorf("len mismatch: got %d want %d", len(got), len(tc.want))
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("key %q: got %q want %q", k, got[k], v)
				}
			}
		})
	}
}

// TestReleaseGoreleaserHasRequiredPermissions spot-checks the release template
// for job-level permission escalation.
func TestReleaseGoreleaserHasRequiredPermissions(t *testing.T) {
	t.Parallel()
	got, err := Render("release-goreleaser", Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"contents: write", "packages: write", "id-token: write"} {
		if !strings.Contains(got, want) {
			t.Errorf("release-goreleaser template missing %q", want)
		}
	}
	// Workflow-level should be contents: read.
	if !strings.Contains(got, "contents: read") {
		t.Error("release-goreleaser template: expected workflow-level contents: read")
	}
}

// TestDependabotNotAWorkflow confirms the dependabot template does not contain
// workflow-specific keys like "on:" or "jobs:".
func TestDependabotNotAWorkflow(t *testing.T) {
	t.Parallel()
	got, err := Render("dependabot", Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"jobs:", "runs-on:", "steps:"} {
		if strings.Contains(got, bad) {
			t.Errorf("dependabot template should not contain workflow key %q", bad)
		}
	}
	if !strings.Contains(got, "version: 2") {
		t.Error("dependabot template: expected 'version: 2'")
	}
}

// TestAllTemplatesSHAPinned verifies that every action reference in workflow
// templates uses a 40-char SHA (no floating tags).
func TestAllTemplatesSHAPinned(t *testing.T) {
	t.Parallel()

	// Matches `uses: owner/repo@<ref>` — the ref must be a 40-hex SHA.
	shaRE := func(line string) bool {
		idx := strings.Index(line, "uses:")
		if idx < 0 {
			return true // not a uses line
		}
		atIdx := strings.LastIndex(line, "@")
		if atIdx < 0 {
			return false
		}
		ref := line[atIdx+1:]
		// Strip trailing comment.
		if ci := strings.Index(ref, "#"); ci >= 0 {
			ref = strings.TrimSpace(ref[:ci])
		}
		ref = strings.TrimSpace(ref)
		if len(ref) != 40 {
			return false
		}
		for _, c := range ref {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return false
			}
		}
		return true
	}

	for _, tmpl := range Templates() {
		if tmpl.IsDependabot {
			continue
		}
		tmpl := tmpl
		t.Run(tmpl.Name, func(t *testing.T) {
			t.Parallel()
			rendered, err := Render(tmpl.Name, Options{})
			if err != nil {
				t.Fatalf("Render: %v", err)
			}
			for i, line := range strings.Split(rendered, "\n") {
				if !shaRE(line) {
					t.Errorf("line %d: action not pinned to 40-char SHA: %s", i+1, strings.TrimSpace(line))
				}
			}
		})
	}
}
