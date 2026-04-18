package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func mustLoad(t *testing.T, yaml string) *File {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, ".ghactor.yml")
	if err := os.WriteFile(p, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return f
}

func mustLoadErr(t *testing.T, yaml string) error {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, ".ghactor.yml")
	if err := os.WriteFile(p, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(p)
	return err
}

// ---------------------------------------------------------------------------
// Severity canonicalization
// ---------------------------------------------------------------------------

func TestCanonicalSeverity(t *testing.T) {
	cases := []struct {
		in   string
		want Severity
	}{
		// canonical forms
		{"error", SevError},
		{"warning", SevWarning},
		{"info", SevInfo},
		{"off", SevOff},
		// aliases — case insensitive
		{"ERROR", SevError},
		{"err", SevError},
		{"WARNING", SevWarning},
		{"warn", SevWarning},
		{"WARN", SevWarning},
		{"INFO", SevInfo},
		{"information", SevInfo},
		{"note", SevInfo},
		{"OFF", SevOff},
		{"disable", SevOff},
		{"disabled", SevOff},
		{"none", SevOff},
		{"ignore", SevOff},
		{"NONE", SevOff},
	}
	for _, tc := range cases {
		got, err := canonicalSeverity(tc.in)
		if err != nil {
			t.Errorf("canonicalSeverity(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("canonicalSeverity(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCanonicalSeverityUnknown(t *testing.T) {
	for _, bad := range []string{"blocker", "critical", "FATAL", "", "  "} {
		_, err := canonicalSeverity(bad)
		if err == nil {
			t.Errorf("canonicalSeverity(%q): expected error, got nil", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// YAML parse: severity aliases canonicalized at load time
// ---------------------------------------------------------------------------

func TestYAMLSeverityAliasesCanonicalized(t *testing.T) {
	f := mustLoad(t, `
version: 1
rules:
  GHA019:
    severity: warn
  GHA005:
    severity: INFO
  GHA001:
    severity: none
`)
	if got := f.Rules["GHA019"].Severity; got != SevWarning {
		t.Errorf("GHA019 severity = %q, want %q", got, SevWarning)
	}
	if got := f.Rules["GHA005"].Severity; got != SevInfo {
		t.Errorf("GHA005 severity = %q, want %q", got, SevInfo)
	}
	if got := f.Rules["GHA001"].Severity; got != SevOff {
		t.Errorf("GHA001 severity = %q, want %q", got, SevOff)
	}
}

// ---------------------------------------------------------------------------
// YAML parse: unknown severity is a hard error
// ---------------------------------------------------------------------------

func TestYAMLUnknownSeverityIsError(t *testing.T) {
	err := mustLoadErr(t, `
version: 1
rules:
  GHA005:
    severity: blocker
`)
	if err == nil {
		t.Fatal("expected parse error for unknown severity, got nil")
	}
	if !strings.Contains(err.Error(), "blocker") {
		t.Errorf("error %q should mention the bad value 'blocker'", err.Error())
	}
}

// ---------------------------------------------------------------------------
// YAML parse: back-compat boolean form
// ---------------------------------------------------------------------------

func TestYAMLBooleanBackCompat(t *testing.T) {
	f := mustLoad(t, `
version: 1
rules:
  GHA005: false
  GHA001: true
`)
	if !f.Rules["GHA005"].Disabled {
		t.Error("GHA005: false should produce Disabled=true")
	}
	if f.Rules["GHA001"].Disabled {
		t.Error("GHA001: true should produce Disabled=false")
	}
}

// ---------------------------------------------------------------------------
// Validate: unknown rule ID warns but does not fail
// ---------------------------------------------------------------------------

func TestValidateUnknownRuleIDWarns(t *testing.T) {
	f := mustLoad(t, `
version: 1
rules:
  GHA999:
    severity: warning
  GHA001:
    severity: error
`)
	var buf bytes.Buffer
	known := []string{"GHA001", "GHA002", "GHA003"}
	f.Validate(known, &buf)
	out := buf.String()
	if !strings.Contains(out, "GHA999") {
		t.Errorf("expected warning for GHA999, got: %q", out)
	}
	// GHA001 is known — should not appear in the warning
	if strings.Contains(out, "GHA001") && !strings.Contains(out, "known IDs") {
		// GHA001 should only appear in the "known IDs" list, not the "unknown" list
		if strings.Index(out, "GHA001") < strings.Index(out, "known IDs") {
			t.Errorf("GHA001 appeared in unknown-IDs section: %q", out)
		}
	}
}

func TestValidateUnknownRuleIDInOverride(t *testing.T) {
	f := mustLoad(t, `
version: 1
overrides:
  - paths: ["release*.yml"]
    rules:
      GHA999:
        severity: warning
`)
	var buf bytes.Buffer
	f.Validate([]string{"GHA001"}, &buf)
	if !strings.Contains(buf.String(), "GHA999") {
		t.Errorf("expected warning for GHA999 in override, got: %q", buf.String())
	}
}

func TestValidateNoKnownIDsSkips(t *testing.T) {
	f := mustLoad(t, `version: 1`)
	var buf bytes.Buffer
	// Should not panic or write anything
	f.Validate(nil, &buf)
	if buf.Len() != 0 {
		t.Errorf("expected no output when knownIDs is nil, got: %q", buf.String())
	}
}

func TestValidateNilFileIsSafe(t *testing.T) {
	var f *File
	var buf bytes.Buffer
	// Must not panic.
	f.Validate([]string{"GHA001"}, &buf)
}

// ---------------------------------------------------------------------------
// ResolvedSeverity precedence
// ---------------------------------------------------------------------------

func TestResolvedSeverityNoConfig(t *testing.T) {
	var f *File
	if got := f.ResolvedSeverity("GHA001", "ci.yml"); got != "" {
		t.Errorf("nil config should return empty string, got %q", got)
	}
}

func TestResolvedSeverityTopLevelOverride(t *testing.T) {
	f := mustLoad(t, `
version: 1
rules:
  GHA005:
    severity: error
`)
	if got := f.ResolvedSeverity("GHA005", "any.yml"); got != "error" {
		t.Errorf("expected \"error\", got %q", got)
	}
	// Rule not mentioned → empty string
	if got := f.ResolvedSeverity("GHA001", "any.yml"); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestResolvedSeverityOffDisablesBothWays(t *testing.T) {
	// Via severity: off
	f1 := mustLoad(t, `
version: 1
rules:
  GHA001:
    severity: off
`)
	if got := f1.ResolvedSeverity("GHA001", "ci.yml"); got != "off" {
		t.Errorf("severity:off should resolve to \"off\", got %q", got)
	}

	// Via disabled: true
	f2 := mustLoad(t, `
version: 1
rules:
  GHA001:
    disabled: true
`)
	if got := f2.ResolvedSeverity("GHA001", "ci.yml"); got != "off" {
		t.Errorf("disabled:true should resolve to \"off\", got %q", got)
	}
}

func TestResolvedSeverityOverrideBeatsTopLevel(t *testing.T) {
	f := mustLoad(t, `
version: 1
rules:
  GHA019:
    severity: info
overrides:
  - paths: ["release*.yml"]
    rules:
      GHA019:
        severity: warning
`)
	// Non-matching path → top-level wins
	if got := f.ResolvedSeverity("GHA019", "ci.yml"); got != "info" {
		t.Errorf("non-matching: expected \"info\", got %q", got)
	}
	// Matching path → override wins
	if got := f.ResolvedSeverity("GHA019", "release-prod.yml"); got != "warning" {
		t.Errorf("matching path: expected \"warning\", got %q", got)
	}
}

func TestResolvedSeverityLastOverrideWins(t *testing.T) {
	// Two overrides both match; the later one should win.
	f := mustLoad(t, `
version: 1
overrides:
  - paths: ["*.yml"]
    rules:
      GHA005:
        severity: info
  - paths: ["release*.yml"]
    rules:
      GHA005:
        severity: error
`)
	if got := f.ResolvedSeverity("GHA005", "release-v2.yml"); got != "error" {
		t.Errorf("last override should win, got %q", got)
	}
	// Only the first override matches this path.
	if got := f.ResolvedSeverity("GHA005", "ci.yml"); got != "info" {
		t.Errorf("first override, got %q", got)
	}
}

func TestResolvedSeverityOffInOverrideOnlyForMatchingPaths(t *testing.T) {
	f := mustLoad(t, `
version: 1
rules:
  GHA019:
    severity: warning
overrides:
  - paths: ["release*.yml"]
    rules:
      GHA019:
        severity: off
`)
	// Non-matching → warning from top-level
	if got := f.ResolvedSeverity("GHA019", "ci.yml"); got != "warning" {
		t.Errorf("non-matching path: expected \"warning\", got %q", got)
	}
	// Matching → suppressed
	if got := f.ResolvedSeverity("GHA019", "release-prod.yml"); got != "off" {
		t.Errorf("matching path: expected \"off\", got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Legacy README-documented shape back-compat
// ---------------------------------------------------------------------------

func TestLegacyDocumentedShapeStillParses(t *testing.T) {
	// Shape from the original README: boolean disable + trusted-actions + fail-on
	f := mustLoad(t, `
version: 1
fail-on: error
ignore-actionlint: false
trusted-actions:
  - actions/*
  - docker/*@v3
deny_actions:
  - evil/action@v1
rules:
  GHA005:
    disabled: true
overrides:
  - paths: [".github/workflows/release-*.yml"]
    disable:
      - GHA001
`)
	if f.Version != 1 {
		t.Errorf("version: want 1, got %d", f.Version)
	}
	if f.FailOn != SevError {
		t.Errorf("fail-on: want error, got %q", f.FailOn)
	}
	if !f.Rules["GHA005"].Disabled {
		t.Error("GHA005.disabled should be true")
	}
	if len(f.TrustedActions) != 2 {
		t.Errorf("trusted-actions: want 2, got %d", len(f.TrustedActions))
	}
	if len(f.DenyActions) != 1 {
		t.Errorf("deny_actions: want 1, got %d", len(f.DenyActions))
	}
	if len(f.Overrides) != 1 {
		t.Errorf("overrides: want 1, got %d", len(f.Overrides))
	}
}

// ---------------------------------------------------------------------------
// Existing tests (preserved)
// ---------------------------------------------------------------------------

func TestDiscoverWalksUpStopsAtGit(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "sub", "deep"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".ghactor.yml"), []byte("version: 1"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := Discover(filepath.Join(root, "sub", "deep"))
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(root, ".ghactor.yml") {
		t.Errorf("Discover = %q", got)
	}
}

func TestRuleForWithOverride(t *testing.T) {
	f := &File{
		Rules: map[string]Rule{"GHA005": {Severity: "warning"}},
		Overrides: []Override{
			{Paths: []string{".github/workflows/release-*.yml"}, Disable: []string{"GHA005"}},
		},
	}
	if f.RuleFor("GHA005", ".github/workflows/ci.yml").Disabled {
		t.Error("ci.yml should not disable GHA005")
	}
	if !f.RuleFor("GHA005", ".github/workflows/release-prod.yml").Disabled {
		t.Error("release-prod.yml should disable GHA005")
	}
	if f.RuleFor("GHA005", "anything").Severity != "warning" {
		t.Error("severity override lost")
	}
}

func TestTrustsAction(t *testing.T) {
	f := &File{TrustedActions: []string{"actions/*", "docker/*@v3"}}
	cases := map[string]bool{
		"actions/checkout@v4":  true,
		"docker/build-push@v3": true,
		"docker/build-push@v4": false,
		"third-party/thing@v1": false,
	}
	for uses, want := range cases {
		if got := f.TrustsAction(uses); got != want {
			t.Errorf("TrustsAction(%s) = %v, want %v", uses, got, want)
		}
	}
}

func TestDenyActionsFieldLoadedFromYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".ghactor.yml")
	content := `version: 1
deny_actions:
  - actions/cache@v2
  - third-party/*
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(f.DenyActions) != 2 {
		t.Fatalf("want 2 deny_actions entries, got %d: %v", len(f.DenyActions), f.DenyActions)
	}
	if f.DenyActions[0] != "actions/cache@v2" {
		t.Errorf("first entry: got %q, want %q", f.DenyActions[0], "actions/cache@v2")
	}
	if f.DenyActions[1] != "third-party/*" {
		t.Errorf("second entry: got %q, want %q", f.DenyActions[1], "third-party/*")
	}
}
