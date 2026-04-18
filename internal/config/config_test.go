package config

import (
	"os"
	"path/filepath"
	"testing"
)

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
