package lint

import (
	"os"
	"testing"

	"github.com/kdairatchi/ghactor/internal/pin"
	"github.com/kdairatchi/ghactor/internal/workflow"
)

func load(t *testing.T, path string) *workflow.File {
	t.Helper()
	f, err := workflow.Load(path)
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	return f
}

func kinds(iss []Issue) map[string]int {
	m := map[string]int{}
	for _, i := range iss {
		m[i.Kind]++
	}
	return m
}

func TestBadWorkflowFlagsAllRules(t *testing.T) {
	f := load(t, "testdata/bad.yml")
	var all []Issue
	for _, r := range Rules {
		all = append(all, r.Check(f)...)
	}
	got := kinds(all)
	wantAtLeast := []string{"GHA001", "GHA002", "GHA003", "GHA004", "GHA005", "GHA006", "GHA007"}
	for _, k := range wantAtLeast {
		if got[k] == 0 {
			t.Errorf("expected rule %s to fire, got kinds=%v", k, got)
		}
	}
}

func TestGoodWorkflowClean(t *testing.T) {
	f := load(t, "testdata/good.yml")
	var all []Issue
	for _, r := range Rules {
		all = append(all, r.Check(f)...)
	}
	if len(all) != 0 {
		t.Errorf("expected no issues, got %+v", all)
	}
}

func TestRefOf(t *testing.T) {
	cases := map[string]string{
		"actions/checkout@v4":    "v4",
		"actions/checkout@main":  "main",
		"owner/repo/path@v1.2.3": "v1.2.3",
		"noref":                  "",
	}
	for in, want := range cases {
		if got := refOf(in); got != want {
			t.Errorf("refOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGHA009ReusableWorkflowUnpinned(t *testing.T) {
	t.Run("bad fixture fires error and warning", func(t *testing.T) {
		f := load(t, "testdata/reusable_bad.yml")
		issues := ruleReusableUnpinned(f)
		got := map[Severity]int{}
		for _, iss := range issues {
			if iss.Kind != "GHA009" {
				t.Errorf("unexpected kind %q", iss.Kind)
			}
			got[iss.Severity]++
		}
		// floating ref @main → error; tag @v1.2.3 → warning; SHA → clean (no issue)
		if got[SevError] != 1 {
			t.Errorf("want 1 GHA009 error, got %d", got[SevError])
		}
		if got[SevWarning] != 1 {
			t.Errorf("want 1 GHA009 warning, got %d", got[SevWarning])
		}
		if total := len(issues); total != 2 {
			t.Errorf("want 2 GHA009 issues total, got %d", total)
		}
	})

	t.Run("good fixture is clean", func(t *testing.T) {
		f := load(t, "testdata/reusable_good.yml")
		issues := ruleReusableUnpinned(f)
		if len(issues) != 0 {
			t.Errorf("expected no GHA009 issues, got %+v", issues)
		}
	})

	t.Run("line numbers are non-zero", func(t *testing.T) {
		f := load(t, "testdata/reusable_bad.yml")
		issues := ruleReusableUnpinned(f)
		for _, iss := range issues {
			if iss.Line == 0 {
				t.Errorf("issue %+v has zero line number", iss)
			}
		}
	})
}

func TestGHA009InRulesSlice(t *testing.T) {
	found := false
	for _, r := range Rules {
		if r.ID == "GHA009" {
			found = true
			break
		}
	}
	if !found {
		t.Error("GHA009 not registered in Rules slice")
	}
}

// --- GHA004 extended: steps/needs/matrix tainted injection ---

func TestGHA004Extended(t *testing.T) {
	t.Run("steps.outputs in run fires warning", func(t *testing.T) {
		f := load(t, "testdata/gha004_extended_bad.yml")
		issues := ruleScriptInjection(f)
		found := false
		for _, iss := range issues {
			if iss.Kind == "GHA004" && iss.Severity == SevWarning {
				found = true
			}
		}
		if !found {
			t.Errorf("expected GHA004 warning for steps.outputs usage, got %+v", issues)
		}
	})

	t.Run("steps.outputs via env var does not fire", func(t *testing.T) {
		f := load(t, "testdata/gha004_extended_good.yml")
		issues := ruleScriptInjection(f)
		for _, iss := range issues {
			if iss.Kind == "GHA004" {
				t.Errorf("expected no GHA004 for safe env-var pattern, got %+v", iss)
			}
		}
	})
}

// --- GHA011: persist-credentials-on-prt ---

func TestGHA011PersistCredentialsPRT(t *testing.T) {
	t.Run("persist-credentials true on prt fires error", func(t *testing.T) {
		f := load(t, "testdata/gha011_bad.yml")
		issues := rulePersistCredentialsPRT(f)
		if len(issues) == 0 {
			t.Fatal("expected GHA011 issue, got none")
		}
		for _, iss := range issues {
			if iss.Kind != "GHA011" {
				t.Errorf("unexpected kind %q", iss.Kind)
			}
			if iss.Severity != SevError {
				t.Errorf("want error severity, got %s", iss.Severity)
			}
		}
	})

	t.Run("persist-credentials false on prt is clean", func(t *testing.T) {
		f := load(t, "testdata/gha011_good.yml")
		issues := rulePersistCredentialsPRT(f)
		if len(issues) != 0 {
			t.Errorf("expected no GHA011 issues, got %+v", issues)
		}
	})

	t.Run("persist-credentials true without prt trigger is clean", func(t *testing.T) {
		f := load(t, "testdata/gha015_good.yml") // push trigger, upload-artifact
		issues := rulePersistCredentialsPRT(f)
		if len(issues) != 0 {
			t.Errorf("expected no GHA011 for non-prt workflow, got %+v", issues)
		}
	})
}

// --- GHA012: curl-pipe-shell ---

func TestGHA012CurlPipeShell(t *testing.T) {
	t.Run("curl pipe bash fires warning", func(t *testing.T) {
		f := load(t, "testdata/gha012_bad.yml")
		issues := ruleCurlPipeShell(f)
		if len(issues) == 0 {
			t.Fatal("expected GHA012 issues, got none")
		}
		for _, iss := range issues {
			if iss.Kind != "GHA012" {
				t.Errorf("unexpected kind %q", iss.Kind)
			}
			if iss.Severity != SevWarning {
				t.Errorf("want warning severity, got %s", iss.Severity)
			}
		}
		if len(issues) < 2 {
			t.Errorf("want at least 2 GHA012 issues (curl|bash and wget|sh), got %d", len(issues))
		}
	})

	t.Run("download then verify is clean", func(t *testing.T) {
		f := load(t, "testdata/gha012_good.yml")
		issues := ruleCurlPipeShell(f)
		if len(issues) != 0 {
			t.Errorf("expected no GHA012 issues, got %+v", issues)
		}
	})
}

// --- GHA013: cache-key-untrusted ---

func TestGHA013CacheKeyUntrusted(t *testing.T) {
	t.Run("cache key with github.event fires warning", func(t *testing.T) {
		f := load(t, "testdata/gha013_bad.yml")
		issues := ruleCacheKeyUntrusted(f)
		if len(issues) == 0 {
			t.Fatal("expected GHA013 issue, got none")
		}
		for _, iss := range issues {
			if iss.Kind != "GHA013" {
				t.Errorf("unexpected kind %q", iss.Kind)
			}
			if iss.Severity != SevWarning {
				t.Errorf("want warning severity, got %s", iss.Severity)
			}
		}
	})

	t.Run("cache key with hashFiles is clean", func(t *testing.T) {
		f := load(t, "testdata/gha013_good.yml")
		issues := ruleCacheKeyUntrusted(f)
		if len(issues) != 0 {
			t.Errorf("expected no GHA013 issues, got %+v", issues)
		}
	})
}

// --- GHA014: legacy-set-env ---

func TestGHA014LegacySetEnv(t *testing.T) {
	t.Run("set-env and add-path fire error", func(t *testing.T) {
		f := load(t, "testdata/gha014_bad.yml")
		issues := ruleLegacySetEnv(f)
		if len(issues) == 0 {
			t.Fatal("expected GHA014 issues, got none")
		}
		for _, iss := range issues {
			if iss.Kind != "GHA014" {
				t.Errorf("unexpected kind %q", iss.Kind)
			}
			if iss.Severity != SevError {
				t.Errorf("want error severity, got %s", iss.Severity)
			}
		}
		if len(issues) < 2 {
			t.Errorf("want at least 2 GHA014 issues (set-env + add-path), got %d", len(issues))
		}
	})

	t.Run("GITHUB_ENV and GITHUB_PATH are clean", func(t *testing.T) {
		f := load(t, "testdata/gha014_good.yml")
		issues := ruleLegacySetEnv(f)
		if len(issues) != 0 {
			t.Errorf("expected no GHA014 issues, got %+v", issues)
		}
	})
}

// --- GHA015: prt-artifact-upload ---

func TestGHA015PRTArtifactUpload(t *testing.T) {
	t.Run("upload-artifact in prt workflow fires error", func(t *testing.T) {
		f := load(t, "testdata/gha015_bad.yml")
		issues := rulePRTArtifactUpload(f)
		if len(issues) == 0 {
			t.Fatal("expected GHA015 issue, got none")
		}
		for _, iss := range issues {
			if iss.Kind != "GHA015" {
				t.Errorf("unexpected kind %q", iss.Kind)
			}
			if iss.Severity != SevError {
				t.Errorf("want error severity, got %s", iss.Severity)
			}
		}
	})

	t.Run("upload-artifact in non-prt workflow is clean", func(t *testing.T) {
		f := load(t, "testdata/gha015_good.yml")
		issues := rulePRTArtifactUpload(f)
		if len(issues) != 0 {
			t.Errorf("expected no GHA015 for push-triggered workflow, got %+v", issues)
		}
	})
}

// --- GHA016: self-hosted-public ---

func TestGHA016SelfHostedPublic(t *testing.T) {
	t.Run("self-hosted with only OS label fires warning", func(t *testing.T) {
		f := load(t, "testdata/gha016_bad.yml")
		issues := ruleSelfHostedPublic(f)
		if len(issues) == 0 {
			t.Fatal("expected GHA016 issues, got none")
		}
		for _, iss := range issues {
			if iss.Kind != "GHA016" {
				t.Errorf("unexpected kind %q", iss.Kind)
			}
			if iss.Severity != SevWarning {
				t.Errorf("want warning severity, got %s", iss.Severity)
			}
		}
		if len(issues) < 2 {
			t.Errorf("want 2 GHA016 issues (linux and windows jobs), got %d", len(issues))
		}
	})

	t.Run("self-hosted with org-scoped label is clean", func(t *testing.T) {
		f := load(t, "testdata/gha016_good.yml")
		issues := ruleSelfHostedPublic(f)
		if len(issues) != 0 {
			t.Errorf("expected no GHA016 issues for org-scoped runner, got %+v", issues)
		}
	})
}

// --- GHA017: missing-concurrency-deploy ---

func TestGHA017MissingConcurrencyDeploy(t *testing.T) {
	t.Run("deploy workflow without concurrency fires info", func(t *testing.T) {
		f := load(t, "testdata/gha017_bad.yml")
		issues := ruleMissingConcurrencyDeploy(f)
		if len(issues) == 0 {
			t.Fatal("expected GHA017 issue, got none")
		}
		for _, iss := range issues {
			if iss.Kind != "GHA017" {
				t.Errorf("unexpected kind %q", iss.Kind)
			}
			if iss.Severity != SevInfo {
				t.Errorf("want info severity, got %s", iss.Severity)
			}
		}
	})

	t.Run("deploy workflow with concurrency is clean", func(t *testing.T) {
		f := load(t, "testdata/gha017_good.yml")
		issues := ruleMissingConcurrencyDeploy(f)
		if len(issues) != 0 {
			t.Errorf("expected no GHA017 issues when concurrency present, got %+v", issues)
		}
	})

	t.Run("non-deploy workflow is clean regardless", func(t *testing.T) {
		f := load(t, "testdata/gha012_good.yml") // push trigger, generic name
		issues := ruleMissingConcurrencyDeploy(f)
		if len(issues) != 0 {
			t.Errorf("expected no GHA017 for non-deploy workflow, got %+v", issues)
		}
	})
}

// --- GHA018: github-env-smuggling ---

func TestGHA018GitHubEnvSmuggling(t *testing.T) {
	t.Run("untrusted expr into GITHUB_ENV fires error", func(t *testing.T) {
		f := load(t, "testdata/gha018_bad.yml")
		issues := ruleGitHubEnvSmuggling(f)
		if len(issues) == 0 {
			t.Fatal("expected GHA018 issue, got none")
		}
		for _, iss := range issues {
			if iss.Kind != "GHA018" {
				t.Errorf("unexpected kind %q", iss.Kind)
			}
			if iss.Severity != SevError {
				t.Errorf("want error severity, got %s", iss.Severity)
			}
		}
	})

	t.Run("safe env: variable export is clean", func(t *testing.T) {
		f := load(t, "testdata/gha018_good.yml")
		issues := ruleGitHubEnvSmuggling(f)
		if len(issues) != 0 {
			t.Errorf("expected no GHA018 for safe env: pattern, got %+v", issues)
		}
	})
}

// --- GHA019: oidc-no-subject ---

func TestGHA019OIDCNoSubject(t *testing.T) {
	t.Run("id-token write fires warning", func(t *testing.T) {
		f := load(t, "testdata/gha019_bad.yml")
		issues := ruleOIDCNoSubject(f)
		if len(issues) == 0 {
			t.Fatal("expected GHA019 issue, got none")
		}
		for _, iss := range issues {
			if iss.Kind != "GHA019" {
				t.Errorf("unexpected kind %q", iss.Kind)
			}
			if iss.Severity != SevWarning {
				t.Errorf("want warning severity, got %s", iss.Severity)
			}
		}
	})

	t.Run("no id-token write is clean", func(t *testing.T) {
		f := load(t, "testdata/gha019_good.yml")
		issues := ruleOIDCNoSubject(f)
		if len(issues) != 0 {
			t.Errorf("expected no GHA019 issues, got %+v", issues)
		}
	})
}

// --- GHA020: overprivileged-token ---

func TestGHA020OverprivilegedToken(t *testing.T) {
	t.Run("workflow-level write scopes with no justification fire warning", func(t *testing.T) {
		f := load(t, "testdata/gha020_bad.yml")
		issues := ruleOverprivilegedToken(f)
		if len(issues) == 0 {
			t.Fatal("expected GHA020 issue, got none")
		}
		for _, iss := range issues {
			if iss.Kind != "GHA020" {
				t.Errorf("unexpected kind %q", iss.Kind)
			}
			if iss.Severity != SevWarning {
				t.Errorf("want warning severity, got %s", iss.Severity)
			}
			if iss.Line == 0 {
				t.Error("GHA020 issue has zero line number")
			}
		}
	})

	t.Run("workflow-level read-only permissions is clean", func(t *testing.T) {
		f := load(t, "testdata/gha020_good.yml")
		issues := ruleOverprivilegedToken(f)
		if len(issues) != 0 {
			t.Errorf("expected no GHA020 issues, got %+v", issues)
		}
	})

	t.Run("workflow with release trigger is clean", func(t *testing.T) {
		src := []byte("name: release\non: [release]\npermissions:\n  contents: write\njobs:\n  build:\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n")
		tmp := t.TempDir() + "/release.yml"
		if err := os.WriteFile(tmp, src, 0o644); err != nil {
			t.Fatal(err)
		}
		f := load(t, tmp)
		issues := ruleOverprivilegedToken(f)
		if len(issues) != 0 {
			t.Errorf("release trigger should suppress GHA020, got %+v", issues)
		}
	})

	t.Run("job-level permissions override suppresses finding", func(t *testing.T) {
		src := []byte(`name: t
on: [push]
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
`)
		// Write to a temp file and load it.
		tmp := t.TempDir() + "/inline.yml"
		if err := os.WriteFile(tmp, src, 0o644); err != nil {
			t.Fatal(err)
		}
		f := load(t, tmp)
		issues := ruleOverprivilegedToken(f)
		if len(issues) != 0 {
			t.Errorf("job-level override should suppress GHA020, got %+v", issues)
		}
	})
}

// --- GHA021: workflow-call-untyped-input ---

func TestGHA021WorkflowCallUntypedInput(t *testing.T) {
	t.Run("inputs without type fire warning", func(t *testing.T) {
		f := load(t, "testdata/gha021_bad.yml")
		issues := ruleWorkflowCallUntypedInput(f)
		if len(issues) == 0 {
			t.Fatal("expected GHA021 issues, got none")
		}
		for _, iss := range issues {
			if iss.Kind != "GHA021" {
				t.Errorf("unexpected kind %q", iss.Kind)
			}
			if iss.Severity != SevWarning {
				t.Errorf("want warning severity, got %s", iss.Severity)
			}
			if iss.Line == 0 {
				t.Error("GHA021 issue has zero line number")
			}
		}
		if len(issues) < 2 {
			t.Errorf("want at least 2 GHA021 issues (both untyped inputs), got %d", len(issues))
		}
	})

	t.Run("inputs with explicit type are clean", func(t *testing.T) {
		f := load(t, "testdata/gha021_good.yml")
		issues := ruleWorkflowCallUntypedInput(f)
		if len(issues) != 0 {
			t.Errorf("expected no GHA021 issues, got %+v", issues)
		}
	})

	t.Run("non-workflow_call workflow is clean", func(t *testing.T) {
		f := load(t, "testdata/good.yml")
		issues := ruleWorkflowCallUntypedInput(f)
		if len(issues) != 0 {
			t.Errorf("expected no GHA021 for non-reusable workflow, got %+v", issues)
		}
	})
}

// --- GHA022: step-shell-unspecified ---

func TestGHA022StepShellUnspecified(t *testing.T) {
	t.Run("multi-os matrix job with run: and no shell: fires info", func(t *testing.T) {
		f := load(t, "testdata/gha022_bad.yml")
		issues := ruleStepShellUnspecified(f)
		if len(issues) == 0 {
			t.Fatal("expected GHA022 issues, got none")
		}
		for _, iss := range issues {
			if iss.Kind != "GHA022" {
				t.Errorf("unexpected kind %q", iss.Kind)
			}
			if iss.Severity != SevInfo {
				t.Errorf("want info severity, got %s", iss.Severity)
			}
		}
		if len(issues) < 2 {
			t.Errorf("want at least 2 GHA022 issues (two run: steps), got %d", len(issues))
		}
	})

	t.Run("multi-os matrix job with shell: set is clean", func(t *testing.T) {
		f := load(t, "testdata/gha022_good.yml")
		issues := ruleStepShellUnspecified(f)
		if len(issues) != 0 {
			t.Errorf("expected no GHA022 issues, got %+v", issues)
		}
	})

	t.Run("single-os job without shell: is clean", func(t *testing.T) {
		f := load(t, "testdata/good.yml")
		issues := ruleStepShellUnspecified(f)
		if len(issues) != 0 {
			t.Errorf("expected no GHA022 for single-OS job, got %+v", issues)
		}
	})
}

// --- GHA023: container-unpinned ---

func TestGHA023ContainerUnpinned(t *testing.T) {
	t.Run("tag-only container and service images fire warning", func(t *testing.T) {
		f := load(t, "testdata/gha023_bad.yml")
		issues := ruleContainerUnpinned(f)
		if len(issues) == 0 {
			t.Fatal("expected GHA023 issues, got none")
		}
		for _, iss := range issues {
			if iss.Kind != "GHA023" {
				t.Errorf("unexpected kind %q", iss.Kind)
			}
			if iss.Severity != SevWarning {
				t.Errorf("want warning severity, got %s", iss.Severity)
			}
			if iss.Line == 0 {
				t.Error("GHA023 issue has zero line number")
			}
		}
		if len(issues) < 2 {
			t.Errorf("want at least 2 GHA023 issues (container + service), got %d", len(issues))
		}
	})

	t.Run("digest-pinned container and service images are clean", func(t *testing.T) {
		f := load(t, "testdata/gha023_good.yml")
		issues := ruleContainerUnpinned(f)
		if len(issues) != 0 {
			t.Errorf("expected no GHA023 issues, got %+v", issues)
		}
	})

	t.Run("workflow with no container or services is clean", func(t *testing.T) {
		f := load(t, "testdata/good.yml")
		issues := ruleContainerUnpinned(f)
		if len(issues) != 0 {
			t.Errorf("expected no GHA023 for workflow with no containers, got %+v", issues)
		}
	})
}

// --- GHA008: tag-drift ---

// mockResolver returns a *pin.Resolver whose Fetch function is controlled by the caller.
func mockResolver(fn pin.ResolveFunc) *pin.Resolver {
	r := pin.NewResolver("") // empty cachePath → no file I/O
	r.Fetch = fn
	return r
}

func TestGHA008TagDrift(t *testing.T) {
	staleSHA := "cccccccccccccccccccccccccccccccccccccccc"
	currentSHA := "dddddddddddddddddddddddddddddddddddddddd"
	correctSHA := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	resolver := mockResolver(func(owner, repo, ref string) (string, error) {
		// actions/checkout@v4 has drifted; actions/setup-node@v4 is current.
		if owner == "actions" && repo == "checkout" {
			return currentSHA, nil
		}
		return correctSHA, nil
	})

	t.Run("stale pin fires GHA008", func(t *testing.T) {
		f := load(t, "testdata/stale_pin.yml")
		check := ruleTagDrift(resolver)
		issues := check(f)
		if len(issues) == 0 {
			t.Fatal("expected GHA008 issue for stale pin, got none")
		}
		for _, iss := range issues {
			if iss.Kind != "GHA008" {
				t.Errorf("unexpected kind %q", iss.Kind)
			}
			if iss.Severity != SevWarning {
				t.Errorf("want warning severity, got %s", iss.Severity)
			}
			if iss.Line == 0 {
				t.Error("GHA008 issue has zero line number")
			}
		}
		// The stale_pin.yml has one stale action (checkout) and one current (setup-node).
		if len(issues) != 1 {
			t.Errorf("want 1 GHA008 issue, got %d: %+v", len(issues), issues)
		}
	})

	t.Run("no issue when resolver returns same SHA", func(t *testing.T) {
		// Build a synthetic workflow file with a correctly pinned action.
		src := []byte("name: t\non: [push]\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@" + staleSHA + " # v4\n")
		sameResolver := mockResolver(func(owner, repo, ref string) (string, error) {
			return staleSHA, nil // tag resolves to the pinned SHA → no drift
		})
		wf := &workflow.File{Path: "inline.yml", Source: src}
		check := ruleTagDrift(sameResolver)
		issues := check(wf)
		if len(issues) != 0 {
			t.Errorf("expected no issues for current pin, got %+v", issues)
		}
	})

	t.Run("no issue when nil resolver (optRules skips GHA008)", func(t *testing.T) {
		extra := optRules(nil, nil)
		for _, r := range extra {
			if r.ID == "GHA008" {
				t.Error("GHA008 should not appear when resolver is nil")
			}
		}
	})

	_ = staleSHA
}

// --- GHA010: denied-action ---

func TestGHA010DeniedAction(t *testing.T) {
	t.Run("exact match fires error", func(t *testing.T) {
		f := load(t, "testdata/denied_action.yml")
		check := ruleDeniedAction([]string{"actions/cache"})
		issues := check(f)
		if len(issues) == 0 {
			t.Fatal("expected GHA010 issue for denied action, got none")
		}
		for _, iss := range issues {
			if iss.Kind != "GHA010" {
				t.Errorf("unexpected kind %q", iss.Kind)
			}
			if iss.Severity != SevError {
				t.Errorf("want error severity, got %s", iss.Severity)
			}
		}
	})

	t.Run("glob pattern fires for matching owner", func(t *testing.T) {
		f := load(t, "testdata/denied_action.yml")
		// "actions/*" should match both actions/cache and actions/checkout.
		check := ruleDeniedAction([]string{"actions/*"})
		issues := check(f)
		if len(issues) < 2 {
			t.Errorf("want at least 2 GHA010 issues for actions/* glob, got %d", len(issues))
		}
	})

	t.Run("ref-specific pattern only fires on matching ref", func(t *testing.T) {
		// Deny actions/cache@v2 — the fixture uses a SHA, not @v2, so no match.
		f := load(t, "testdata/denied_action.yml")
		check := ruleDeniedAction([]string{"actions/cache@v2"})
		issues := check(f)
		if len(issues) != 0 {
			t.Errorf("ref-specific deny @v2 should not match SHA pin, got %+v", issues)
		}
	})

	t.Run("non-matching pattern produces no issues", func(t *testing.T) {
		f := load(t, "testdata/denied_action.yml")
		check := ruleDeniedAction([]string{"third-party/*"})
		issues := check(f)
		if len(issues) != 0 {
			t.Errorf("expected no issues for non-matching deny list, got %+v", issues)
		}
	})

	t.Run("empty deny list produces no GHA010 in optRules", func(t *testing.T) {
		extra := optRules(nil, nil)
		for _, r := range extra {
			if r.ID == "GHA010" {
				t.Error("GHA010 should not appear when deny list is empty")
			}
		}
	})
}

// --- GHA024: deprecated-action-version ---

func TestGHA024DeprecatedActionVersion(t *testing.T) {
	t.Run("deprecated versions fire expected severities", func(t *testing.T) {
		f := load(t, "testdata/gha024_bad.yml")
		issues := ruleDeprecatedActionVersion(f)
		if len(issues) == 0 {
			t.Fatal("expected GHA024 issues, got none")
		}
		for _, iss := range issues {
			if iss.Kind != "GHA024" {
				t.Errorf("unexpected kind %q", iss.Kind)
			}
		}
		// Count errors vs warnings: upload-artifact@v2, download-artifact@v3, create-release@v1 → error
		// cache@v2, checkout SHA#v3 → warning
		errCount := 0
		warnCount := 0
		for _, iss := range issues {
			switch iss.Severity {
			case SevError:
				errCount++
			case SevWarning:
				warnCount++
			}
		}
		if errCount == 0 {
			t.Errorf("want at least 1 GHA024 error (hard-fail versions), got %d", errCount)
		}
		if warnCount == 0 {
			t.Errorf("want at least 1 GHA024 warning (deprecated but not hard-fail), got %d", warnCount)
		}
	})

	t.Run("current versions are clean", func(t *testing.T) {
		f := load(t, "testdata/gha024_good.yml")
		issues := ruleDeprecatedActionVersion(f)
		if len(issues) != 0 {
			t.Errorf("expected no GHA024 issues for current versions, got %+v", issues)
		}
	})

	t.Run("SHA-pinned with v4 comment is clean", func(t *testing.T) {
		src := []byte("name: t\non: [push]\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4\n")
		tmp := t.TempDir() + "/inline.yml"
		if err := os.WriteFile(tmp, src, 0o644); err != nil {
			t.Fatal(err)
		}
		f := load(t, tmp)
		issues := ruleDeprecatedActionVersion(f)
		if len(issues) != 0 {
			t.Errorf("SHA pin with v4 comment should be clean, got %+v", issues)
		}
	})

	t.Run("whole-action deprecation fires error regardless of version", func(t *testing.T) {
		src := []byte("name: t\non: [push]\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n    steps:\n      - uses: actions/create-release@v1\n")
		tmp := t.TempDir() + "/inline.yml"
		if err := os.WriteFile(tmp, src, 0o644); err != nil {
			t.Fatal(err)
		}
		f := load(t, tmp)
		issues := ruleDeprecatedActionVersion(f)
		found := false
		for _, iss := range issues {
			if iss.Kind == "GHA024" && iss.Severity == SevError {
				found = true
			}
		}
		if !found {
			t.Error("expected GHA024 error for archived actions/create-release")
		}
	})

	t.Run("GHA024 registered in Rules slice", func(t *testing.T) {
		for _, r := range Rules {
			if r.ID == "GHA024" {
				return
			}
		}
		t.Error("GHA024 not found in Rules slice")
	})
}

// --- GHA025: deprecated-runner-image ---

func TestGHA025DeprecatedRunnerImage(t *testing.T) {
	t.Run("removed and deprecated runners fire issues", func(t *testing.T) {
		f := load(t, "testdata/gha025_bad.yml")
		issues := ruleDeprecatedRunnerImage(f)
		if len(issues) == 0 {
			t.Fatal("expected GHA025 issues, got none")
		}
		for _, iss := range issues {
			if iss.Kind != "GHA025" {
				t.Errorf("unexpected kind %q", iss.Kind)
			}
		}
		errCount := 0
		warnCount := 0
		for _, iss := range issues {
			switch iss.Severity {
			case SevError:
				errCount++
			case SevWarning:
				warnCount++
			}
		}
		if errCount < 2 {
			t.Errorf("want ≥2 GHA025 errors (ubuntu-20.04, macos-12), got %d", errCount)
		}
		if warnCount < 1 {
			t.Errorf("want ≥1 GHA025 warning (windows-2019), got %d", warnCount)
		}
	})

	t.Run("supported runners are clean", func(t *testing.T) {
		f := load(t, "testdata/gha025_good.yml")
		issues := ruleDeprecatedRunnerImage(f)
		if len(issues) != 0 {
			t.Errorf("expected no GHA025 issues for supported runners, got %+v", issues)
		}
	})

	t.Run("macos-13 fires warning", func(t *testing.T) {
		src := []byte("name: t\non: [push]\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: macos-13\n    timeout-minutes: 10\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n")
		tmp := t.TempDir() + "/inline.yml"
		if err := os.WriteFile(tmp, src, 0o644); err != nil {
			t.Fatal(err)
		}
		f := load(t, tmp)
		issues := ruleDeprecatedRunnerImage(f)
		found := false
		for _, iss := range issues {
			if iss.Kind == "GHA025" && iss.Severity == SevWarning {
				found = true
			}
		}
		if !found {
			t.Error("expected GHA025 warning for macos-13")
		}
	})
}

// --- GHA026 (GHA004 promotion): tainted-changed-files output escalates to error ---

func TestGHA026TaintedChangedFilesPromotion(t *testing.T) {
	t.Run("tj-actions/changed-files output in run fires GHA004 error", func(t *testing.T) {
		f := load(t, "testdata/gha026_bad.yml")
		issues := ruleScriptInjection(f)
		found := false
		for _, iss := range issues {
			if iss.Kind == "GHA004" && iss.Severity == SevError {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected GHA004 error for tj-actions/changed-files output, got %+v", issues)
		}
	})

	t.Run("non-tainting step output stays at warning", func(t *testing.T) {
		src := []byte(`name: t
on: [push]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - id: myapp
        uses: myorg/some-action@v1
      - name: use-output
        run: echo ${{ steps.myapp.outputs.result }}
`)
		tmp := t.TempDir() + "/inline.yml"
		if err := os.WriteFile(tmp, src, 0o644); err != nil {
			t.Fatal(err)
		}
		f := load(t, tmp)
		issues := ruleScriptInjection(f)
		hasError := false
		hasWarning := false
		for _, iss := range issues {
			if iss.Kind == "GHA004" {
				if iss.Severity == SevError {
					hasError = true
				}
				if iss.Severity == SevWarning {
					hasWarning = true
				}
			}
		}
		if hasError {
			t.Errorf("non-tainting step output should not be promoted to error")
		}
		if !hasWarning {
			t.Errorf("non-tainting step output should still fire GHA004 warning, got none")
		}
	})
}

// --- GHA027: publish-cache-restore ---

func TestGHA027PublishCacheRestore(t *testing.T) {
	t.Run("release workflow with cache restore fires warning", func(t *testing.T) {
		f := load(t, "testdata/gha027_bad.yml")
		issues := rulePublishCacheRestore(f)
		if len(issues) == 0 {
			t.Fatal("expected GHA027 issue, got none")
		}
		for _, iss := range issues {
			if iss.Kind != "GHA027" {
				t.Errorf("unexpected kind %q", iss.Kind)
			}
			if iss.Severity != SevWarning {
				t.Errorf("want warning severity, got %s", iss.Severity)
			}
		}
	})

	t.Run("release workflow without cache is clean", func(t *testing.T) {
		f := load(t, "testdata/gha027_good.yml")
		issues := rulePublishCacheRestore(f)
		if len(issues) != 0 {
			t.Errorf("expected no GHA027 issues, got %+v", issues)
		}
	})

	t.Run("non-publish workflow with cache is clean", func(t *testing.T) {
		f := load(t, "testdata/good.yml")
		issues := rulePublishCacheRestore(f)
		if len(issues) != 0 {
			t.Errorf("expected no GHA027 for non-publish workflow, got %+v", issues)
		}
	})
}

// --- GHA028: no-build-provenance ---

func TestGHA028NoBuildProvenance(t *testing.T) {
	t.Run("publish workflow without attest fires info", func(t *testing.T) {
		f := load(t, "testdata/gha028_bad.yml")
		issues := ruleNoBuildProvenance(f)
		if len(issues) == 0 {
			t.Fatal("expected GHA028 issue, got none")
		}
		for _, iss := range issues {
			if iss.Kind != "GHA028" {
				t.Errorf("unexpected kind %q", iss.Kind)
			}
			if iss.Severity != SevInfo {
				t.Errorf("want info severity, got %s", iss.Severity)
			}
		}
	})

	t.Run("publish workflow with attest is clean", func(t *testing.T) {
		f := load(t, "testdata/gha028_good.yml")
		issues := ruleNoBuildProvenance(f)
		if len(issues) != 0 {
			t.Errorf("expected no GHA028 issues, got %+v", issues)
		}
	})

	t.Run("non-publish workflow is clean", func(t *testing.T) {
		f := load(t, "testdata/good.yml")
		issues := ruleNoBuildProvenance(f)
		if len(issues) != 0 {
			t.Errorf("expected no GHA028 for non-publish workflow, got %+v", issues)
		}
	})
}

// --- GHA029: cross-org-secrets-inherit ---

func TestGHA029CrossOrgSecretsInherit(t *testing.T) {
	t.Run("cross-org secrets inherit fires when GITHUB_REPOSITORY is set", func(t *testing.T) {
		t.Setenv("GITHUB_REPOSITORY", "myorg/myrepo")
		f := load(t, "testdata/gha029_bad.yml")
		issues := ruleCrossOrgSecretsInherit(f)
		if len(issues) == 0 {
			t.Fatal("expected GHA029 issue, got none")
		}
		for _, iss := range issues {
			if iss.Kind != "GHA029" {
				t.Errorf("unexpected kind %q", iss.Kind)
			}
			if iss.Severity != SevWarning {
				t.Errorf("want warning severity, got %s", iss.Severity)
			}
		}
	})

	t.Run("same-org secrets inherit is clean", func(t *testing.T) {
		t.Setenv("GITHUB_REPOSITORY", "myorg/myrepo")
		f := load(t, "testdata/gha029_good.yml")
		issues := ruleCrossOrgSecretsInherit(f)
		if len(issues) != 0 {
			t.Errorf("expected no GHA029 issues for same-org call, got %+v", issues)
		}
	})

	t.Run("no GITHUB_REPOSITORY env → skip gracefully", func(t *testing.T) {
		t.Setenv("GITHUB_REPOSITORY", "")
		f := load(t, "testdata/gha029_bad.yml")
		issues := ruleCrossOrgSecretsInherit(f)
		if len(issues) != 0 {
			t.Errorf("expected no GHA029 when owner unknown, got %+v", issues)
		}
	})
}

// --- GHA030: action-not-in-allowlist ---

func TestGHA030ActionNotInAllowlist(t *testing.T) {
	t.Run("action outside allowlist fires error", func(t *testing.T) {
		f := load(t, "testdata/gha030_bad.yml")
		check := ruleActionNotInAllowlist([]string{"actions/*"})
		issues := check(f)
		if len(issues) == 0 {
			t.Fatal("expected GHA030 issue, got none")
		}
		for _, iss := range issues {
			if iss.Kind != "GHA030" {
				t.Errorf("unexpected kind %q", iss.Kind)
			}
			if iss.Severity != SevError {
				t.Errorf("want error severity, got %s", iss.Severity)
			}
		}
	})

	t.Run("action inside allowlist is clean", func(t *testing.T) {
		f := load(t, "testdata/gha030_good.yml")
		check := ruleActionNotInAllowlist([]string{"actions/*"})
		issues := check(f)
		if len(issues) != 0 {
			t.Errorf("expected no GHA030 for allowlisted actions, got %+v", issues)
		}
	})

	t.Run("empty allowlist returns nil check", func(t *testing.T) {
		check := ruleActionNotInAllowlist(nil)
		if check != nil {
			t.Error("expected nil check for empty allowlist")
		}
	})

	t.Run("optAllowlistRule returns nil for empty list", func(t *testing.T) {
		r := optAllowlistRule(nil)
		if r != nil {
			t.Error("expected nil rule for empty allowlist")
		}
	})

	t.Run("optAllowlistRule returns rule for non-empty list", func(t *testing.T) {
		r := optAllowlistRule([]string{"actions/*"})
		if r == nil {
			t.Fatal("expected non-nil rule for non-empty allowlist")
		}
		if r.ID != "GHA030" {
			t.Errorf("want GHA030, got %s", r.ID)
		}
	})
}

// --- GHA031: obfuscated-run ---

func TestGHA031ObfuscatedRun(t *testing.T) {
	t.Run("obfuscation patterns fire warnings", func(t *testing.T) {
		f := load(t, "testdata/gha031_bad.yml")
		issues := ruleObfuscatedRun(f)
		if len(issues) == 0 {
			t.Fatal("expected GHA031 issues, got none")
		}
		for _, iss := range issues {
			if iss.Kind != "GHA031" {
				t.Errorf("unexpected kind %q", iss.Kind)
			}
			if iss.Severity != SevWarning {
				t.Errorf("want warning severity, got %s", iss.Severity)
			}
		}
		if len(issues) < 3 {
			t.Errorf("want ≥3 GHA031 issues (base64 pipe, eval curl, pipe-to-python, long base64), got %d", len(issues))
		}
	})

	t.Run("safe download-verify-execute pattern is clean", func(t *testing.T) {
		f := load(t, "testdata/gha031_good.yml")
		issues := ruleObfuscatedRun(f)
		if len(issues) != 0 {
			t.Errorf("expected no GHA031 for safe patterns, got %+v", issues)
		}
	})
}

// --- GHA032: spoofable-actor-check ---

func TestGHA032SpoofableActorCheck(t *testing.T) {
	t.Run("github.actor bot comparison fires warning", func(t *testing.T) {
		f := load(t, "testdata/gha032_bad.yml")
		issues := ruleSpoofableActorCheck(f)
		if len(issues) == 0 {
			t.Fatal("expected GHA032 issues, got none")
		}
		for _, iss := range issues {
			if iss.Kind != "GHA032" {
				t.Errorf("unexpected kind %q", iss.Kind)
			}
			if iss.Severity != SevWarning {
				t.Errorf("want warning severity, got %s", iss.Severity)
			}
		}
		if len(issues) < 2 {
			t.Errorf("want ≥2 GHA032 issues (job-level and step-level), got %d", len(issues))
		}
	})

	t.Run("event.pull_request.user.login pattern is clean", func(t *testing.T) {
		f := load(t, "testdata/gha032_good.yml")
		issues := ruleSpoofableActorCheck(f)
		if len(issues) != 0 {
			t.Errorf("expected no GHA032 for safe actor check pattern, got %+v", issues)
		}
	})
}

// --- workflow.SecretsInherit ---

func TestWorkflowSecretsInherit(t *testing.T) {
	t.Run("secrets: inherit sets SecretsInherit on ReusableUse", func(t *testing.T) {
		f := load(t, "testdata/gha029_bad.yml")
		if f.WF == nil {
			t.Fatal("nil WF")
		}
		if len(f.WF.Reusables) == 0 {
			t.Fatal("expected reusable entries, got none")
		}
		found := false
		for _, ru := range f.WF.Reusables {
			if ru.SecretsInherit {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected SecretsInherit=true for job with secrets: inherit")
		}
	})

	t.Run("no secrets: inherit leaves SecretsInherit false", func(t *testing.T) {
		f := load(t, "testdata/reusable_bad.yml")
		for _, ru := range f.WF.Reusables {
			if ru.SecretsInherit {
				t.Errorf("expected SecretsInherit=false, got true for %s/%s", ru.Owner, ru.Repo)
			}
		}
	})
}

