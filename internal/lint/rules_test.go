package lint

import (
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

