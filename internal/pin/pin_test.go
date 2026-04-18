package pin

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const fakeSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestSplitUses(t *testing.T) {
	cases := []struct {
		in, o, r, ref string
		ok            bool
	}{
		{"actions/checkout@v4", "actions", "checkout", "v4", true},
		{"actions/cache/save@v3", "actions", "cache", "v3", true},
		{"noatsign", "", "", "", false},
		{"single@v1", "", "", "", false},
	}
	for _, c := range cases {
		o, r, ref, ok := splitUses(c.in)
		if o != c.o || r != c.r || ref != c.ref || ok != c.ok {
			t.Errorf("splitUses(%q) = (%q,%q,%q,%v); want (%q,%q,%q,%v)",
				c.in, o, r, ref, ok, c.o, c.r, c.ref, c.ok)
		}
	}
}

func TestResolveCachesAndPassesSHAThrough(t *testing.T) {
	var calls int32
	r := &Resolver{cache: map[string]string{}, Fetch: func(o, repo, ref string) (string, error) {
		atomic.AddInt32(&calls, 1)
		return fakeSHA, nil
	}}
	for i := 0; i < 3; i++ {
		got, err := r.Resolve("actions", "checkout", "v4")
		if err != nil || got != fakeSHA {
			t.Fatalf("Resolve: %v %q", err, got)
		}
	}
	if calls != 1 {
		t.Errorf("cache miss: want 1 fetch call, got %d", calls)
	}
	got, _ := r.Resolve("a", "b", fakeSHA)
	if got != fakeSHA || calls != 1 {
		t.Errorf("SHA passthrough should skip fetch (calls=%d)", calls)
	}
}

func TestPinDryRunAndWrite(t *testing.T) {
	dir := t.TempDir()
	wf := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wf, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(wf, "ci.yml")
	src := "name: ci\non: [push]\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &Resolver{cache: map[string]string{}, Fetch: func(_, _, _ string) (string, error) { return fakeSHA, nil }}

	ch, err := Pin(wf, r, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch) != 1 {
		t.Fatalf("want 1 change, got %d: %+v", len(ch), ch)
	}
	if ch[0].NewUses != "actions/checkout@"+fakeSHA {
		t.Errorf("NewUses = %q", ch[0].NewUses)
	}
	if b, _ := os.ReadFile(path); string(b) != src {
		t.Errorf("dry-run modified file:\n%s", b)
	}

	if _, err := Pin(wf, r, false); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	want := "uses: actions/checkout@" + fakeSHA + " # v4"
	if !strings.Contains(string(b), want) {
		t.Errorf("pin missing; got:\n%s", b)
	}
}

func TestRewriteFileTo(t *testing.T) {
	src := "steps:\n  - uses: actions/checkout@v3\n  - uses: actions/setup-go@v4\n"
	path := filepath.Join(t.TempDir(), "w.yml")
	os.WriteFile(path, []byte(src), 0o644)
	targets := map[string]Pinned{
		"actions/checkout": {SHA: fakeSHA, Tag: "v4"},
	}
	ch, _, err := RewriteFileTo(path, []byte(src), targets, false)
	if err != nil || len(ch) != 1 {
		t.Fatalf("want 1 change, got %d err=%v", len(ch), err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "actions/checkout@"+fakeSHA+" # v4") {
		t.Errorf("rewrite missing:\n%s", b)
	}
	if !strings.Contains(string(b), "actions/setup-go@v4") {
		t.Errorf("untouched target was rewritten:\n%s", b)
	}
}
