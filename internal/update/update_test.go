package update

import (
	"bytes"
	"strings"
	"testing"
)

func TestChangelogRendersDriftAndSkipped(t *testing.T) {
	us := []Update{
		{Key: "actions/checkout", Owner: "actions", Repo: "checkout",
			CurRef: "v3", CurSHA: "11111111111111111111",
			LatestTag: "v4", LatestSHA: "22222222222222222222",
			SameMajor: false, Drift: true},
		{Key: "old/action", Owner: "old", Repo: "action",
			CurRef: "v1", LatestTag: "v5", Skip: true},
	}
	// first entry has SameMajor=false but Drift=true, allow-major accepted it; render it
	var buf bytes.Buffer
	if err := WriteChangelog(&buf, us); err != nil {
		t.Fatal(err)
	}
	s := buf.String()
	if !strings.Contains(s, "`actions/checkout`") {
		t.Errorf("drift row missing:\n%s", s)
	}
	if !strings.Contains(s, "compare/v3...v4") {
		t.Errorf("compare URL missing:\n%s", s)
	}
	if !strings.Contains(s, "Skipped major bumps (1)") {
		t.Errorf("skipped section missing:\n%s", s)
	}
}
