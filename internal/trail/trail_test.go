package trail

import (
	"testing"
	"time"
)

func TestParseWindow(t *testing.T) {
	cases := map[string]time.Duration{
		"":    0,
		"24h": 24 * time.Hour,
		"7d":  7 * 24 * time.Hour,
		"30d": 30 * 24 * time.Hour,
		"2h":  2 * time.Hour,
	}
	for in, want := range cases {
		got, err := ParseWindow(in)
		if err != nil {
			t.Errorf("ParseWindow(%q) err %v", in, err)
		}
		if got != want {
			t.Errorf("ParseWindow(%q) = %v, want %v", in, got, want)
		}
	}
	if _, err := ParseWindow("banana"); err == nil {
		t.Error("expected error on invalid")
	}
}

func TestAggregateFailRate(t *testing.T) {
	now := time.Now()
	runs := []Run{
		{Workflow: "ci", Conclusion: "success", Attempt: 1, CreatedAt: now, UpdatedAt: now.Add(3 * time.Minute)},
		{Workflow: "ci", Conclusion: "failure", Attempt: 1, CreatedAt: now, UpdatedAt: now},
		{Workflow: "ci", Conclusion: "failure", Attempt: 2, CreatedAt: now, UpdatedAt: now},
		{Workflow: "ci", Conclusion: "success", Attempt: 2, CreatedAt: now, UpdatedAt: now},
		{Workflow: "release", Conclusion: "success", Attempt: 1, CreatedAt: now, UpdatedAt: now},
	}
	rep := Aggregate(runs, 7*24*time.Hour, "main", 40)
	if len(rep.PerWorkflow) != 2 {
		t.Fatalf("want 2 workflows, got %d", len(rep.PerWorkflow))
	}
	// ci should be first (worse fail rate)
	if rep.PerWorkflow[0].Workflow != "ci" {
		t.Errorf("ordering: %+v", rep.PerWorkflow)
	}
	// ci: 2 success, 2 failure → 50%
	if rep.PerWorkflow[0].FailRate != 50 {
		t.Errorf("ci fail rate = %.1f, want 50", rep.PerWorkflow[0].FailRate)
	}
	// ci: 1 flaky recovered (attempt 2 success), 1 flaky broken (attempt 2 failure)
	if rep.PerWorkflow[0].FlakyRecovered != 1 || rep.PerWorkflow[0].FlakyBroken != 1 {
		t.Errorf("flaky: rec=%d broken=%d", rep.PerWorkflow[0].FlakyRecovered, rep.PerWorkflow[0].FlakyBroken)
	}
	// overall: 3 success 2 failure → 40% exactly, threshold 40 → not breached (strict >)
	if rep.Breached {
		t.Errorf("should not breach on equal fail rate: overall=%.1f", rep.Overall.FailRate)
	}
	// now with threshold 30, should breach
	rep2 := Aggregate(runs, 0, "", 30)
	if !rep2.Breached {
		t.Errorf("should breach at 30%%")
	}
}
