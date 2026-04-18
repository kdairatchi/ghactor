package explain_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kdairatchi/ghactor/internal/explain"
)

// runCmd executes the explain command with the given args and returns
// stdout and any error.
func runCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := explain.Cmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

func TestExplain_UnknownID(t *testing.T) {
	_, err := runCmd(t, "GHA999")
	if err == nil {
		t.Fatal("expected error for unknown rule ID, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "GHA999") {
		t.Errorf("error should mention the unknown ID, got: %s", msg)
	}
	// Error message should suggest known IDs.
	if !strings.Contains(msg, "GHA001") {
		t.Errorf("error should list known IDs including GHA001, got: %s", msg)
	}
	if !strings.Contains(msg, "Known rules") {
		t.Errorf("error should say 'Known rules', got: %s", msg)
	}
}

func TestExplain_KnownID_GHA001(t *testing.T) {
	out, err := runCmd(t, "GHA001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "GHA001") {
		t.Errorf("output should contain the rule ID, got:\n%s", out)
	}
	if !strings.Contains(out, "unpinned-action") {
		t.Errorf("output should contain the rule title, got:\n%s", out)
	}
	// Description snippet.
	if !strings.Contains(out, "supply-chain") {
		t.Errorf("output should contain description snippet 'supply-chain', got:\n%s", out)
	}
	// Fix example section.
	if !strings.Contains(out, "Fix example") {
		t.Errorf("output should contain 'Fix example' section, got:\n%s", out)
	}
	if !strings.Contains(out, "Before") || !strings.Contains(out, "After") {
		t.Errorf("output should contain Before/After fix examples, got:\n%s", out)
	}
}

func TestExplain_JSONFlag_GHA001(t *testing.T) {
	out, err := runCmd(t, "GHA001", "--json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var card explain.Card
	if err := json.Unmarshal([]byte(out), &card); err != nil {
		t.Fatalf("--json output is not valid JSON: %v\noutput:\n%s", err, out)
	}
	if card.ID != "GHA001" {
		t.Errorf("JSON card.id = %q, want GHA001", card.ID)
	}
	if card.Title == "" {
		t.Error("JSON card.title should not be empty")
	}
	if card.Description == "" {
		t.Error("JSON card.description should not be empty")
	}
	if card.Remediation == "" {
		t.Error("JSON card.remediation should not be empty")
	}
	if len(card.References) == 0 {
		t.Error("JSON card.references should not be empty")
	}
	if card.FixBefore == "" || card.FixAfter == "" {
		t.Error("JSON card fix_before/fix_after should be set for GHA001")
	}
	if card.Severity == "" {
		t.Error("JSON card.severity should not be empty")
	}
}

func TestExplain_CaseInsensitive(t *testing.T) {
	// The command should accept lowercase IDs.
	out, err := runCmd(t, "gha004")
	if err != nil {
		t.Fatalf("lowercase ID should work, got error: %v", err)
	}
	if !strings.Contains(out, "GHA004") {
		t.Errorf("output should contain GHA004, got:\n%s", out)
	}
}

func TestExplain_NewRules(t *testing.T) {
	// Spot-check that all four new rules are reachable.
	for _, id := range []string{"GHA020", "GHA021", "GHA022", "GHA023"} {
		t.Run(id, func(t *testing.T) {
			out, err := runCmd(t, id)
			if err != nil {
				t.Fatalf("explain %s returned error: %v", id, err)
			}
			if !strings.Contains(out, id) {
				t.Errorf("output for %s should contain the rule ID, got:\n%s", id, out)
			}
			if !strings.Contains(out, "Fix example") {
				t.Errorf("output for %s should contain Fix example section, got:\n%s", id, out)
			}
		})
	}
}

func TestExplain_JSONAllFields(t *testing.T) {
	// Verify all required top-level fields are present in JSON output for GHA004.
	out, err := runCmd(t, "GHA004", "--json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	required := []string{"id", "title", "severity", "description", "remediation", "references"}
	for _, field := range required {
		if _, ok := m[field]; !ok {
			t.Errorf("JSON output missing field %q", field)
		}
	}
}

func TestExplain_ConfigGatedNote(t *testing.T) {
	// The text output should always contain the config-gated note about GHA008/GHA010.
	out, err := runCmd(t, "GHA001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "GHA008") {
		t.Errorf("output should mention GHA008 config-gated note, got:\n%s", out)
	}
	if !strings.Contains(out, "GHA010") {
		t.Errorf("output should mention GHA010 config-gated note, got:\n%s", out)
	}
}
