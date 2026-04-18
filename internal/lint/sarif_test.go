package lint

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestSARIFShape(t *testing.T) {
	issues := []Issue{
		{File: ".github/workflows/ci.yml", Line: 10, Col: 9, Kind: "GHA001",
			Severity: SevWarning, Message: "unpinned", Source: "ghactor"},
		{File: ".github/workflows/ci.yml", Line: 14, Col: 1, Kind: "GHA004",
			Severity: SevError, Message: "injection", Source: "ghactor"},
	}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, issues, "test"); err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", doc["version"])
	}
	runs := doc["runs"].([]interface{})
	if len(runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(runs))
	}
	results := runs[0].(map[string]interface{})["results"].([]interface{})
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2", len(results))
	}
	r0 := results[0].(map[string]interface{})
	if r0["ruleId"] != "GHA001" || r0["level"] != "warning" {
		t.Errorf("result[0] = %+v", r0)
	}
	r1 := results[1].(map[string]interface{})
	if r1["level"] != "error" {
		t.Errorf("result[1] level = %v, want error", r1["level"])
	}
}
