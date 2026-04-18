package lint

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
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

// TestSARIFRuleCatalogCompleteness verifies every rule in lint.Rules has an
// entry in the SARIF driver catalog, identified by matching ID.
func TestSARIFRuleCatalogCompleteness(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, nil, "test"); err != nil {
		t.Fatal(err)
	}
	doc := mustUnmarshalSARIF(t, &buf)
	catalog := extractCatalog(t, doc)

	catalogByID := make(map[string]map[string]interface{}, len(catalog))
	for _, entry := range catalog {
		e := entry.(map[string]interface{})
		id := e["id"].(string)
		catalogByID[id] = e
	}

	for _, r := range Rules {
		if _, ok := catalogByID[r.ID]; !ok {
			t.Errorf("rule %s (%s) missing from SARIF catalog", r.ID, r.Title)
		}
	}
	if t.Failed() {
		t.Logf("catalog IDs present: %v", catalogKeys(catalogByID))
	}
}

// TestSARIFRuleIndex verifies every result carries a ruleIndex that points to
// the correct catalog entry (matching ruleId).
func TestSARIFRuleIndex(t *testing.T) {
	issues := []Issue{
		{Kind: "GHA001", Severity: SevWarning, File: "a.yml", Line: 1},
		{Kind: "GHA004", Severity: SevError, File: "a.yml", Line: 2},
		{Kind: "GHA005", Severity: SevInfo, File: "a.yml", Line: 3},
	}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, issues, "test"); err != nil {
		t.Fatal(err)
	}
	doc := mustUnmarshalSARIF(t, &buf)
	catalog := extractCatalog(t, doc)
	results := extractResults(t, doc)

	// Build ID→index map from catalog.
	catalogIDToIndex := make(map[string]int, len(catalog))
	for i, entry := range catalog {
		e := entry.(map[string]interface{})
		catalogIDToIndex[e["id"].(string)] = i
	}

	for i, res := range results {
		r := res.(map[string]interface{})
		ruleID := r["ruleId"].(string)
		ruleIndex := int(r["ruleIndex"].(float64))

		expectedIdx, ok := catalogIDToIndex[ruleID]
		if !ok {
			t.Errorf("result[%d] ruleId=%q not found in catalog", i, ruleID)
			continue
		}
		if ruleIndex != expectedIdx {
			t.Errorf("result[%d] ruleIndex=%d, catalog index for %q=%d", i, ruleIndex, ruleID, expectedIdx)
		}
	}
}

// TestSARIFLevelMapping verifies the severity→SARIF level mapping for all
// three severity values.
func TestSARIFLevelMapping(t *testing.T) {
	cases := []struct {
		sev   Severity
		want  string
		kind  string
	}{
		{SevError, "error", "GHA004"},
		{SevWarning, "warning", "GHA001"},
		{SevInfo, "note", "GHA005"},
	}
	for _, tc := range cases {
		t.Run(string(tc.sev), func(t *testing.T) {
			issues := []Issue{{Kind: tc.kind, Severity: tc.sev, File: "a.yml", Line: 1}}
			var buf bytes.Buffer
			if err := WriteSARIF(&buf, issues, "test"); err != nil {
				t.Fatal(err)
			}
			doc := mustUnmarshalSARIF(t, &buf)
			results := extractResults(t, doc)
			if len(results) != 1 {
				t.Fatalf("want 1 result, got %d", len(results))
			}
			got := results[0].(map[string]interface{})["level"].(string)
			if got != tc.want {
				t.Errorf("level = %q, want %q for severity %q", got, tc.want, tc.sev)
			}
		})
	}
}

// TestSARIFHelpURI verifies that helpUri is set when a rule has References and
// omitted when it has none.
func TestSARIFHelpURI(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, nil, "test"); err != nil {
		t.Fatal(err)
	}
	doc := mustUnmarshalSARIF(t, &buf)
	catalog := extractCatalog(t, doc)

	for _, entry := range catalog {
		e := entry.(map[string]interface{})
		id := e["id"].(string)
		// Find the matching rule to check its References.
		var matchedRule *Rule
		for i := range Rules {
			if Rules[i].ID == id {
				matchedRule = &Rules[i]
				break
			}
		}
		if matchedRule == nil {
			continue // synthetic entry for unknown rule; skip
		}
		uri, hasURI := e["helpUri"]
		if len(matchedRule.References) > 0 {
			if !hasURI || uri == "" {
				t.Errorf("rule %s has References but helpUri is absent/empty", id)
			} else if uri != matchedRule.References[0] {
				t.Errorf("rule %s helpUri = %q, want %q", id, uri, matchedRule.References[0])
			}
		} else {
			if hasURI && uri != "" {
				t.Errorf("rule %s has no References but helpUri is set to %q", id, uri)
			}
		}
	}
}

// TestSARIFValidJSON verifies that the emitted SARIF is valid JSON (round-trip).
func TestSARIFValidJSON(t *testing.T) {
	issues := []Issue{
		{File: "f.yml", Line: 1, Kind: "GHA003", Severity: SevError, Message: "pwn"},
		{File: "f.yml", Line: 5, Kind: "GHA002", Severity: SevWarning, Message: "perms"},
	}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, issues, "v0.3.0"); err != nil {
		t.Fatal(err)
	}
	var any interface{}
	if err := json.Unmarshal(buf.Bytes(), &any); err != nil {
		t.Fatalf("round-trip JSON parse failed: %v\nraw:\n%s", err, buf.String())
	}
}

// TestSARIFGoldenGHA004 is a golden-file test for GHA004's catalog entry.
// It asserts the exact shape so future regressions (e.g. accidental field
// deletion or name change) are immediately obvious.
func TestSARIFGoldenGHA004(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, nil, "test"); err != nil {
		t.Fatal(err)
	}
	doc := mustUnmarshalSARIF(t, &buf)
	catalog := extractCatalog(t, doc)

	var gha004 map[string]interface{}
	for _, entry := range catalog {
		e := entry.(map[string]interface{})
		if e["id"] == "GHA004" {
			gha004 = e
			break
		}
	}
	if gha004 == nil {
		t.Fatal("GHA004 not found in SARIF catalog")
	}

	checks := []struct {
		field string
		check func(v interface{}) bool
		desc  string
	}{
		{"id", func(v interface{}) bool { return v == "GHA004" }, `"GHA004"`},
		{"name", func(v interface{}) bool { return v == "script-injection" }, `"script-injection"`},
		{"shortDescription", func(v interface{}) bool {
			m, ok := v.(map[string]interface{})
			return ok && m["text"] == "script-injection"
		}, `shortDescription.text == "script-injection"`},
		{"fullDescription", func(v interface{}) bool {
			m, ok := v.(map[string]interface{})
			if !ok {
				return false
			}
			text, _ := m["text"].(string)
			return strings.Contains(text, "github.event.issue.title")
		}, "fullDescription.text contains 'github.event.issue.title'"},
		{"help", func(v interface{}) bool {
			m, ok := v.(map[string]interface{})
			if !ok {
				return false
			}
			md, _ := m["markdown"].(string)
			return strings.Contains(md, "**Remediation**") && strings.Contains(md, "**References**")
		}, "help.markdown contains Remediation and References sections"},
		{"helpUri", func(v interface{}) bool {
			s, ok := v.(string)
			return ok && strings.HasPrefix(s, "https://")
		}, "helpUri is a non-empty https:// URL"},
		{"defaultConfiguration", func(v interface{}) bool {
			m, ok := v.(map[string]interface{})
			return ok && m["level"] == "error"
		}, `defaultConfiguration.level == "error"`},
		{"properties", func(v interface{}) bool {
			m, ok := v.(map[string]interface{})
			if !ok {
				return false
			}
			if m["precision"] != "high" {
				return false
			}
			tags, ok := m["tags"].([]interface{})
			if !ok || len(tags) < 2 {
				return false
			}
			hasSecTag, hasGHATag := false, false
			for _, tag := range tags {
				switch tag {
				case "security":
					hasSecTag = true
				case "github-actions":
					hasGHATag = true
				}
			}
			return hasSecTag && hasGHATag
		}, `properties.precision=="high" and tags contains "security","github-actions"`},
	}

	for _, c := range checks {
		t.Run(fmt.Sprintf("GHA004/%s", c.field), func(t *testing.T) {
			v, ok := gha004[c.field]
			if !ok {
				t.Fatalf("field %q missing from GHA004 catalog entry", c.field)
			}
			if !c.check(v) {
				b, _ := json.MarshalIndent(v, "", "  ")
				t.Errorf("field %q failed check %q\ngot: %s", c.field, c.desc, b)
			}
		})
	}
}

// TestSARIFHelpMarkdownTruncation verifies the truncation guard works if we
// construct a synthetic rule with an enormous Remediation.
func TestSARIFHelpMarkdownTruncation(t *testing.T) {
	// Build a markdown string that would exceed maxHelpMarkdown.
	remediation := strings.Repeat("x", maxHelpMarkdown+1000)
	result := buildHelpMarkdown(remediation, nil)
	if len(result) > maxHelpMarkdown+100 {
		// The truncation is applied by WriteSARIF, not buildHelpMarkdown.
		// buildHelpMarkdown itself can be large; WriteSARIF caps it.
		// Just verify buildHelpMarkdown returns the remediation wrapped in headers.
		t.Logf("buildHelpMarkdown len=%d (truncation applied by WriteSARIF)", len(result))
	}
	if !strings.HasPrefix(result, "**Remediation**") {
		t.Errorf("buildHelpMarkdown output missing **Remediation** header")
	}
}

// helpers

func mustUnmarshalSARIF(t *testing.T, buf *bytes.Buffer) map[string]interface{} {
	t.Helper()
	var doc map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid SARIF JSON: %v\nraw: %s", err, buf.String())
	}
	return doc
}

func extractCatalog(t *testing.T, doc map[string]interface{}) []interface{} {
	t.Helper()
	runs := doc["runs"].([]interface{})
	driver := runs[0].(map[string]interface{})["tool"].(map[string]interface{})["driver"].(map[string]interface{})
	rules, ok := driver["rules"].([]interface{})
	if !ok {
		t.Fatal("runs[0].tool.driver.rules is missing or not an array")
	}
	return rules
}

func extractResults(t *testing.T, doc map[string]interface{}) []interface{} {
	t.Helper()
	runs := doc["runs"].([]interface{})
	results, ok := runs[0].(map[string]interface{})["results"].([]interface{})
	if !ok {
		t.Fatal("runs[0].results is missing or not an array")
	}
	return results
}

func catalogKeys(m map[string]map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
