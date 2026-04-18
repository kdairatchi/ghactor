// Package sarifdiff compares SARIF 2.1.0 reports for CI regression gating.
// Primary use case: compare a PR's SARIF output against a main-branch baseline
// and fail only when NEW findings appear.
package sarifdiff

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode"
)

// Result is a flat representation of one SARIF finding.
type Result struct {
	RuleID  string `json:"ruleId"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	Col     int    `json:"col"`
	Level   string `json:"level"`  // "error" | "warning" | "note"
	Message string `json:"message"`
}

// Diff holds the three-way partition produced by Compare.
type Diff struct {
	New       []Result `json:"new"`
	Fixed     []Result `json:"fixed"`
	Unchanged []Result `json:"unchanged"`
}

// Options controls Compare behaviour.
type Options struct {
	// LineSensitive, when true, includes the line number in the fingerprint so
	// that a finding that shifted to a different line is treated as Fixed+New
	// rather than Unchanged.
	LineSensitive bool
}

// ---------------------------------------------------------------------------
// SARIF parsing types — narrow struct that covers only what we need.
// ---------------------------------------------------------------------------

type sarifFile struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				Rules   []struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID    string `json:"ruleId"`
			RuleIndex int    `json:"ruleIndex"`
			Level     string `json:"level"`
			Message   struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine   int `json:"startLine"`
						StartColumn int `json:"startColumn"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

// ---------------------------------------------------------------------------
// Fingerprint normalisation
// ---------------------------------------------------------------------------

// normalisation regexes — compiled once at package init.
//
// Transformations applied (in order):
//  1. Collapse backslash path separators to forward slash.
//  2. Strip leading "./" or "/" from file URIs.
//  3. Replace 40-hex SHA strings with "<SHA>".
//  4. Replace semver tags ("v1.2.3" or "1.2.3") with "<TAG>".
//  5. Replace bare integers in "line N" / "col N" / ":N" position markers with "<N>".
//  6. Replace ISO-8601 timestamps with "<TS>".
//  7. Replace durations like "3m42s" or "120ms" with "<DUR>".
//  8. Collapse runs of Unicode whitespace to a single ASCII space.
//
// The baseline package (internal/baseline) has a compatible but narrower
// normalizer.  We implement our own here to avoid an import cycle and to add
// the additional patterns needed for SARIF messages (tags, durations, timestamps).
var (
	reHexSHA    = regexp.MustCompile(`\b[0-9a-fA-F]{40}\b`)
	reGitTag    = regexp.MustCompile(`\bv?[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[A-Za-z0-9.]+)?\b`)
	reLineCol   = regexp.MustCompile(`(?i)\b(?:line|col(?:umn)?)\s+[0-9]+\b`)
	reColonNum  = regexp.MustCompile(`:[0-9]+`)
	reTimestamp = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b`)
	reDuration  = regexp.MustCompile(`\b[0-9]+(?:ms|s|m|h)\b`)
	reSpaceRun  = regexp.MustCompile(`[\s\p{Zs}]+`)
)

// normalizeMessage strips volatile bits from a SARIF result message so that
// semantically identical findings produce identical fingerprints even when
// the underlying file shifts lines or SHAs rotate.
func normalizeMessage(msg string) string {
	s := msg
	s = reTimestamp.ReplaceAllString(s, "<TS>")
	s = reHexSHA.ReplaceAllString(s, "<SHA>")
	s = reGitTag.ReplaceAllString(s, "<TAG>")
	s = reLineCol.ReplaceAllString(s, "<N>")
	s = reColonNum.ReplaceAllString(s, ":<N>")
	s = reDuration.ReplaceAllString(s, "<DUR>")
	s = reSpaceRun.ReplaceAllStringFunc(s, func(r string) string {
		for _, c := range r {
			if !unicode.IsSpace(c) {
				return r
			}
		}
		return " "
	})
	return strings.TrimSpace(s)
}

// normalizeFile normalizes a file URI: backslashes → forward slash, strip
// leading "./" or "/".
func normalizeFile(uri string) string {
	f := strings.ReplaceAll(uri, `\`, "/")
	f = strings.TrimPrefix(f, "./")
	f = strings.TrimPrefix(f, "/")
	return f
}

// fingerprint computes a stable SHA-256 key for a Result.
// By default, line is excluded so that line shifts are not counted as new
// findings.  Pass line=r.Line when LineSensitive is true.
func fingerprint(r Result, includeLine bool) string {
	file := normalizeFile(r.File)
	msg := normalizeMessage(r.Message)
	var input string
	if includeLine {
		input = fmt.Sprintf("%s|%s|%d|%s", r.RuleID, file, r.Line, msg)
	} else {
		input = fmt.Sprintf("%s|%s|%s", r.RuleID, file, msg)
	}
	sum := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", sum)
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

// LoadFile parses a SARIF 2.1.0 file and returns a flat list of Results.
// If ruleId is absent but ruleIndex is present, the rule ID is resolved from
// the driver's rules catalog.
func LoadFile(path string) ([]Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sarifdiff: read %s: %w", path, err)
	}
	return parseBytes(path, data)
}

func parseBytes(name string, data []byte) ([]Result, error) {
	var sf sarifFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return nil, fmt.Errorf("sarifdiff: parse %s: %w", name, err)
	}

	var out []Result
	for _, run := range sf.Runs {
		// Build rule index → id lookup for the shortcut case.
		ruleByIndex := make(map[int]string, len(run.Tool.Driver.Rules))
		for i, r := range run.Tool.Driver.Rules {
			ruleByIndex[i] = r.ID
		}

		for _, sr := range run.Results {
			ruleID := sr.RuleID
			if ruleID == "" {
				ruleID = ruleByIndex[sr.RuleIndex]
			}

			var file string
			var line, col int
			if len(sr.Locations) > 0 {
				pl := sr.Locations[0].PhysicalLocation
				file = normalizeFile(pl.ArtifactLocation.URI)
				line = pl.Region.StartLine
				col = pl.Region.StartColumn
			}

			level := sr.Level
			if level == "" {
				level = "note"
			}

			out = append(out, Result{
				RuleID:  ruleID,
				File:    file,
				Line:    line,
				Col:     col,
				Level:   level,
				Message: sr.Message.Text,
			})
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

// Compare partitions (oldResults, newResults) into New, Fixed, and Unchanged.
//
//   - New: in newResults but not in oldResults (by fingerprint).
//   - Fixed: in oldResults but not in newResults (by fingerprint).
//   - Unchanged: fingerprint present in both.
//
// The Result values in Unchanged come from newResults so callers see current
// line numbers.
func Compare(oldResults, newResults []Result, opts Options) Diff {
	fp := func(r Result) string { return fingerprint(r, opts.LineSensitive) }

	oldSet := make(map[string]struct{}, len(oldResults))
	for _, r := range oldResults {
		oldSet[fp(r)] = struct{}{}
	}

	newSet := make(map[string]struct{}, len(newResults))
	for _, r := range newResults {
		newSet[fp(r)] = struct{}{}
	}

	var d Diff
	for _, r := range newResults {
		if _, inOld := oldSet[fp(r)]; inOld {
			d.Unchanged = append(d.Unchanged, r)
		} else {
			d.New = append(d.New, r)
		}
	}
	for _, r := range oldResults {
		if _, inNew := newSet[fp(r)]; !inNew {
			d.Fixed = append(d.Fixed, r)
		}
	}
	return d
}

// ---------------------------------------------------------------------------
// Merge
// ---------------------------------------------------------------------------

// Merge reads each SARIF file in paths, de-duplicates results by fingerprint
// (line-insensitive), and returns a valid SARIF 2.1.0 JSON document.
// The tool.driver.rules catalog is taken from the first file; results from
// subsequent files are appended with their ruleId inline (ruleIndex omitted
// in the merged output to stay simple and valid).
func Merge(paths []string) ([]byte, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("sarifdiff: merge requires at least one file")
	}

	type mergeResult struct {
		RuleID    string         `json:"ruleId,omitempty"`
		Level     string         `json:"level"`
		Message   map[string]any `json:"message"`
		Locations []any          `json:"locations"`
	}
	type mergeDriver struct {
		Name    string         `json:"name"`
		Version string         `json:"version,omitempty"`
		Rules   []map[string]any `json:"rules"`
	}
	type mergeRun struct {
		Tool    map[string]any `json:"tool"`
		Results []mergeResult  `json:"results"`
	}
	type mergeSARIF struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []mergeRun `json:"runs"`
	}

	// Read first file as the authoritative tool catalog.
	firstData, err := os.ReadFile(paths[0])
	if err != nil {
		return nil, fmt.Errorf("sarifdiff: merge read %s: %w", paths[0], err)
	}
	var firstRaw sarifFile
	if err := json.Unmarshal(firstData, &firstRaw); err != nil {
		return nil, fmt.Errorf("sarifdiff: merge parse %s: %w", paths[0], err)
	}

	// Collect canonical rules from all files for the merged catalog.
	rulesSeen := make(map[string]struct{})
	var mergedRules []map[string]any

	addRule := func(id, name string) {
		if id == "" {
			return
		}
		if _, already := rulesSeen[id]; already {
			return
		}
		rulesSeen[id] = struct{}{}
		r := map[string]any{"id": id}
		if name != "" {
			r["name"] = name
		}
		mergedRules = append(mergedRules, r)
	}

	if len(firstRaw.Runs) > 0 {
		for _, r := range firstRaw.Runs[0].Tool.Driver.Rules {
			addRule(r.ID, r.Name)
		}
	}

	// Load all flat results and deduplicate by fingerprint.
	seen := make(map[string]struct{})
	var allResults []Result
	// Also track per-path raw data for reconstructing SARIF locations.
	type rawEntry struct {
		r      Result
		level  string
		msgTxt string
	}
	var rawEntries []rawEntry

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("sarifdiff: merge read %s: %w", path, err)
		}
		var sf sarifFile
		if err := json.Unmarshal(data, &sf); err != nil {
			return nil, fmt.Errorf("sarifdiff: merge parse %s: %w", path, err)
		}
		for _, run := range sf.Runs {
			ruleByIndex := make(map[int]string, len(run.Tool.Driver.Rules))
			for i, r := range run.Tool.Driver.Rules {
				ruleByIndex[i] = r.ID
				addRule(r.ID, r.Name)
			}
			for _, sr := range run.Results {
				ruleID := sr.RuleID
				if ruleID == "" {
					ruleID = ruleByIndex[sr.RuleIndex]
				}
				var file string
				var line, col int
				if len(sr.Locations) > 0 {
					pl := sr.Locations[0].PhysicalLocation
					file = normalizeFile(pl.ArtifactLocation.URI)
					line = pl.Region.StartLine
					col = pl.Region.StartColumn
				}
				level := sr.Level
				if level == "" {
					level = "note"
				}
				r := Result{RuleID: ruleID, File: file, Line: line, Col: col, Level: level, Message: sr.Message.Text}
				fp := fingerprint(r, false)
				if _, dup := seen[fp]; dup {
					continue
				}
				seen[fp] = struct{}{}
				allResults = append(allResults, r)
				rawEntries = append(rawEntries, rawEntry{r: r, level: level, msgTxt: sr.Message.Text})
			}
		}
	}
	_ = allResults // used indirectly via rawEntries

	// Build merged SARIF results.
	results := make([]mergeResult, 0, len(rawEntries))
	for _, e := range rawEntries {
		loc := map[string]any{
			"physicalLocation": map[string]any{
				"artifactLocation": map[string]any{"uri": e.r.File},
				"region": map[string]any{
					"startLine":   e.r.Line,
					"startColumn": e.r.Col,
				},
			},
		}
		results = append(results, mergeResult{
			RuleID:    e.r.RuleID,
			Level:     e.level,
			Message:   map[string]any{"text": e.msgTxt},
			Locations: []any{loc},
		})
	}

	toolName := "ghactor"
	toolVersion := ""
	if len(firstRaw.Runs) > 0 {
		if n := firstRaw.Runs[0].Tool.Driver.Name; n != "" {
			toolName = n
		}
		toolVersion = firstRaw.Runs[0].Tool.Driver.Version
	}

	doc := mergeSARIF{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []mergeRun{
			{
				Tool: map[string]any{
					"driver": mergeDriver{
						Name:    toolName,
						Version: toolVersion,
						Rules:   mergedRules,
					},
				},
				Results: results,
			},
		},
	}

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("sarifdiff: merge marshal: %w", err)
	}
	return append(out, '\n'), nil
}
