package lint

import (
	"encoding/json"
	"io"
)

// SARIF 2.1.0 minimal writer — enough for GitHub code scanning ingestion.
// Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
func WriteSARIF(w io.Writer, issues []Issue, version string) error {
	type msg struct {
		Text string `json:"text"`
	}
	type region struct {
		StartLine   int `json:"startLine"`
		StartColumn int `json:"startColumn,omitempty"`
	}
	type artifactLoc struct {
		URI string `json:"uri"`
	}
	type physLoc struct {
		ArtifactLocation artifactLoc `json:"artifactLocation"`
		Region           region      `json:"region"`
	}
	type location struct {
		PhysicalLocation physLoc `json:"physicalLocation"`
	}
	type result struct {
		RuleID    string     `json:"ruleId"`
		Level     string     `json:"level"`
		Message   msg        `json:"message"`
		Locations []location `json:"locations"`
	}
	type ruleShort struct {
		Text string `json:"text"`
	}
	type rule struct {
		ID               string    `json:"id"`
		Name             string    `json:"name"`
		ShortDescription ruleShort `json:"shortDescription"`
		DefaultConfig    struct {
			Level string `json:"level"`
		} `json:"defaultConfiguration"`
	}
	type driver struct {
		Name           string `json:"name"`
		Version        string `json:"version"`
		InformationURI string `json:"informationUri"`
		Rules          []rule `json:"rules"`
	}
	type tool struct {
		Driver driver `json:"driver"`
	}
	type run struct {
		Tool    tool     `json:"tool"`
		Results []result `json:"results"`
	}
	type sarif struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []run  `json:"runs"`
	}

	rules := make([]rule, 0, len(Rules))
	for _, r := range Rules {
		rr := rule{ID: r.ID, Name: r.Title}
		rr.ShortDescription.Text = r.Title
		rr.DefaultConfig.Level = sarifLevel(r.Severity)
		rules = append(rules, rr)
	}

	results := make([]result, 0, len(issues))
	for _, i := range issues {
		results = append(results, result{
			RuleID:  i.Kind,
			Level:   sarifLevel(i.Severity),
			Message: msg{Text: i.Message},
			Locations: []location{{
				PhysicalLocation: physLoc{
					ArtifactLocation: artifactLoc{URI: i.File},
					Region:           region{StartLine: i.Line, StartColumn: i.Col},
				},
			}},
		})
	}

	doc := sarif{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []run{{
			Tool: tool{Driver: driver{
				Name:           "ghactor",
				Version:        version,
				InformationURI: "https://github.com/kdairatchi/ghactor",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func sarifLevel(s Severity) string {
	switch s {
	case SevError:
		return "error"
	case SevWarning:
		return "warning"
	default:
		return "note"
	}
}
