package lint

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// maxHelpMarkdown is a belt-and-suspenders cap on the markdown help text we
// embed in the SARIF rule catalog. GitHub Code Scanning imposes no documented
// hard limit, but very large payloads can be rejected by some ingestion paths.
const maxHelpMarkdown = 8000

// WriteSARIF writes a SARIF 2.1.0 document to w.
// The tool driver includes a full rule catalog so GitHub Code Scanning can
// display rich descriptions, remediation guidance, and help URIs.
// Each result carries a ruleIndex that points to its entry in the catalog.
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
		RuleIndex int        `json:"ruleIndex"`
		Level     string     `json:"level"`
		Message   msg        `json:"message"`
		Locations []location `json:"locations"`
	}

	type ruleHelp struct {
		Text     string `json:"text"`
		Markdown string `json:"markdown"`
	}
	type ruleDefaultConfig struct {
		Level string `json:"level"`
	}
	type ruleShortDesc struct {
		Text string `json:"text"`
	}
	type ruleFullDesc struct {
		Text string `json:"text"`
	}
	type ruleProperties struct {
		Precision string   `json:"precision"`
		Tags      []string `json:"tags"`
	}
	type rule struct {
		ID                   string            `json:"id"`
		Name                 string            `json:"name"`
		ShortDescription     ruleShortDesc     `json:"shortDescription"`
		FullDescription      ruleFullDesc      `json:"fullDescription"`
		Help                 *ruleHelp         `json:"help,omitempty"`
		HelpURI              string            `json:"helpUri,omitempty"`
		DefaultConfiguration ruleDefaultConfig `json:"defaultConfiguration"`
		Properties           ruleProperties    `json:"properties"`
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

	// Build rule catalog and an ID→index lookup for result emission.
	ruleIndex := make(map[string]int, len(Rules))
	catalog := make([]rule, 0, len(Rules))
	for i, r := range Rules {
		ruleIndex[r.ID] = i

		var helpURI string
		if len(r.References) > 0 {
			helpURI = r.References[0]
		}

		var help *ruleHelp
		if r.Remediation != "" {
			helpText := r.Remediation
			helpMD := buildHelpMarkdown(r.Remediation, r.References)
			if len(helpMD) > maxHelpMarkdown {
				helpMD = helpMD[:maxHelpMarkdown]
			}
			help = &ruleHelp{Text: helpText, Markdown: helpMD}
		}

		entry := rule{
			ID:               r.ID,
			Name:             r.Title,
			ShortDescription: ruleShortDesc{Text: r.Title},
			FullDescription:  ruleFullDesc{Text: r.Description},
			Help:             help,
			HelpURI:          helpURI,
			DefaultConfiguration: ruleDefaultConfig{
				Level: sarifLevel(r.Severity),
			},
			Properties: ruleProperties{
				Precision: "high",
				Tags:      []string{"security", "github-actions"},
			},
		}
		catalog = append(catalog, entry)
	}

	// Build results, resolving ruleIndex from the catalog.
	results := make([]result, 0, len(issues))
	for _, i := range issues {
		idx, ok := ruleIndex[i.Kind]
		if !ok {
			// Issues from actionlint or unknown rules: append a synthetic
			// catalog entry so ruleIndex is always valid.
			idx = len(catalog)
			catalog = append(catalog, rule{
				ID:               i.Kind,
				Name:             i.Kind,
				ShortDescription: ruleShortDesc{Text: i.Kind},
				FullDescription:  ruleFullDesc{Text: i.Kind},
				DefaultConfiguration: ruleDefaultConfig{
					Level: sarifLevel(i.Severity),
				},
				Properties: ruleProperties{
					Precision: "high",
					Tags:      []string{"security", "github-actions"},
				},
			})
			ruleIndex[i.Kind] = idx
		}
		results = append(results, result{
			RuleID:    i.Kind,
			RuleIndex: idx,
			Level:     sarifLevel(i.Severity),
			Message:   msg{Text: i.Message},
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
				Rules:          catalog,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// buildHelpMarkdown renders the Remediation and References sections of a rule
// as Markdown, suitable for display in GitHub Code Scanning.
func buildHelpMarkdown(remediation string, references []string) string {
	var sb strings.Builder
	sb.WriteString("**Remediation**\n\n")
	sb.WriteString(remediation)
	if len(references) > 0 {
		sb.WriteString("\n\n**References**\n\n")
		for _, r := range references {
			fmt.Fprintf(&sb, "- %s\n", r)
		}
	}
	return sb.String()
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
