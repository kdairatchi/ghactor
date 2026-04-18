// Package explain provides the `ghactor explain <RULE_ID>` command.
// It looks up a rule by ID and prints a structured card with description,
// remediation, references, and a before/after YAML fix example.
package explain

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kdairatchi/ghactor/internal/lint"
)

// Card is the machine-readable representation of a rule explanation.
type Card struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
	References  []string `json:"references"`
	FixBefore   string   `json:"fix_before,omitempty"`
	FixAfter    string   `json:"fix_after,omitempty"`
}

// fixExamples holds per-rule before/after YAML snippets.
// Keys are rule IDs. Both "before" and "after" are stored as a two-element array.
var fixExamples = map[string][2]string{
	"GHA001": {
		`jobs:
  build:
    steps:
      - uses: actions/checkout@v4  # mutable tag`,
		`jobs:
  build:
    steps:
      # Pin to the 40-char SHA that tag v4 currently resolves to.
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4`,
	},
	"GHA002": {
		`name: ci
on: [push]
# No permissions: block — defaults to write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683`,
		`name: ci
on: [push]
permissions:
  contents: read  # deny all, grant only what is needed
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683`,
	},
	"GHA003": {
		`on: pull_request_target
jobs:
  check:
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # untrusted code!`,
		`on: pull_request_target
jobs:
  check:
    # Split into two workflows: pull_request (untrusted) + workflow_run (privileged).
    # Never check out the PR head ref in a pull_request_target workflow with secrets.
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        # ref omitted — checks out the base branch (safe)`,
	},
	"GHA004": {
		`steps:
  - name: greet
    run: echo "Hello ${{ github.event.issue.title }}"  # injection!`,
		`steps:
  - name: greet
    env:
      ISSUE_TITLE: ${{ github.event.issue.title }}
    run: echo "Hello $ISSUE_TITLE"  # value treated as data, not code`,
	},
	"GHA020": {
		`permissions:
  contents: write      # unused write scope
  pull-requests: write # unused write scope
jobs:
  test:
    steps:
      - run: go test ./...`,
		`permissions:
  contents: read  # minimal scope; escalate per-job only if needed
jobs:
  test:
    steps:
      - run: go test ./...`,
	},
	"GHA021": {
		`on:
  workflow_call:
    inputs:
      environment:
        description: Target environment
        required: true
        # No type: — implicit string, validation disabled`,
		`on:
  workflow_call:
    inputs:
      environment:
        description: Target environment
        required: true
        type: string  # explicit; enables GitHub input validation`,
	},
	"GHA022": {
		`jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
    steps:
      - run: go test ./...  # no shell: — pwsh on Windows, bash on Linux`,
		`jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
    steps:
      - shell: bash  # consistent across all platforms
        run: go test ./...`,
	},
	"GHA023": {
		`jobs:
  test:
    container:
      image: node:20  # mutable tag — registry can swap layers`,
		`jobs:
  test:
    container:
      # Resolve with: crane digest node:20
      image: node:20@sha256:a9f26cf4c8b413f4e05a2c2a5dfd4cd7cb93a10e45cce0e2d5e1d92637cfbec2`,
	},
}

// configGatedNote is printed after the rule card for rules that are not in the static slice.
const configGatedNote = "\nNote: GHA008 (tag-drift), GHA010 (denied-action), and GHA030 (allow-actions) " +
	"require runtime config and are not listed above. Run `ghactor rules --verbose` to see all rules."

// Cmd returns the cobra.Command for `ghactor explain <RULE_ID>`.
func Cmd() *cobra.Command {
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "explain <RULE_ID>",
		Short: "Print a detailed explanation and fix example for a rule",
		Long: `Print the full description, remediation guidance, references, and a before/after
YAML fix example for a ghactor security rule.

Example:
  ghactor explain GHA004
  ghactor explain GHA001 --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := strings.ToUpper(strings.TrimSpace(args[0]))

			allRules := append([]lint.Rule{}, lint.Rules...)
			ruleMap := make(map[string]lint.Rule, len(allRules))
			for _, r := range allRules {
				ruleMap[r.ID] = r
			}

			r, ok := ruleMap[id]
			if !ok {
				ids := make([]string, 0, len(ruleMap))
				for k := range ruleMap {
					ids = append(ids, k)
				}
				sort.Strings(ids)
				return fmt.Errorf("unknown rule %q\n\nKnown rules: %s%s",
					id, strings.Join(ids, ", "), configGatedNote)
			}

			card := Card{
				ID:          r.ID,
				Title:       r.Title,
				Severity:    string(r.Severity),
				Description: r.Description,
				Remediation: r.Remediation,
				References:  r.References,
			}
			if ex, ok := fixExamples[r.ID]; ok {
				card.FixBefore = ex[0]
				card.FixAfter = ex[1]
			}

			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(card)
			}

			printCard(cmd, card)
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit machine-readable JSON")
	return cmd
}

// printCard writes a human-readable rule card to the command's output writer.
func printCard(cmd *cobra.Command, c Card) {
	w := cmd.OutOrStdout()

	fmt.Fprintf(w, "Rule:        %s — %s\n", c.ID, c.Title)
	fmt.Fprintf(w, "Severity:    %s\n", c.Severity)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Description:")
	fmt.Fprintln(w, wrap(c.Description, 72, "  "))
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Remediation:")
	fmt.Fprintln(w, wrap(c.Remediation, 72, "  "))
	fmt.Fprintln(w)

	if len(c.References) > 0 {
		fmt.Fprintln(w, "References:")
		for _, ref := range c.References {
			fmt.Fprintf(w, "  - %s\n", ref)
		}
		fmt.Fprintln(w)
	}

	if c.FixBefore != "" || c.FixAfter != "" {
		fmt.Fprintln(w, "Fix example:")
		if c.FixBefore != "" {
			fmt.Fprintln(w, "  Before:")
			for _, line := range strings.Split(c.FixBefore, "\n") {
				fmt.Fprintf(w, "    %s\n", line)
			}
		}
		if c.FixAfter != "" {
			fmt.Fprintln(w, "  After:")
			for _, line := range strings.Split(c.FixAfter, "\n") {
				fmt.Fprintf(w, "    %s\n", line)
			}
		}
	}

	fmt.Fprintln(w, configGatedNote)
}

// wrap performs simple word-wrapping of s at maxWidth columns, prefixing each
// line with indent.
func wrap(s string, maxWidth int, indent string) string {
	effective := maxWidth - len(indent)
	if effective <= 0 {
		effective = maxWidth
	}

	var sb strings.Builder
	paragraphs := strings.Split(s, "\n")
	for pi, para := range paragraphs {
		words := strings.Fields(para)
		if len(words) == 0 {
			if pi > 0 {
				sb.WriteString(indent)
				sb.WriteByte('\n')
			}
			continue
		}
		lineLen := 0
		sb.WriteString(indent)
		for i, w := range words {
			if i == 0 {
				sb.WriteString(w)
				lineLen = len(w)
			} else if lineLen+1+len(w) > effective {
				sb.WriteByte('\n')
				sb.WriteString(indent)
				sb.WriteString(w)
				lineLen = len(w)
			} else {
				sb.WriteByte(' ')
				sb.WriteString(w)
				lineLen += 1 + len(w)
			}
		}
		if pi < len(paragraphs)-1 {
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}
