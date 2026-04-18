package sarifdiff

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// colour helpers — constructed once.
var (
	cRed   = color.New(color.FgRed, color.Bold).SprintFunc()
	cGreen = color.New(color.FgGreen, color.Bold).SprintFunc()
	cDim   = color.New(color.Faint).SprintFunc()
	cBold  = color.New(color.Bold).SprintFunc()
)

// Cmd returns the `sarif` subcommand group (diff, stats, merge).
//
// Wire it in cmd/ghactor/main.go:
//
//	import "github.com/kdairatchi/ghactor/internal/sarifdiff"
//	root.AddCommand(sarifdiff.Cmd())
func Cmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "sarif",
		Short: "Utilities for working with SARIF 2.1.0 reports",
		Long: `sarif provides three subcommands for SARIF report management:

  diff    Compare two reports; gate CI on new findings.
  stats   Show a breakdown of a single report.
  merge   Union two or more reports (de-dup by fingerprint).`,
	}
	root.AddCommand(diffCmd(), statsCmd(), mergeCmd())
	return root
}

// ---------------------------------------------------------------------------
// sarif diff
// ---------------------------------------------------------------------------

func diffCmd() *cobra.Command {
	var (
		jsonOut         bool
		failOnNew       bool
		lineSensitive   bool
		includeUnchanged bool
	)

	c := &cobra.Command{
		Use:   "diff <old.sarif> <new.sarif>",
		Short: "Compare two SARIF reports; exit 1 when --fail-on-new and new findings exist",
		Long: `diff loads two SARIF 2.1.0 files and partitions results into:

  new       — findings present in NEW but not in OLD
  fixed     — findings present in OLD but not in NEW
  unchanged — findings present in both (matched by fingerprint)

Fingerprint key: sha256(ruleId + normalised_file + normalised_message).
Line numbers are excluded from the key by default so that shifted findings
are still considered unchanged.  Pass --line-sensitive to treat line shifts
as a Fixed + New pair.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			oldResults, err := LoadFile(args[0])
			if err != nil {
				return err
			}
			newResults, err := LoadFile(args[1])
			if err != nil {
				return err
			}

			diff := Compare(oldResults, newResults, Options{LineSensitive: lineSensitive})

			if jsonOut {
				type counts struct {
					New       int `json:"new"`
					Fixed     int `json:"fixed"`
					Unchanged int `json:"unchanged"`
				}
				type jsonOutput struct {
					New       []Result `json:"new"`
					Fixed     []Result `json:"fixed"`
					Unchanged []Result `json:"unchanged"`
					Counts    counts   `json:"counts"`
				}
				return json.NewEncoder(os.Stdout).Encode(jsonOutput{
					New:       nilSlice(diff.New),
					Fixed:     nilSlice(diff.Fixed),
					Unchanged: nilSlice(diff.Unchanged),
					Counts: counts{
						New:       len(diff.New),
						Fixed:     len(diff.Fixed),
						Unchanged: len(diff.Unchanged),
					},
				})
			}

			renderDiff(diff, includeUnchanged)

			if failOnNew && len(diff.New) > 0 {
				os.Exit(1)
			}
			return nil
		},
	}

	c.Flags().BoolVar(&jsonOut, "json", false, "emit JSON instead of human-readable text")
	c.Flags().BoolVar(&failOnNew, "fail-on-new", false, "exit 1 when new findings are present")
	c.Flags().BoolVar(&lineSensitive, "line-sensitive", false, "include line number in fingerprint (line shifts count as Fixed+New)")
	c.Flags().BoolVar(&includeUnchanged, "include-unchanged", false, "also show unchanged findings in text output")
	return c
}

// renderDiff prints a grouped, colour-coded diff to stdout.
func renderDiff(d Diff, includeUnchanged bool) {
	type entry struct {
		prefix string
		color  func(a ...any) string
		r      Result
	}

	// Group by file for a compact display.
	type fileGroup struct {
		file    string
		entries []entry
	}
	groups := make(map[string]*fileGroup)
	order := []string{}

	add := func(prefix string, col func(a ...any) string, r Result) {
		if _, ok := groups[r.File]; !ok {
			groups[r.File] = &fileGroup{file: r.File}
			order = append(order, r.File)
		}
		groups[r.File].entries = append(groups[r.File].entries, entry{prefix, col, r})
	}

	for _, r := range d.New {
		add("+", func(a ...any) string { return cRed(a...) }, r)
	}
	for _, r := range d.Fixed {
		add("-", func(a ...any) string { return cGreen(a...) }, r)
	}
	if includeUnchanged {
		for _, r := range d.Unchanged {
			add(" ", func(a ...any) string { return cDim(a...) }, r)
		}
	}

	sort.Strings(order)

	for _, file := range order {
		g := groups[file]
		fmt.Println(cBold(g.file))
		for _, e := range g.entries {
			line := fmt.Sprintf("%s %s:%d [%s] %s",
				e.prefix,
				e.r.File,
				e.r.Line,
				e.r.RuleID,
				e.r.Message,
			)
			fmt.Println(e.color(line))
		}
	}

	if len(d.New)+len(d.Fixed)+len(d.Unchanged) > 0 || true {
		fmt.Printf("\n%s %d new, %d fixed, %d unchanged\n",
			cDim("summary:"), len(d.New), len(d.Fixed), len(d.Unchanged))
	}
}

// nilSlice returns an empty (non-nil) slice if in is nil, so JSON encodes as
// [] rather than null.
func nilSlice(in []Result) []Result {
	if in == nil {
		return []Result{}
	}
	return in
}

// ---------------------------------------------------------------------------
// sarif stats
// ---------------------------------------------------------------------------

func statsCmd() *cobra.Command {
	var jsonOut bool

	c := &cobra.Command{
		Use:   "stats <file.sarif>",
		Short: "Show a count breakdown of a SARIF report",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			results, err := LoadFile(args[0])
			if err != nil {
				return err
			}

			byRule := make(map[string]int)
			byFile := make(map[string]int)
			byLevel := make(map[string]int)
			for _, r := range results {
				byRule[r.RuleID]++
				byFile[r.File]++
				byLevel[r.Level]++
			}

			if jsonOut {
				type statsJSON struct {
					Total   int            `json:"total"`
					ByLevel map[string]int `json:"by_level"`
					ByRule  map[string]int `json:"by_rule"`
					ByFile  map[string]int `json:"by_file"`
				}
				return json.NewEncoder(os.Stdout).Encode(statsJSON{
					Total:   len(results),
					ByLevel: byLevel,
					ByRule:  byRule,
					ByFile:  byFile,
				})
			}

			fmt.Printf("%s %d total\n\n", cBold("stats:"), len(results))

			fmt.Println(cDim("by level"))
			for _, lvl := range []string{"error", "warning", "note"} {
				if n := byLevel[lvl]; n > 0 {
					fmt.Printf("  %-10s %d\n", lvl, n)
				}
			}

			if len(byRule) > 0 {
				fmt.Println()
				fmt.Println(cDim("by rule"))
				for _, k := range sortedKeys(byRule) {
					fmt.Printf("  %-12s %d\n", k, byRule[k])
				}
			}

			if len(byFile) > 0 {
				fmt.Println()
				fmt.Println(cDim("by file"))
				for _, k := range sortedKeys(byFile) {
					fmt.Printf("  %-50s %d\n", k, byFile[k])
				}
			}

			return nil
		},
	}

	c.Flags().BoolVar(&jsonOut, "json", false, "emit JSON")
	return c
}

// ---------------------------------------------------------------------------
// sarif merge
// ---------------------------------------------------------------------------

func mergeCmd() *cobra.Command {
	var out string

	c := &cobra.Command{
		Use:   "merge <file.sarif>... [-o combined.sarif]",
		Short: "Union SARIF reports, deduplicating by fingerprint",
		Long: `merge reads two or more SARIF 2.1.0 files, de-duplicates results by
fingerprint (ruleId + normalised_file + normalised_message, line-insensitive),
and writes a single combined SARIF document.

The tool.driver.rules catalog is built from the union of all input files.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := Merge(args)
			if err != nil {
				return err
			}

			if out == "" || out == "-" {
				_, err = os.Stdout.Write(data)
				return err
			}

			if err := os.WriteFile(out, data, 0o644); err != nil {
				return fmt.Errorf("sarifdiff: write %s: %w", out, err)
			}
			fmt.Fprintf(os.Stderr, "wrote %s (%s)\n", out, humanSize(len(data)))
			return nil
		},
	}

	c.Flags().StringVarP(&out, "out", "o", "", "output file (default: stdout)")
	return c
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func humanSize(n int) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%dB", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.1fKiB", float64(n)/1024)
	default:
		return fmt.Sprintf("%.1fMiB", float64(n)/(1024*1024))
	}
}

