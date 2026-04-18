// Package baseline implements the ghactor baseline subcommand for legacy-repo adoption.
// It lets users snapshot current lint findings as fingerprints, then report only new
// findings on subsequent runs so teams can adopt linting incrementally.
package baseline

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/kdairatchi/ghactor/internal/lint"
	"github.com/spf13/cobra"
)

const (
	defaultBaselineFile = ".ghactor-baseline.json"
	defaultWorkflowDir  = ".github/workflows"
	generatorTag        = "ghactor 0.2.0"
	fileVersion         = 1
)

// Fingerprint is a stable identifier for a single lint finding.
// Line and Col are intentionally excluded from the hash so that
// nearby unrelated edits do not invalidate the suppression.
type Fingerprint struct {
	File string `json:"file"`
	Rule string `json:"rule"`
	Hash string `json:"hash"`
}

// File is the on-disk representation of a baseline snapshot.
type File struct {
	Version      int           `json:"version"`
	Generated    time.Time     `json:"generated"`
	Generator    string        `json:"generator"`
	Fingerprints []Fingerprint `json:"fingerprints"`
}

// compiled normalisation patterns (package-level to avoid recompilation per call).
var (
	reLineMarker   = regexp.MustCompile(`:[0-9]+`)
	reHexSHA       = regexp.MustCompile(`\b[0-9a-fA-F]{40}\b`)
	reSemVer       = regexp.MustCompile(`[0-9]+\.[0-9]+\.[0-9]+`)
	reSpaceRun     = regexp.MustCompile(`[\s\p{Zs}]+`)
)

// normalizeMessage strips volatile bits from a lint message so that the same
// logical finding produces the same fingerprint across minor file edits.
func normalizeMessage(msg string) string {
	s := msg
	s = reLineMarker.ReplaceAllString(s, "")
	s = reHexSHA.ReplaceAllString(s, "<sha>")
	s = reSemVer.ReplaceAllString(s, "<ver>")
	// collapse any Unicode whitespace runs to a single ASCII space
	s = reSpaceRun.ReplaceAllStringFunc(s, func(r string) string {
		// keep only runs that contain at least one non-space printable rune
		for _, c := range r {
			if !unicode.IsSpace(c) {
				return r
			}
		}
		return " "
	})
	return strings.TrimSpace(s)
}

// FingerprintIssue computes a deterministic SHA-256 fingerprint for a lint finding.
// The hash covers file path, rule ID, and the normalised message — NOT line/col.
func FingerprintIssue(iss lint.Issue) string {
	normalised := normalizeMessage(iss.Message)
	input := iss.File + "|" + iss.Kind + "|" + normalised
	sum := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", sum)
}

// Load reads a baseline JSON file from path.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("baseline load %s: %w", path, err)
	}
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("baseline parse %s: %w", path, err)
	}
	return &f, nil
}

// Save writes the baseline to path, creating or overwriting the file.
func Save(path string, f *File) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("baseline marshal: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("baseline write %s: %w", path, err)
	}
	return nil
}

// Filter partitions issues into those suppressed by the baseline and genuinely new ones.
func Filter(issues []lint.Issue, f *File) (suppressed, newOnes []lint.Issue) {
	known := make(map[string]struct{}, len(f.Fingerprints))
	for _, fp := range f.Fingerprints {
		known[fp.Hash] = struct{}{}
	}
	for _, iss := range issues {
		h := FingerprintIssue(iss)
		if _, ok := known[h]; ok {
			suppressed = append(suppressed, iss)
		} else {
			newOnes = append(newOnes, iss)
		}
	}
	return suppressed, newOnes
}

// buildFingerprints creates a deduplicated, sorted slice of Fingerprint values from issues.
func buildFingerprints(issues []lint.Issue) []Fingerprint {
	seen := make(map[string]struct{}, len(issues))
	var fps []Fingerprint
	for _, iss := range issues {
		h := FingerprintIssue(iss)
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		fps = append(fps, Fingerprint{
			File: iss.File,
			Rule: iss.Kind,
			Hash: h,
		})
	}
	sort.Slice(fps, func(i, j int) bool {
		if fps[i].File != fps[j].File {
			return fps[i].File < fps[j].File
		}
		if fps[i].Rule != fps[j].Rule {
			return fps[i].Rule < fps[j].Rule
		}
		return fps[i].Hash < fps[j].Hash
	})
	return fps
}

// Cmd returns the cobra.Command for the `baseline` subcommand tree.
func Cmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "baseline",
		Short: "Manage lint baseline for incremental adoption",
		Long: `baseline lets you snapshot current lint findings and only fail on new ones.

Workflow:
  1. ghactor baseline create   # snapshot today's findings
  2. ... fix issues over time ...
  3. ghactor baseline status   # see only NEW findings since snapshot
  4. ghactor baseline prune    # remove already-fixed fingerprints`,
	}

	root.AddCommand(
		createCmd(),
		listCmd(),
		pruneCmd(),
		statusCmd(),
	)
	return root
}

// ---------------------------------------------------------------------------
// create
// ---------------------------------------------------------------------------

func createCmd() *cobra.Command {
	var out string
	var dir string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Snapshot current lint findings into a baseline file",
		Long: `Runs lint on the workflow directory, then writes all current findings
as fingerprints to the baseline file. Always exits 0 so it can be used
safely in setup scripts without blocking CI.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			issues, err := lint.Run(dir)
			if err != nil {
				return fmt.Errorf("lint: %w", err)
			}

			fps := buildFingerprints(issues)
			f := &File{
				Version:      fileVersion,
				Generated:    time.Now().UTC(),
				Generator:    generatorTag,
				Fingerprints: fps,
			}
			if err := Save(out, f); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "baseline: wrote %d fingerprints to %s\n", len(fps), out)
			return nil
		},
	}

	cmd.Flags().StringVar(&out, "out", defaultBaselineFile, "path to write baseline file")
	cmd.Flags().StringVar(&dir, "dir", defaultWorkflowDir, "workflows directory to lint")
	return cmd
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

func listCmd() *cobra.Command {
	var filePath string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "Show contents of the baseline file",
		Long:  `Prints counts by rule and by file for every fingerprint in the baseline.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := Load(filePath)
			if err != nil {
				return err
			}

			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(f)
			}

			byRule := make(map[string]int)
			byFile := make(map[string]int)
			for _, fp := range f.Fingerprints {
				byRule[fp.Rule]++
				byFile[fp.File]++
			}

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintf(w, "baseline: %d fingerprints  generated %s  (%s)\n\n",
				len(f.Fingerprints), f.Generated.Format(time.RFC3339), f.Generator)

			fmt.Fprintln(w, "BY RULE\t")
			rules := sortedKeys(byRule)
			for _, r := range rules {
				fmt.Fprintf(w, "  %s\t%d\n", r, byRule[r])
			}

			fmt.Fprintln(w, "\nBY FILE\t")
			files := sortedKeys(byFile)
			for _, fi := range files {
				fmt.Fprintf(w, "  %s\t%d\n", fi, byFile[fi])
			}
			return w.Flush()
		},
	}

	cmd.Flags().StringVar(&filePath, "file", defaultBaselineFile, "baseline file to read")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output raw JSON")
	return cmd
}

// ---------------------------------------------------------------------------
// prune
// ---------------------------------------------------------------------------

func pruneCmd() *cobra.Command {
	var filePath string
	var dir string

	cmd := &cobra.Command{
		Use:   "prune",
		Short: "Remove fingerprints for findings that no longer exist",
		Long: `Re-runs lint and removes from the baseline any fingerprint that does not
match a current finding. This keeps the baseline tight as issues get fixed,
so you don't silently re-suppress regressions.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := Load(filePath)
			if err != nil {
				return err
			}

			issues, err := lint.Run(dir)
			if err != nil {
				return fmt.Errorf("lint: %w", err)
			}

			// build set of hashes that still exist in current lint output
			currentHashes := make(map[string]struct{}, len(issues))
			for _, iss := range issues {
				currentHashes[FingerprintIssue(iss)] = struct{}{}
			}

			before := len(f.Fingerprints)
			kept := f.Fingerprints[:0]
			for _, fp := range f.Fingerprints {
				if _, ok := currentHashes[fp.Hash]; ok {
					kept = append(kept, fp)
				}
			}
			f.Fingerprints = kept
			f.Generated = time.Now().UTC()

			if err := Save(filePath, f); err != nil {
				return err
			}

			removed := before - len(kept)
			fmt.Fprintf(cmd.OutOrStdout(),
				"baseline prune: removed %d stale fingerprints, %d remain  (%s)\n",
				removed, len(kept), filePath)
			return nil
		},
	}

	cmd.Flags().StringVar(&filePath, "file", defaultBaselineFile, "baseline file to update")
	cmd.Flags().StringVar(&dir, "dir", defaultWorkflowDir, "workflows directory to lint")
	return cmd
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

// severityLevel maps severity strings to an integer for ordered comparison.
func severityLevel(s string) int {
	switch strings.ToLower(s) {
	case "error":
		return 3
	case "warning":
		return 2
	case "info":
		return 1
	default:
		return 0 // "none" or unknown — never fail
	}
}

func statusCmd() *cobra.Command {
	var filePath string
	var dir string
	var failOn string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Report new findings not covered by the baseline",
		Long: `Runs lint and cross-references results against the baseline.
Reports how many findings are suppressed by the baseline and how many are new.
Exits 1 if any new finding meets --fail-on severity.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := Load(filePath)
			if err != nil {
				return err
			}

			issues, err := lint.Run(dir)
			if err != nil {
				return fmt.Errorf("lint: %w", err)
			}

			suppressed, newOnes := Filter(issues, f)

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "baseline status: %d suppressed, %d new\n",
				len(suppressed), len(newOnes))

			if len(newOnes) > 0 {
				fmt.Fprintln(out, "\nNEW FINDINGS:")
				w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
				for _, iss := range newOnes {
					fmt.Fprintf(w, "  %s\t%s:%d\t[%s]\t%s\n",
						iss.Severity, iss.File, iss.Line, iss.Kind, iss.Message)
				}
				w.Flush()
			}

			// determine whether to exit 1
			threshold := severityLevel(failOn)
			if threshold == 0 {
				return nil // --fail-on=none
			}
			for _, iss := range newOnes {
				if severityLevel(string(iss.Severity)) >= threshold {
					return fmt.Errorf("new findings at or above %q severity", failOn)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&filePath, "file", defaultBaselineFile, "baseline file to compare against")
	cmd.Flags().StringVar(&dir, "dir", defaultWorkflowDir, "workflows directory to lint")
	cmd.Flags().StringVar(&failOn, "fail-on", "error", "exit 1 when new findings reach this severity (error|warning|info|none)")
	return cmd
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
