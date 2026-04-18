// Package secrets performs gitleaks-style regex scanning on GitHub Actions
// workflow YAML to catch secret literals accidentally committed in run: blocks,
// env: values, and with: parameters.
package secrets

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// Finding represents a single detected secret candidate.
type Finding struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Col      int    `json:"col"`
	Rule     string `json:"rule"`     // pattern ID, e.g. "github_pat"
	Severity string `json:"severity"` // "error" | "warning"
	Redacted string `json:"redacted"` // redacted form — never the raw match
	Context  string `json:"context"`  // "run:" | "env:MY_TOKEN" | "with:api_key"
}

// Options configures a Scan call.
type Options struct {
	Dir     string // directory to walk (default: .github/workflows)
	Entropy bool   // enable generic high-entropy token detection
}

// Scan walks every YAML file under opts.Dir, runs all patterns against each
// non-ignored line, and returns findings. No finding ever contains the raw
// secret value.
func Scan(opts Options) ([]Finding, error) {
	if opts.Dir == "" {
		opts.Dir = ".github/workflows"
	}
	info, err := os.Stat(opts.Dir)
	if err != nil {
		return nil, fmt.Errorf("secrets: stat %s: %w", opts.Dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("secrets: %s is not a directory", opts.Dir)
	}

	var findings []Finding
	err = filepath.WalkDir(opts.Dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}
		ff, err := scanFile(p, opts.Entropy)
		if err != nil {
			// Non-fatal: report and continue.
			fmt.Fprintf(os.Stderr, "secrets: skipping %s: %v\n", p, err)
			return nil
		}
		findings = append(findings, ff...)
		return nil
	})
	return findings, err
}

// scanFile scans a single workflow YAML file line by line.
func scanFile(path string, entropy bool) ([]Finding, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var findings []Finding
	scanner := bufio.NewScanner(bytes.NewReader(src))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		raw := scanner.Text()

		// Honour per-line suppression comments.
		if isIgnored(raw) {
			continue
		}

		// Derive the context label from the YAML key on this line.
		ctx := lineContext(raw)

		// Run every compiled pattern.
		for _, pat := range Patterns {
			loc := pat.Regex.FindStringIndex(raw)
			if loc == nil {
				continue
			}
			match := raw[loc[0]:loc[1]]

			// For the aws_secret_key pattern, the full match includes the key
			// name prefix; we want the actual 40-char token for redaction.
			// The regex has one capture group — use it when present.
			subs := pat.Regex.FindStringSubmatch(raw)
			if len(subs) > 1 && subs[1] != "" {
				match = subs[1]
			}

			if isAllowlisted(match) {
				continue
			}

			findings = append(findings, Finding{
				File:     path,
				Line:     lineNum,
				Col:      loc[0] + 1,
				Rule:     pat.ID,
				Severity: pat.Severity,
				Redacted: redact(match, pat.RedactTo),
				Context:  ctx,
			})
		}

		// Optional high-entropy scan.
		if entropy {
			for _, tok := range extractTokens(raw) {
				if isAllowlisted(tok) {
					continue
				}
				if shannonEntropy(tok) >= 4.5 {
					col := strings.Index(raw, tok) + 1
					findings = append(findings, Finding{
						File:     path,
						Line:     lineNum,
						Col:      col,
						Rule:     "generic_high_entropy",
						Severity: "warning",
						Redacted: redact(tok, 4),
						Context:  ctx,
					})
				}
			}
		}
	}
	return findings, scanner.Err()
}

// isIgnored returns true when the line carries a suppression directive.
func isIgnored(line string) bool {
	return strings.Contains(line, "# ghactor:ignore secrets") ||
		strings.Contains(line, "# pragma: ignore-secrets")
}

// isAllowlisted returns true when the value is obviously fake/example data.
func isAllowlisted(s string) bool {
	lower := strings.ToLower(s)
	for _, sub := range allowlistSubstrings {
		if strings.Contains(lower, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

// lineContext derives a short context label from a YAML line.
// It identifies run:, env:KEY, with:KEY, or falls back to "value".
func lineContext(line string) string {
	trimmed := strings.TrimSpace(line)
	switch {
	case strings.HasPrefix(trimmed, "run:") || strings.HasPrefix(trimmed, "- run:"):
		return "run:"
	case strings.HasPrefix(trimmed, "env:"):
		// env: KEY: value  — extract the key if present
		rest := strings.TrimPrefix(trimmed, "env:")
		rest = strings.TrimSpace(rest)
		if kv := strings.SplitN(rest, ":", 2); len(kv) == 2 {
			return "env:" + strings.TrimSpace(kv[0])
		}
		return "env:"
	case strings.HasPrefix(trimmed, "with:"):
		rest := strings.TrimPrefix(trimmed, "with:")
		rest = strings.TrimSpace(rest)
		if kv := strings.SplitN(rest, ":", 2); len(kv) == 2 {
			return "with:" + strings.TrimSpace(kv[0])
		}
		return "with:"
	default:
		// Try to pick up inline env/with key from indented YAML.
		if idx := strings.Index(trimmed, ":"); idx > 0 {
			key := strings.TrimSpace(trimmed[:idx])
			if key != "" && !strings.ContainsAny(key, " \t{}[]") {
				return key + ":"
			}
		}
		return "value"
	}
}

// redact returns a safe representation of match for display.
// If len(match) <= 8 it returns "****".
// Otherwise it returns the first keepLeading chars + "****" + last 2 chars.
func redact(match string, keepLeading int) string {
	if len(match) <= 8 {
		return "****"
	}
	if keepLeading < 0 {
		keepLeading = 0
	}
	if keepLeading > len(match)-2 {
		keepLeading = len(match) - 2
	}
	prefix := match[:keepLeading]
	suffix := match[len(match)-2:]
	return prefix + "****" + suffix
}

// extractTokens returns contiguous alphanumeric+symbols tokens of 20+ chars
// from a line, suitable for entropy analysis.
func extractTokens(line string) []string {
	var tokens []string
	start := -1
	for i, ch := range line {
		isTokenChar := (ch >= 'A' && ch <= 'Z') ||
			(ch >= 'a' && ch <= 'z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '+' || ch == '/' || ch == '=' ||
			ch == '-' || ch == '_'
		if isTokenChar {
			if start == -1 {
				start = i
			}
		} else {
			if start != -1 && i-start >= 20 {
				tokens = append(tokens, line[start:i])
			}
			start = -1
		}
	}
	if start != -1 && len(line)-start >= 20 {
		tokens = append(tokens, line[start:])
	}
	return tokens
}

// shannonEntropy computes the Shannon entropy of a string over its byte alphabet.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[byte]int)
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, count := range freq {
		p := float64(count) / n
		h -= p * math.Log2(p)
	}
	return h
}

// Cmd builds the cobra.Command for `ghactor secrets`.
func Cmd() *cobra.Command {
	var (
		dir      string
		jsonOut  bool
		failOn   string
		entropy  bool
	)

	c := &cobra.Command{
		Use:   "secrets",
		Short: "Scan workflow YAML for accidentally committed secrets",
		Long: `Scan every .yml/.yaml file under the workflows directory for secret literals
committed in run: blocks, env: values, and with: parameters.

Suppression: add  # ghactor:ignore secrets  or  # pragma: ignore-secrets  to
a line to silence findings on that line.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate --fail-on.
			switch strings.ToLower(failOn) {
			case "error", "warning", "none", "never":
				// ok
			default:
				return fmt.Errorf("invalid --fail-on %q (allowed: error|warning|none)", failOn)
			}

			findings, err := Scan(Options{Dir: dir, Entropy: entropy})
			if err != nil {
				return err
			}

			if jsonOut {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(findings)
			}

			renderFindings(findings)

			if shouldFailOn(findings, failOn) {
				os.Exit(1)
			}
			return nil
		},
	}

	c.Flags().StringVarP(&dir, "dir", "d", ".github/workflows", "workflows directory to scan")
	c.Flags().BoolVar(&jsonOut, "json", false, "emit findings as JSON")
	c.Flags().StringVar(&failOn, "fail-on", "warning", "exit 1 when severity >= this level (error|warning|none)")
	c.Flags().BoolVar(&entropy, "entropy", false, "enable generic high-entropy token detection (may produce false positives)")

	return c
}

// renderFindings prints a human-readable report to stdout.
func renderFindings(findings []Finding) {
	if len(findings) == 0 {
		fmt.Println("no secrets found")
		return
	}
	var currentFile string
	for _, f := range findings {
		if f.File != currentFile {
			currentFile = f.File
			fmt.Println()
			fmt.Println(currentFile)
		}
		sev := strings.ToUpper(f.Severity[:1]) + f.Severity[1:]
		fmt.Printf("  %s  %d:%d  [%s]  %s  (%s)\n",
			sev, f.Line, f.Col, f.Rule, f.Redacted, f.Context)
	}
	errs, warns := countFindings(findings)
	fmt.Printf("\nsummary: %d error(s) · %d warning(s)\n", errs, warns)
}

// countFindings returns error and warning totals.
func countFindings(findings []Finding) (errors, warnings int) {
	for _, f := range findings {
		switch f.Severity {
		case "error":
			errors++
		case "warning":
			warnings++
		}
	}
	return
}

// shouldFailOn returns true when the finding set triggers the given threshold.
func shouldFailOn(findings []Finding, level string) bool {
	errs, warns := countFindings(findings)
	switch strings.ToLower(level) {
	case "error":
		return errs > 0
	case "warning":
		return errs+warns > 0
	case "none", "never":
		return false
	}
	return errs+warns > 0
}
