package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/kdairatchi/ghactor/internal/config"
	"github.com/kdairatchi/ghactor/internal/doctor"
	"github.com/kdairatchi/ghactor/internal/fix"
	"github.com/kdairatchi/ghactor/internal/lint"
	"github.com/kdairatchi/ghactor/internal/pin"
	"github.com/kdairatchi/ghactor/internal/trail"
	"github.com/kdairatchi/ghactor/internal/trial"
	"github.com/kdairatchi/ghactor/internal/update"
)

var (
	version = "0.2.0"

	cRed    = color.New(color.FgRed, color.Bold).SprintFunc()
	cYellow = color.New(color.FgYellow).SprintFunc()
	cBlue   = color.New(color.FgBlue).SprintFunc()
	cGreen  = color.New(color.FgGreen, color.Bold).SprintFunc()
	cDim    = color.New(color.Faint).SprintFunc()
	cBold   = color.New(color.Bold).SprintFunc()
)

const banner = ` ┓
┓┓┣┓┏┓┏╋┏┓┏┓
┗┫┛┗┗┻┗┗┗┛┛   lint · fix · pin · trial · trail`

func main() {
	root := &cobra.Command{
		Use:     "ghactor",
		Short:   "Lint, fix, pin, and trial-run GitHub Actions workflows",
		Long:    banner + "\n\nA security-first CLI for GitHub Actions.",
		Version: version,
	}
	root.AddCommand(
		lintCmd(),
		pinCmd(),
		fixCmd(),
		updateCmd(),
		trialCmd(),
		trailCmd(),
		doctorCmd(),
		rulesCmd(),
	)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, cRed("error:"), err)
		os.Exit(1)
	}
}

// ---- lint ----

func lintCmd() *cobra.Command {
	var (
		dir        string
		jsonOut    bool
		sarifOut   string
		onlyGH     bool
		disabled   []string
		failLevel  string
		configPath string
	)
	c := &cobra.Command{
		Use:   "lint",
		Short: "Lint workflows with actionlint + ghactor security rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(configPath, dir)
			if err != nil {
				return err
			}
			if cfg != nil {
				if !cmd.Flags().Changed("only-ghactor") {
					onlyGH = cfg.IgnoreActionlint
				}
				if !cmd.Flags().Changed("fail-on") && cfg.FailOn != "" {
					failLevel = string(cfg.FailOn)
				}
			}
			// Normalise and validate --fail-on.
			if strings.ToLower(failLevel) == "never" {
				failLevel = "none"
			}
			switch strings.ToLower(failLevel) {
			case "none", "info", "warning", "error":
				// valid
			default:
				return fmt.Errorf("invalid --fail-on %q (allowed: none|info|warning|error)", failLevel)
			}
			issues, err := lint.RunWithOptions(lint.Options{
				Dir:              dir,
				DisabledRules:    disabled,
				IgnoreActionlint: onlyGH,
				Config:           cfg,
			})
			if err != nil {
				return err
			}
			if jsonOut {
				return json.NewEncoder(os.Stdout).Encode(issues)
			}
			if sarifOut != "" {
				f, err := os.Create(sarifOut)
				if err != nil {
					return err
				}
				defer f.Close()
				if err := lint.WriteSARIF(f, issues, version); err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "%s wrote SARIF → %s (%d results)\n", cGreen("✓"), sarifOut, len(issues))
			}
			renderIssues(issues)
			if shouldFail(issues, failLevel) {
				os.Exit(1)
			}
			return nil
		},
	}
	c.Flags().StringVarP(&dir, "dir", "d", ".github/workflows", "workflows directory")
	c.Flags().BoolVar(&jsonOut, "json", false, "emit JSON")
	c.Flags().StringVar(&sarifOut, "sarif", "", "write SARIF 2.1.0 to given path (for GitHub code scanning)")
	c.Flags().BoolVar(&onlyGH, "only-ghactor", false, "skip actionlint, only run ghactor rules")
	c.Flags().StringSliceVar(&disabled, "disable", nil, "rule IDs to disable (e.g. GHA005)")
	c.Flags().StringVar(&failLevel, "fail-on", "warning", "exit 1 on: error | warning | info | none (alias: never)")
	c.Flags().StringVar(&configPath, "config", "", "path to .ghactor.yml (default: auto-discover)")
	return c
}

func loadConfig(explicit, dir string) (*config.File, error) {
	if explicit != "" {
		return config.Load(explicit)
	}
	return config.LoadAuto(dir)
}

func renderIssues(issues []lint.Issue) {
	if len(issues) == 0 {
		fmt.Println(cGreen("✓"), "no issues found")
		return
	}
	var currentFile string
	for _, i := range issues {
		if i.File != currentFile {
			currentFile = i.File
			fmt.Println()
			fmt.Println(cBold(currentFile))
		}
		fmt.Printf("  %s %s %s %s\n",
			sevBadge(i.Severity),
			cDim(fmt.Sprintf("%d:%d", i.Line, i.Col)),
			cBlue("["+i.Kind+"]"),
			i.Message)
	}
	e, w, n := lint.Counts(issues)
	fmt.Println()
	fmt.Printf("%s %d errors · %d warnings · %d info\n", cDim("summary:"), e, w, n)
}

func sevBadge(s lint.Severity) string {
	switch s {
	case lint.SevError:
		return cRed("ERROR")
	case lint.SevWarning:
		return cYellow(" WARN")
	default:
		return cBlue(" INFO")
	}
}

func shouldFail(iss []lint.Issue, level string) bool {
	e, w, n := lint.Counts(iss)
	switch strings.ToLower(level) {
	case "error":
		return e > 0
	case "warning":
		return e+w > 0
	case "info":
		return e+w+n > 0
	case "none", "never":
		// "never" kept here as a belt-and-suspenders fallback;
		// the canonical value is "none" after normalisation in lintCmd.
		return false
	}
	return e+w > 0
}

// ---- pin ----

func pinCmd() *cobra.Command {
	var (
		dir       string
		dry       bool
		cachePath string
	)
	c := &cobra.Command{
		Use:   "pin",
		Short: "Pin actions to 40-char SHAs (uses `gh api`)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if cachePath == "" {
				cachePath = filepath.Join(".ghactor", "cache.json")
			}
			r := pin.NewResolver(cachePath)
			changes, err := pin.Pin(dir, r, dry)
			if err != nil {
				return err
			}
			if len(changes) == 0 {
				fmt.Println(cGreen("✓"), "nothing to pin — all actions already pinned by SHA")
				return nil
			}
			for _, ch := range changes {
				tag := "wrote"
				if dry {
					tag = "would pin"
				}
				fmt.Printf("%s %s:%d  %s → %s  %s\n",
					cGreen(tag), ch.File, ch.Line, cDim(ch.Uses), cBold(ch.NewUses), cDim("# "+ch.Comment))
			}
			fmt.Printf("\n%s %d change(s)\n", cDim("total:"), len(changes))
			return nil
		},
	}
	c.Flags().StringVarP(&dir, "dir", "d", ".github/workflows", "workflows directory")
	c.Flags().BoolVar(&dry, "dry-run", false, "print changes without writing files")
	c.Flags().StringVar(&cachePath, "cache", "", "cache path (default .ghactor/cache.json)")
	return c
}

// ---- fix ----

func fixCmd() *cobra.Command {
	var (
		dir       string
		dry       bool
		noPerms   bool
		timeout   int
		alsoPin   bool
		cachePath string
		pr        bool
	)
	c := &cobra.Command{
		Use:   "fix",
		Short: "Apply safe autofixes (permissions, timeouts, optionally pin)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if pr {
				repoDir, err := repoRoot()
				if err != nil {
					return err
				}
				if err := gitCleanTreeCheck(repoDir); err != nil {
					return err
				}
			}

			changes, err := fix.Apply(fix.Options{
				Dir:            dir,
				AddPermissions: !noPerms,
				AddTimeout:     timeout,
				Dry:            dry,
			})
			if err != nil {
				return err
			}
			for _, ch := range changes {
				fmt.Printf("%s %s:%d  %s %s\n",
					cGreen("fix"), ch.File, ch.Line, cBlue("["+ch.Rule+"]"), ch.Summary)
			}
			if alsoPin {
				if cachePath == "" {
					cachePath = filepath.Join(".ghactor", "cache.json")
				}
				r := pin.NewResolver(cachePath)
				pinChanges, err := pin.Pin(dir, r, dry)
				if err != nil {
					return err
				}
				for _, ch := range pinChanges {
					fmt.Printf("%s %s:%d  %s → %s\n",
						cGreen("pin"), ch.File, ch.Line, cDim(ch.Uses), cBold(ch.NewUses))
				}
				changes = append(changes, convertPinChanges(pinChanges)...)
			}
			if len(changes) == 0 {
				fmt.Println(cGreen("✓"), "no drift / no fixes needed")
				return nil
			}
			fmt.Printf("\n%s %d change(s)%s\n", cDim("total:"), len(changes),
				map[bool]string{true: " (dry run)", false: ""}[dry])

			if pr && !dry {
				files := make([]string, 0, len(changes))
				rules := make([]string, 0, len(changes))
				for _, ch := range changes {
					files = append(files, ch.File)
					rules = append(rules, ch.Rule)
				}
				repoDir, err := repoRoot()
				if err != nil {
					return err
				}
				body := fixPRBody(rules, files)
				url, err := runPR(repoDir, files, "fix", "ghactor: fix workflows", body)
				if err != nil {
					return err
				}
				fmt.Println(cGreen("PR:"), url)
			}
			return nil
		},
	}
	c.Flags().StringVarP(&dir, "dir", "d", ".github/workflows", "workflows directory")
	c.Flags().BoolVar(&dry, "dry-run", false, "print changes without writing")
	c.Flags().BoolVar(&noPerms, "no-permissions", false, "skip adding permissions blocks")
	c.Flags().IntVar(&timeout, "timeout", 0, "inject timeout-minutes for jobs missing one (0=off)")
	c.Flags().BoolVar(&alsoPin, "pin", false, "also pin actions to SHAs")
	c.Flags().StringVar(&cachePath, "cache", "", "pin cache path")
	c.Flags().BoolVar(&pr, "pr", false, "create a GitHub PR with the fixes (requires clean git tree)")
	return c
}

func convertPinChanges(in []pin.Change) []fix.Change {
	out := make([]fix.Change, 0, len(in))
	for _, c := range in {
		out = append(out, fix.Change{File: c.File, Line: c.Line, Rule: "GHA001",
			Summary: "pinned " + c.Uses + " → " + c.NewUses})
	}
	return out
}

// ---- update ----

func updateCmd() *cobra.Command {
	var (
		dir         string
		apply       bool
		dry         bool
		major       bool
		jsonOut     bool
		changelog   string
		cachePath   string
		concurrency int
		pr          bool
	)
	c := &cobra.Command{
		Use:   "update",
		Short: "Compare actions to latest releases; optionally rewrite to latest pinned by SHA",
		RunE: func(cmd *cobra.Command, args []string) error {
			// --pr implies --apply; guard before touching the tree.
			if pr {
				apply = true
				repoDir, err := repoRoot()
				if err != nil {
					return err
				}
				if err := gitCleanTreeCheck(repoDir); err != nil {
					return err
				}
			}

			if cachePath == "" {
				cachePath = filepath.Join(".ghactor", "cache.json")
			}
			res := pin.NewResolver(cachePath)
			defer res.Save()
			updates, err := update.Scan(update.Options{
				Dir: dir, AllowMajor: major, Concurrency: concurrency,
			}, res)
			if err != nil {
				return err
			}
			if jsonOut {
				return json.NewEncoder(os.Stdout).Encode(updates)
			}
			renderUpdates(updates)

			// Build changelog body — used both for --changelog file and --pr body.
			var clBuf bytes.Buffer
			if err := update.WriteChangelog(&clBuf, updates); err != nil {
				return err
			}
			if changelog != "" {
				if err := os.WriteFile(changelog, clBuf.Bytes(), 0o644); err != nil {
					return err
				}
				fmt.Printf("\n%s wrote changelog → %s\n", cGreen("✓"), changelog)
			}

			if apply {
				changes, err := update.Apply(dir, updates, dry)
				if err != nil {
					return err
				}
				for _, ch := range changes {
					fmt.Printf("%s %s:%d  %s → %s  %s\n",
						cGreen("apply"), ch.File, ch.Line, cDim(ch.Uses), cBold(ch.NewUses), cDim("# "+ch.Comment))
				}
				if len(changes) == 0 {
					fmt.Println(cDim("no drift / no fixes needed"))
					return nil
				}

				if pr && !dry {
					files := make([]string, 0, len(changes))
					for _, ch := range changes {
						files = append(files, ch.File)
					}
					repoDir, err := repoRoot()
					if err != nil {
						return err
					}
					url, err := runPR(repoDir, files, "update", "ghactor: update workflows", clBuf.String())
					if err != nil {
						return err
					}
					fmt.Println(cGreen("PR:"), url)
				}
			}
			return nil
		},
	}
	c.Flags().StringVarP(&dir, "dir", "d", ".github/workflows", "workflows directory")
	c.Flags().BoolVar(&apply, "apply", false, "rewrite workflows to latest tag pinned by SHA")
	c.Flags().BoolVar(&dry, "dry-run", false, "with --apply, print changes without writing")
	c.Flags().BoolVar(&major, "major", false, "allow cross-major bumps (default: same major only)")
	c.Flags().BoolVar(&jsonOut, "json", false, "emit JSON report")
	c.Flags().StringVar(&changelog, "changelog", "", "write PR-ready Markdown to FILE")
	c.Flags().StringVar(&cachePath, "cache", "", "SHA cache path (default .ghactor/cache.json)")
	c.Flags().IntVar(&concurrency, "jobs", 4, "parallel gh api calls")
	c.Flags().BoolVar(&pr, "pr", false, "create a GitHub PR with the updates (implies --apply, requires clean git tree)")
	return c
}

func renderUpdates(us []update.Update) {
	for _, u := range us {
		marker := cDim("=")
		switch {
		case u.Skip:
			marker = cDim("⏭")
		case u.Drift:
			if u.SameMajor {
				marker = cYellow("↑")
			} else {
				marker = cRed("⇈")
			}
		}
		latest := u.LatestTag
		if latest == "" {
			latest = "?"
		}
		extra := ""
		if u.Reason != "" {
			extra = "  " + cDim("("+u.Reason+")")
		}
		fmt.Printf("%s %-35s %-12s → %s%s\n", marker, u.Key, u.CurRef, cBold(latest), extra)
	}
}

// ---- trial ----

func trialCmd() *cobra.Command {
	var (
		event    string
		workflow string
	)
	c := &cobra.Command{
		Use:                "trial [-- act flags]",
		Short:              "Run a workflow locally via nektos/act",
		DisableFlagParsing: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			return trial.Run(event, workflow, args)
		},
	}
	c.Flags().StringVarP(&event, "event", "e", "", "event to trigger (push, pull_request, ...)")
	c.Flags().StringVarP(&workflow, "workflow", "W", "", "path to a specific workflow file")
	return c
}

// ---- trail ----

func trailCmd() *cobra.Command {
	var (
		limit    int
		workflow string
		branch   string
		window   string
		failRate float64
		jsonOut  bool
		listOnly bool
	)
	c := &cobra.Command{
		Use:   "trail",
		Short: "Inspect recent workflow runs; optionally gate on failure rate",
		RunE: func(cmd *cobra.Command, args []string) error {
			win, err := trail.ParseWindow(window)
			if err != nil {
				return err
			}
			if workflow != "" {
				if err := trail.ValidateWorkflow(workflow); err != nil {
					return err
				}
			}
			runs, err := trail.RecentWindow(trail.WindowOpts{
				Limit: limit, Window: win, Branch: branch, Workflow: workflow,
			})
			if err != nil {
				return err
			}
			if listOnly {
				if jsonOut {
					return json.NewEncoder(os.Stdout).Encode(runs)
				}
				renderRuns(runs)
				return nil
			}
			rep := trail.Aggregate(runs, win, branch, failRate)
			if jsonOut {
				return json.NewEncoder(os.Stdout).Encode(rep)
			}
			renderReport(rep)
			if failRate > 0 && rep.Breached {
				os.Exit(1)
			}
			return nil
		},
	}
	c.Flags().IntVarP(&limit, "limit", "n", 100, "how many runs to fetch")
	c.Flags().StringVarP(&workflow, "workflow", "W", "", "filter by workflow name or file")
	c.Flags().StringVar(&branch, "branch", "", "filter by branch")
	c.Flags().StringVar(&window, "window", "7d", "time window: 24h, 7d, 30d, or any Go duration")
	c.Flags().Float64Var(&failRate, "fail-rate", 0, "exit 1 if overall failure rate > N percent (0 disables)")
	c.Flags().BoolVar(&jsonOut, "json", false, "emit JSON")
	c.Flags().BoolVar(&listOnly, "list", false, "show individual runs instead of aggregate")
	return c
}

func renderReport(r trail.Report) {
	fmt.Println(cBold("trail report"))
	win := "all-time"
	if r.Window > 0 {
		win = r.Window.String()
	}
	fmt.Printf("  %s window=%s branch=%s threshold=%.0f%%\n",
		cDim("scope:"), win, nz(r.Branch, "*"), r.Threshold)
	if r.Overall.Total == 0 {
		fmt.Println(cDim("  (no runs)"))
		return
	}
	fmt.Println()
	fmt.Printf("  %-30s %5s %5s %5s %5s %7s %s\n",
		cDim("WORKFLOW"), "RUNS", "PASS", "FAIL", "FLAKY", "FAIL%", "LAST FAIL")
	for _, s := range r.PerWorkflow {
		flag := "  "
		if s.FailRate > r.Threshold && r.Threshold > 0 {
			flag = cRed("⚠ ")
		}
		last := "—"
		if !s.LastFailureAt.IsZero() {
			last = humanAgo(time.Since(s.LastFailureAt))
		}
		fmt.Printf("%s%-30s %5d %5d %5d %5d %6.1f%% %s\n",
			flag, truncate(s.Workflow, 30),
			s.Total, s.Success, s.Failure,
			s.FlakyRecovered+s.FlakyBroken, s.FailRate, last)
	}
	fmt.Println()
	verdict := cGreen("OK")
	if r.Breached {
		verdict = cRed("BREACHED")
	}
	fmt.Printf("  %s %d runs · %.1f%% fail rate · %s\n",
		cDim("overall:"), r.Overall.Total, r.Overall.FailRate, verdict)
}

func nz(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func humanAgo(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func renderRuns(runs []trail.Run) {
	if len(runs) == 0 {
		fmt.Println(cDim("no runs"))
		return
	}
	for _, r := range runs {
		icon, col := "·", cDim
		switch r.Conclusion {
		case "success":
			icon, col = "✓", cGreen
		case "failure":
			icon, col = "✗", cRed
		case "cancelled":
			icon, col = "⊘", cYellow
		}
		dur := r.UpdatedAt.Sub(r.CreatedAt).Round(time.Second)
		fmt.Printf("%s %-26s %s  %-12s %-8s %s\n",
			col(icon),
			truncate(r.Workflow, 26),
			cDim(r.CreatedAt.Local().Format("01-02 15:04")),
			r.Event,
			dur,
			cDim(r.URL))
	}
	s := trail.Summarize(runs)
	fmt.Println()
	fmt.Printf("%s %d total · %s %d · %s %d · avg %s\n",
		cDim("summary:"), s.Total,
		cGreen("✓"), s.Success,
		cRed("✗"), s.Failure,
		s.AvgDuration.Round(time.Second))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// ---- doctor ----

func doctorCmd() *cobra.Command {
	var (
		dir     string
		jsonOut bool
	)
	c := &cobra.Command{
		Use:   "doctor",
		Short: "Repo-wide workflow health report",
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := doctor.Scan(dir)
			if err != nil {
				return err
			}
			if jsonOut {
				b, err := json.MarshalIndent(r, "", "  ")
				if err != nil {
					return err
				}
				fmt.Println(string(b))
				return nil
			}
			fmt.Println(cBold("ghactor doctor"))
			fmt.Printf("  %s %s\n", cDim("dir:"), r.Dir)
			fmt.Printf("  %s %d workflows · %d jobs · %d steps\n", cDim("scope:"), r.Workflows, r.Jobs, r.Steps)
			score := r.Score()
			scoreCol := cGreen
			if score < 80 {
				scoreCol = cYellow
			}
			if score < 50 {
				scoreCol = cRed
			}
			fmt.Printf("  %s %s/100\n", cDim("score:"), scoreCol(fmt.Sprintf("%d", score)))
			if len(r.Issues) == 0 {
				fmt.Println("\n" + cGreen("✓") + " no findings")
				return nil
			}
			fmt.Println()
			fmt.Println(cBold("by rule:"))
			for k, v := range r.ByRule {
				fmt.Printf("  %-10s %d\n", k, v)
			}
			fmt.Println()
			renderIssues(r.Issues)
			return nil
		},
	}
	c.Flags().StringVarP(&dir, "dir", "d", ".github/workflows", "workflows directory")
	c.Flags().BoolVar(&jsonOut, "json", false, "emit report as indented JSON instead of human table")
	return c
}

// ---- rules ----

func rulesCmd() *cobra.Command {
	var verbose bool
	c := &cobra.Command{
		Use:   "rules",
		Short: "List all ghactor lint rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			if verbose {
				renderRulesVerbose(lint.Rules)
				return nil
			}
			for _, r := range lint.Rules {
				fmt.Printf("%s  %s  %s\n", cBold(r.ID), sevBadge(r.Severity), r.Title)
			}
			return nil
		},
	}
	c.Flags().BoolVar(&verbose, "verbose", false, "print full card per rule (description, remediation, references)")
	return c
}

// renderRulesVerbose prints each rule as a structured card with full metadata.
func renderRulesVerbose(rules []lint.Rule) {
	sep := strings.Repeat("─", 72)
	for i, r := range rules {
		if i > 0 {
			fmt.Println()
		}
		fmt.Println(sep)
		fmt.Printf("%s  %s  %s\n", cBold(r.ID), sevBadge(r.Severity), cBold(r.Title))
		if r.Description != "" {
			fmt.Println()
			fmt.Println(cDim("description"))
			fmt.Println(wordWrap(r.Description, 72))
		}
		if r.Remediation != "" {
			fmt.Println()
			fmt.Println(cDim("remediation"))
			fmt.Println(wordWrap(r.Remediation, 72))
		}
		if len(r.References) > 0 {
			fmt.Println()
			fmt.Println(cDim("references"))
			for _, ref := range r.References {
				fmt.Printf("  · %s\n", ref)
			}
		}
	}
	fmt.Println(sep)
}

// wordWrap wraps text to at most width runes per line, indented by two spaces.
func wordWrap(text string, width int) string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return ""
	}
	const indent = "  "
	var sb strings.Builder
	line := indent
	for _, w := range words {
		if line == indent {
			line += w
			continue
		}
		if len(line)+1+len(w) > width {
			sb.WriteString(line)
			sb.WriteByte('\n')
			line = indent + w
		} else {
			line += " " + w
		}
	}
	if line != indent {
		sb.WriteString(line)
	}
	return sb.String()
}
