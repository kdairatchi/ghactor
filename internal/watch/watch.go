// Package watch implements the `ghactor watch` command: it monitors a
// workflows directory and re-runs lint on every YAML change.
package watch

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"

	"github.com/kdairatchi/ghactor/internal/config"
	"github.com/kdairatchi/ghactor/internal/lint"
)

// Options configures a watch run.
type Options struct {
	Dir              string
	Disabled         []string
	IgnoreActionlint bool
	Debounce         time.Duration
	Clear            bool
	Config           *config.File // optional — from loadConfig in the caller
	Out              io.Writer    // for tests; nil → os.Stdout
}

// eventSource is the abstraction that separates the fsnotify watcher from the
// runtime loop. Tests inject a fakeSource; production uses fsnotifySource.
type eventSource interface {
	Events() <-chan fsnotify.Event
	Errors() <-chan error
	Add(path string) error
	Close() error
}

// fsnotifySource wraps a real *fsnotify.Watcher.
type fsnotifySource struct{ w *fsnotify.Watcher }

func (s *fsnotifySource) Events() <-chan fsnotify.Event { return s.w.Events }
func (s *fsnotifySource) Errors() <-chan error          { return s.w.Errors }
func (s *fsnotifySource) Add(path string) error         { return s.w.Add(path) }
func (s *fsnotifySource) Close() error                  { return s.w.Close() }

// newFSNotifySource creates a production event source that watches dir and
// every YAML file currently in it.
func newFSNotifySource(dir string) (*fsnotifySource, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("create watcher: %w", err)
	}
	src := &fsnotifySource{w: w}
	if err := src.Add(dir); err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("watch dir %s: %w", dir, err)
	}
	// Pre-watch each existing YAML so we catch write events on individual inodes.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if isYAML(e.Name()) {
			// Best-effort; ignore errors for files that disappear between
			// ReadDir and Add.
			_ = src.Add(filepath.Join(dir, e.Name()))
		}
	}
	return src, nil
}

// isYAML reports whether a file name has a .yml or .yaml extension.
func isYAML(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".yml" || ext == ".yaml"
}

// Run starts the watch loop. It blocks until SIGINT/SIGTERM or a fatal error.
func Run(opts Options) error {
	if opts.Debounce <= 0 {
		opts.Debounce = 250 * time.Millisecond
	}
	if opts.Out == nil {
		opts.Out = os.Stdout
	}
	dir := opts.Dir
	if dir == "" {
		dir = ".github/workflows"
	}

	src, err := newFSNotifySource(dir)
	if err != nil {
		return err
	}
	return runLoop(opts, dir, src)
}

// runLoop is the inner loop, accepting an eventSource so tests can inject a fake.
func runLoop(opts Options, dir string, src eventSource) error {
	defer src.Close()

	out := opts.Out
	if out == nil {
		out = os.Stdout
	}

	cGreen := color.New(color.FgGreen).SprintFunc()
	cCyan  := color.New(color.FgCyan).SprintFunc()
	cDim   := color.New(color.Faint).SprintFunc()

	printHeader := func(path string) {
		if opts.Clear {
			fmt.Fprint(out, "\x1b[2J\x1b[H")
		}
		ts := time.Now().Format("15:04:05")
		base := filepath.Base(path)
		if base == "." || base == "" {
			base = filepath.Base(dir)
		}
		fmt.Fprintf(out, "\n[%s] %s changed\n", cDim(ts), cCyan(base))
	}

	printIssues := func(issues []lint.Issue) {
		if len(issues) == 0 {
			fmt.Fprintf(out, "%s no issues found\n", cGreen("✓"))
			return
		}
		for _, iss := range issues {
			rel := iss.File
			if r, err := filepath.Rel(dir, iss.File); err == nil {
				rel = r
			}
			fmt.Fprintf(out, "  %s %d:%d [%s] %s\n",
				severityLabel(iss.Severity), iss.Line, iss.Col, iss.Kind, iss.Message)
			_ = rel
		}
	}

	runLint := func() []lint.Issue {
		lintOpts := lint.Options{
			Dir:              dir,
			DisabledRules:    opts.Disabled,
			IgnoreActionlint: opts.IgnoreActionlint,
			Config:           opts.Config,
		}
		issues, err := lint.RunWithOptions(lintOpts)
		if err != nil {
			fmt.Fprintf(out, "lint error: %v\n", err)
			return nil
		}
		return issues
	}

	// Initial pass before waiting for any events.
	fmt.Fprintf(out, "watching %s (press Ctrl-C to stop)\n", cCyan(dir))
	printIssues(runLint())

	// Signal handling.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	// Debounce state: track the last changed path and a pending timer.
	var (
		debounceTimer *time.Timer
		lastPath      string
		timerFired    = make(chan string, 1)
	)

	armTimer := func(path string) {
		lastPath = path
		if debounceTimer != nil {
			debounceTimer.Stop()
		}
		debounceTimer = time.AfterFunc(opts.Debounce, func() {
			timerFired <- lastPath
		})
	}

	for {
		select {
		case <-sigCh:
			fmt.Fprintf(out, "\nstopped\n")
			return nil

		case err, ok := <-src.Errors():
			if !ok {
				return nil
			}
			fmt.Fprintf(out, "watcher error: %v\n", err)

		case ev, ok := <-src.Events():
			if !ok {
				return nil
			}
			handleEvent(opts, dir, src, ev, armTimer)

		case path := <-timerFired:
			printHeader(path)
			printIssues(runLint())
		}
	}
}

// handleEvent processes a single fsnotify event, re-arming the debounce timer
// for YAML files and handling atomic rename-over-write sequences.
//
// Rename-over-write edge case: editors like vim and many CLI tools write to a
// temp file then rename it over the original path. fsnotify delivers a RENAME
// on the old inode (which is then removed from the kernel watch table) and a
// CREATE on the directory for the new inode. We respond to the CREATE by
// adding a fresh watch on the new file path. This re-arms the kernel watcher
// for the new inode. The CREATE event itself is then treated as a YAML change
// and fed into the debounce window so exactly one lint run fires per
// rename-over-write sequence — even if the RENAME and CREATE arrive in rapid
// succession, because both collapse inside the same debounce window.
func handleEvent(opts Options, dir string, src eventSource, ev fsnotify.Event, armTimer func(string)) {
	name := ev.Name

	switch {
	case ev.Has(fsnotify.Create):
		// New file appeared — could be a rename-over-write target or a genuinely
		// new YAML. Either way: try to add it to the watcher, then debounce.
		if isYAML(name) {
			_ = src.Add(name) // best-effort; new inode needs its own watch entry
			armTimer(name)
		}
		// Also handle new YAML files created in a sub-path (shouldn't happen for
		// flat workflow dirs, but be defensive).

	case ev.Has(fsnotify.Write) || ev.Has(fsnotify.Chmod):
		if isYAML(name) {
			armTimer(name)
		}

	case ev.Has(fsnotify.Rename) || ev.Has(fsnotify.Remove):
		// The old inode is gone. The kernel watch entry is automatically removed.
		// We do NOT trigger lint here; we wait for the accompanying CREATE event
		// (for renames) or accept that the file is just gone (for removals).
		// If a pure removal happens (no follow-up CREATE), no lint runs — which
		// is correct because the file no longer exists.
		_ = name // intentionally no-op; CREATE will follow for renames
	}
}

// severityLabel returns a coloured severity prefix for output.
func severityLabel(sev lint.Severity) string {
	switch sev {
	case lint.SevError:
		return color.New(color.FgRed, color.Bold).Sprint("ERROR")
	case lint.SevWarning:
		return color.New(color.FgYellow).Sprint("WARN ")
	default:
		return color.New(color.FgBlue).Sprint("INFO ")
	}
}

// Cmd returns the `watch` cobra subcommand.
//
// Wire it in main.go via:
//
//	rootCmd.AddCommand(watch.Cmd())
func Cmd() *cobra.Command {
	var (
		dir      string
		disabled []string
		onlyGA   bool
		debounce time.Duration
		clear    bool
	)

	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Watch a workflows directory and re-run lint on every YAML change",
		Long: `watch monitors a GitHub Actions workflows directory and automatically
re-runs lint whenever a .yml or .yaml file is created or modified.

It performs an initial lint pass immediately so you see the current state,
then waits for file-system events. Multiple rapid saves (e.g. vim's
rename-over-write) are coalesced by a debounce window before lint runs.

Press Ctrl-C to stop.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _ := config.LoadAuto(dir)

			return Run(Options{
				Dir:              dir,
				Disabled:         disabled,
				IgnoreActionlint: onlyGA,
				Debounce:         debounce,
				Clear:            clear,
				Config:           cfg,
			})
		},
	}

	cmd.Flags().StringVarP(&dir, "dir", "d", ".github/workflows", "workflows directory to watch")
	cmd.Flags().StringSliceVar(&disabled, "disable", nil, "comma-separated rule IDs to disable (e.g. GHA005)")
	cmd.Flags().BoolVar(&onlyGA, "only-ghactor", false, "skip actionlint; run only ghactor rules")
	cmd.Flags().DurationVar(&debounce, "debounce", 250*time.Millisecond, "coalesce events within this window before running lint")
	cmd.Flags().BoolVar(&clear, "clear", false, "clear terminal before each lint run")

	return cmd
}
