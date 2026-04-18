// Package fix applies safe, comment-preserving autofixes to workflow YAML.
//
// Strategy: parse with yaml.v3 to locate insertion points by node line/column,
// then splice raw text into the original byte slice. This keeps comments,
// blank lines, and the user's indentation style intact.
package fix

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/kdairatchi/ghactor/internal/workflow"
	"gopkg.in/yaml.v3"
)

type Change struct {
	File    string
	Rule    string
	Line    int
	Summary string
}

type Options struct {
	Dir            string
	AddPermissions bool
	AddTimeout     int
	Dry            bool
}

func Apply(opts Options) ([]Change, error) {
	if opts.Dir == "" {
		opts.Dir = ".github/workflows"
	}
	files, err := workflow.LoadDir(opts.Dir)
	if err != nil {
		return nil, err
	}
	var changes []Change
	for _, f := range files {
		fc, err := applyFile(f, opts)
		if err != nil {
			return changes, err
		}
		changes = append(changes, fc...)
	}
	return changes, nil
}

func applyFile(f *workflow.File, opts Options) ([]Change, error) {
	src := f.Source
	var changes []Change
	modified := false

	if opts.AddPermissions {
		newSrc, ok := addTopPermissions(src)
		if ok {
			src = newSrc
			modified = true
			changes = append(changes, Change{File: f.Path, Rule: "GHA002", Line: 1,
				Summary: "added `permissions: contents: read`"})
		}
	}

	if opts.AddTimeout > 0 {
		newSrc, jobChanges := addJobTimeouts(f.Path, src, opts.AddTimeout)
		if len(jobChanges) > 0 {
			src = newSrc
			modified = true
			changes = append(changes, jobChanges...)
		}
	}

	if modified && !opts.Dry {
		if err := os.WriteFile(f.Path, src, 0o644); err != nil {
			return changes, err
		}
	}
	return changes, nil
}

func parseDoc(src []byte) (*yaml.Node, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(src, &root); err != nil {
		return nil, err
	}
	return &root, nil
}

func topMap(root *yaml.Node) *yaml.Node {
	if root == nil {
		return nil
	}
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		return root.Content[0]
	}
	return root
}

// findKey returns (keyNode, valueNode, idx); idx is position in Content (-1 if missing).
func findKey(m *yaml.Node, name string) (*yaml.Node, *yaml.Node, int) {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil, nil, -1
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == name {
			return m.Content[i], m.Content[i+1], i
		}
	}
	return nil, nil, -1
}

// endLineOfValue returns the line number after the value at idx ends.
// yaml.v3 doesn't expose end-line, so walk to the next sibling key's line.
func endLineOfValue(m *yaml.Node, idx, totalLines int) int {
	if idx+2 < len(m.Content) {
		return m.Content[idx+2].Line - 1
	}
	return totalLines
}

// isCRLF reports whether src uses CRLF line endings.
func isCRLF(src []byte) bool {
	return bytes.Contains(src, []byte("\r\n"))
}

// normalizeInsert converts LF line endings in insert to CRLF when the source
// file uses CRLF, so inserted content is consistent with the rest of the file.
func normalizeInsert(insert string, crlf bool) string {
	if !crlf {
		return insert
	}
	// Replace any bare \n (not already preceded by \r) with \r\n.
	var b strings.Builder
	b.Grow(len(insert) + 8)
	for i := 0; i < len(insert); i++ {
		if insert[i] == '\n' && (i == 0 || insert[i-1] != '\r') {
			b.WriteByte('\r')
		}
		b.WriteByte(insert[i])
	}
	return b.String()
}

// spliceAt inserts `insert` after the given 1-indexed line number.
// When the source uses CRLF line endings the insert string is automatically
// converted to CRLF so the resulting file stays consistent.
func spliceAt(src []byte, lineNum int, insert string) []byte {
	crlf := isCRLF(src)
	insert = normalizeInsert(insert, crlf)

	sep := []byte("\n")
	if crlf {
		sep = []byte("\r\n")
	}
	lines := bytes.SplitAfter(src, sep)
	if lineNum < 0 {
		lineNum = 0
	}
	if lineNum > len(lines) {
		lineNum = len(lines)
	}
	var out bytes.Buffer
	out.Grow(len(src) + len(insert))
	for i := 0; i < lineNum; i++ {
		out.Write(lines[i])
	}
	out.WriteString(insert)
	for i := lineNum; i < len(lines); i++ {
		out.Write(lines[i])
	}
	return out.Bytes()
}

// addTopPermissions inserts a top-level `permissions: contents: read` block
// after `on:`. Returns (newSrc, true) if changed; (src, false) otherwise.
func addTopPermissions(src []byte) ([]byte, bool) {
	root, err := parseDoc(src)
	if err != nil {
		return src, false
	}
	m := topMap(root)
	if _, v, _ := findKey(m, "permissions"); v != nil {
		return src, false
	}
	_, _, onIdx := findKey(m, "on")
	totalLines := bytes.Count(src, []byte("\n")) + 1
	var insertAt int
	if onIdx >= 0 {
		insertAt = endLineOfValue(m, onIdx, totalLines)
	} else {
		insertAt = 0 // prepend
	}
	insert := "\npermissions:\n  contents: read\n"
	if insertAt == 0 {
		insert = "permissions:\n  contents: read\n\n"
	}
	return spliceAt(src, insertAt, insert), true
}

// addJobTimeouts inserts `timeout-minutes: N` right after `runs-on:` for any
// job missing one, using the original indent of `runs-on:` to stay compatible
// with non-standard indentation.
func addJobTimeouts(path string, src []byte, n int) ([]byte, []Change) {
	root, err := parseDoc(src)
	if err != nil {
		return src, nil
	}
	_, jobs, _ := findKey(topMap(root), "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return src, nil
	}
	type ins struct {
		line   int
		indent string
		job    string
	}
	var inserts []ins
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		jobName := jobs.Content[i].Value
		job := jobs.Content[i+1]
		if job.Kind != yaml.MappingNode {
			continue
		}
		if _, t, _ := findKey(job, "timeout-minutes"); t != nil {
			continue
		}
		runsOnKey, _, _ := findKey(job, "runs-on")
		if runsOnKey == nil {
			continue
		}
		indent := strings.Repeat(" ", runsOnKey.Column-1)
		inserts = append(inserts, ins{line: runsOnKey.Line, indent: indent, job: jobName})
	}
	// splice bottom-up so earlier line numbers stay valid
	sort.Slice(inserts, func(i, j int) bool { return inserts[i].line > inserts[j].line })
	var changes []Change
	for _, in := range inserts {
		src = spliceAt(src, in.line, fmt.Sprintf("%stimeout-minutes: %d\n", in.indent, n))
		changes = append(changes, Change{File: path, Rule: "GHA005", Line: in.line + 1,
			Summary: fmt.Sprintf("added timeout-minutes: %d to job %q", n, in.job)})
	}
	// changes were collected in reverse — flip back to file order
	for i, j := 0, len(changes)-1; i < j; i, j = i+1, j-1 {
		changes[i], changes[j] = changes[j], changes[i]
	}
	return src, changes
}
