package fix

import (
	"fmt"
	"strings"

	"github.com/kdairatchi/ghactor/internal/workflow"
	"gopkg.in/yaml.v3"
)

// movePermsToJob implements the GHA020 autofix: when a workflow has top-level
// permissions that include write scopes and there is exactly one job, the write
// scopes are removed from the top-level block and injected (or merged) into the
// sole job's permissions block.
//
// Special cases:
//   - Multiple jobs: no-op (ambiguous — which job needs which scope?).
//   - permissions: write-all or read-all scalar: no-op with a returned note.
//   - Job already has permissions block: missing write scopes are appended.
//   - Read-only scopes at top level are preserved.
func movePermsToJob(path string, src []byte) ([]byte, []Change, string) {
	root, err := parseDoc(src)
	if err != nil {
		return src, nil, ""
	}
	m := topMap(root)

	_, permsVal, permsIdx := findKey(m, "permissions")
	if permsIdx < 0 || permsVal == nil {
		return src, nil, ""
	}

	// Handle scalar permissions (write-all / read-all / etc.)
	if permsVal.Kind == yaml.ScalarNode {
		scalar := strings.ToLower(strings.TrimSpace(permsVal.Value))
		if scalar == "write-all" {
			// write-all at workflow level is too broad to expand automatically without
			// knowing which scopes the job actually uses. Skip and surface a note.
			return src, nil, "GHA020: permissions: write-all — too broad to auto-expand; set explicit scopes manually"
		}
		// read-all or anything else: no write scopes present, nothing to move.
		return src, nil, ""
	}

	if permsVal.Kind != yaml.MappingNode {
		return src, nil, ""
	}

	// Collect write scopes that should move down and read scopes that stay.
	var writeScopes []permScope
	var readScopes []permScope

	for i := 0; i+1 < len(permsVal.Content); i += 2 {
		k := permsVal.Content[i].Value
		v := permsVal.Content[i+1].Value
		if strings.EqualFold(v, "write") {
			writeScopes = append(writeScopes, permScope{k, v})
		} else {
			readScopes = append(readScopes, permScope{k, v})
		}
	}
	if len(writeScopes) == 0 {
		return src, nil, ""
	}

	// Require exactly one job.
	_, jobsVal, _ := findKey(m, "jobs")
	if jobsVal == nil || jobsVal.Kind != yaml.MappingNode {
		return src, nil, ""
	}
	if len(jobsVal.Content)/2 != 1 {
		// Multiple jobs: ambiguous — skip.
		return src, nil, ""
	}
	jobName := jobsVal.Content[0].Value
	jobNode := jobsVal.Content[1]
	if jobNode.Kind != yaml.MappingNode {
		return src, nil, ""
	}

	// Detect indent used by the file (two-space assumed; detect from jobs key column).
	baseIndent := "  " // default 2-space
	if len(jobsVal.Content) > 0 {
		col := jobsVal.Content[0].Column // job name column (1-indexed)
		if col > 1 {
			baseIndent = strings.Repeat(" ", col-1)
		}
	}
	jobIndent := baseIndent + baseIndent // job body indent = 2× job name indent

	// Load the file as a workflow to check for existing job-level permissions.
	wf := &workflow.Workflow{}
	if err := yaml.Unmarshal(src, wf); err != nil {
		return src, nil, ""
	}
	job := wf.Jobs[jobName]

	totalLines := strings.Count(string(src), "\n") + 1

	// Step 1: rewrite (or remove) top-level permissions block.
	// Re-parse so node positions are fresh.
	root2, _ := parseDoc(src)
	m2 := topMap(root2)
	_, permsVal2, permsIdx2 := findKey(m2, "permissions")
	_ = permsIdx2

	// Determine the line range of the top-level permissions block.
	// permsVal2.Line is the first line of the value; we need the end.
	// The key node is at permsIdx2, value at permsIdx2+1.
	permKeyNode := m2.Content[permsIdx2]
	_ = permsVal2
	_ = permKeyNode

	// Build replacement text for the top-level permissions block.
	var newPermBlock string
	if len(readScopes) > 0 {
		var sb strings.Builder
		fmt.Fprintf(&sb, "permissions:\n")
		for _, s := range readScopes {
			fmt.Fprintf(&sb, "%s%s: %s\n", baseIndent, s.k, s.v)
		}
		newPermBlock = sb.String()
	}
	// else: no read scopes remain → remove the block entirely.

	// Step 2: determine insertion point for job-level permissions.
	// We want to insert it right after the job's "runs-on:" key line.
	root3, _ := parseDoc(src)
	m3 := topMap(root3)
	_, jobsVal3, _ := findKey(m3, "jobs")
	jobNode3 := jobsVal3.Content[1] // sole job value node

	_, runsOnKey3, _ := findKey(jobNode3, "runs-on")
	if runsOnKey3 == nil {
		return src, nil, ""
	}
	jobPermsInsertLine := runsOnKey3.Line // insert after this line

	// Compute what scopes to inject: writeScopes minus any already in job-level permissions.
	var scopesToInject []permScope
	if job != nil && job.Permissions.Kind == yaml.MappingNode {
		existing := map[string]bool{}
		for i := 0; i+1 < len(job.Permissions.Content); i += 2 {
			existing[job.Permissions.Content[i].Value] = true
		}
		for _, s := range writeScopes {
			if !existing[s.k] {
				scopesToInject = append(scopesToInject, s)
			}
		}
	} else {
		scopesToInject = writeScopes
	}

	if len(scopesToInject) == 0 && len(readScopes) == len(permsVal.Content)/2 {
		// Nothing to do.
		return src, nil, ""
	}

	// Apply changes bottom-up to keep line numbers valid.
	// 1. Insert job-level permissions block (or merge into existing).
	// 2. Rewrite top-level permissions block.

	lines := splitLines(src)

	// Insert job-level permissions.
	if len(scopesToInject) > 0 {
		if job != nil && job.Permissions.Kind == yaml.MappingNode {
			// Find the last line of the existing job permissions block and append.
			root4, _ := parseDoc(src)
			m4 := topMap(root4)
			_, jobsVal4, _ := findKey(m4, "jobs")
			jn4 := jobsVal4.Content[1]
			permKeyIdx4 := -1
			for i := 0; i+1 < len(jn4.Content); i += 2 {
				if jn4.Content[i].Value == "permissions" {
					permKeyIdx4 = i
					break
				}
			}
			if permKeyIdx4 >= 0 {
				jobPermEndLine := endLineOfValue(jn4, permKeyIdx4, totalLines)
				var appendBlock strings.Builder
				for _, s := range scopesToInject {
					fmt.Fprintf(&appendBlock, "%s%s: %s\n", jobIndent, s.k, s.v)
				}
				lines = spliceLines(lines, jobPermEndLine, appendBlock.String())
			}
		} else {
			// Insert fresh permissions block after runs-on.
			var permBlock strings.Builder
			fmt.Fprintf(&permBlock, "%spermissions:\n", jobIndent)
			for _, s := range scopesToInject {
				fmt.Fprintf(&permBlock, "%s%s%s: %s\n", jobIndent, baseIndent, s.k, s.v)
			}
			lines = spliceLines(lines, jobPermsInsertLine, permBlock.String())
		}
	}

	// Now rewrite the top-level permissions block. Since we spliced above, recount
	// by reparsing on the modified source.
	modSrc := joinLines(lines)
	root5, _ := parseDoc(modSrc)
	m5 := topMap(root5)
	_, _, permsIdx5 := findKey(m5, "permissions")
	if permsIdx5 >= 0 {
		permKeyNode5 := m5.Content[permsIdx5]
		permEndLine5 := endLineOfValue(m5, permsIdx5, strings.Count(string(modSrc), "\n")+1)
		permStartLine := permKeyNode5.Line
		// Replace lines [permStartLine-1 .. permEndLine-1) with newPermBlock.
		modLines := splitLines(modSrc)
		var out []string
		out = append(out, modLines[:permStartLine-1]...)
		if newPermBlock != "" {
			// Strip trailing newline from newPermBlock since each element in lines ends with \n.
			for _, bl := range strings.SplitAfter(strings.TrimRight(newPermBlock, "\n"), "\n") {
				if bl != "" {
					out = append(out, bl)
				}
			}
		}
		out = append(out, modLines[permEndLine5:]...)
		modSrc = []byte(strings.Join(out, ""))
	}

	var changes []Change
	changes = append(changes, Change{
		File:    path,
		Rule:    "GHA020",
		Line:    permKeyNode.Line,
		Summary: fmt.Sprintf("moved write permissions %v from workflow level to job %q", scopeNames(writeScopes), jobName),
	})

	return modSrc, changes, ""
}

// permScope holds a single permission scope key+value pair.
type permScope struct{ k, v string }

func scopeNames(ss []permScope) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = s.k
	}
	return out
}

// splitLines splits src into a slice where each element is a line including its
// trailing newline character(s). The last element may not have a trailing newline.
func splitLines(src []byte) []string {
	// SplitAfter on \n keeps the \n attached to each element.
	return strings.SplitAfter(string(src), "\n")
}

// joinLines reassembles the slice produced by splitLines.
func joinLines(lines []string) []byte {
	return []byte(strings.Join(lines, ""))
}

// spliceLines inserts text after the given 1-indexed line number in the lines slice.
// text must be a complete newline-terminated string (each logical line ends with \n).
// It is split on \n boundaries while keeping the \n attached to each segment.
func spliceLines(lines []string, after int, text string) []string {
	if after < 0 {
		after = 0
	}
	if after > len(lines) {
		after = len(lines)
	}
	// Split text into newline-terminated segments. SplitAfter keeps the \n.
	// If text ends with \n, the last element will be "" which we discard.
	parts := strings.SplitAfter(text, "\n")
	var inserted []string
	for _, p := range parts {
		if p != "" {
			inserted = append(inserted, p)
		}
	}
	result := make([]string, 0, len(lines)+len(inserted))
	result = append(result, lines[:after]...)
	result = append(result, inserted...)
	result = append(result, lines[after:]...)
	return result
}
