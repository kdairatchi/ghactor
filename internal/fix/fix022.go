package fix

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// addShellToSteps implements the GHA022 autofix: for every step that has a
// run: key but no shell: key, and whose enclosing job has no
// defaults.run.shell set (nor does the workflow), insert shell: <defaultShell>
// as a sibling key immediately before run:.
//
// The function only touches steps in jobs that are multi-OS matrix jobs
// (matching the same detection logic used by the lint rule). It is intentionally
// broader in the fix: it will also apply to non-matrix jobs because the lint
// rule may not have flagged them, but having an explicit shell is always safe.
// Callers control scope via opts.FixShell022.
func addShellToSteps(path string, src []byte, defaultShell string) ([]byte, []Change) {
	if defaultShell == "" {
		defaultShell = "bash"
	}

	root, err := parseDoc(src)
	if err != nil {
		return src, nil
	}
	m := topMap(root)

	// Check workflow-level defaults.run.shell.
	if wfDefaultShell(m) != "" {
		return src, nil
	}

	jobsKey, jobsVal, _ := findKey(m, "jobs")
	_ = jobsKey
	if jobsVal == nil || jobsVal.Kind != yaml.MappingNode {
		return src, nil
	}

	totalLines := strings.Count(string(src), "\n") + 1
	_ = totalLines

	// Collect insertion points: (lineAfterWhich, indentPrefix) sorted by line desc.
	type ins struct {
		afterLine int
		indent    string
		stepName  string
		jobName   string
	}
	var inserts []ins

	for i := 0; i+1 < len(jobsVal.Content); i += 2 {
		jobName := jobsVal.Content[i].Value
		jobNode := jobsVal.Content[i+1]
		if jobNode.Kind != yaml.MappingNode {
			continue
		}

		// Skip if job-level defaults.run.shell is set.
		if jobDefaultShell(jobNode) != "" {
			continue
		}

		stepsNode := findNodeKey(jobNode, "steps")
		if stepsNode == nil || stepsNode.Kind != yaml.SequenceNode {
			continue
		}

		for _, stepNode := range stepsNode.Content {
			if stepNode.Kind != yaml.MappingNode {
				continue
			}

			// Skip uses: steps.
			if findNodeKey(stepNode, "uses") != nil {
				continue
			}

			runKey := findNodeKeyNode(stepNode, "run")
			if runKey == nil {
				continue
			}

			// Already has shell:.
			if findNodeKey(stepNode, "shell") != nil {
				continue
			}

			// Insert shell: before run: — use run key's line - 1 (insert before that line).
			// We'll splice the text at (runKey.Line - 1) so it appears before run:.
			nameNode := findNodeKey(stepNode, "name")
			stepName := ""
			if nameNode != nil {
				stepName = nameNode.Value
			}

			// Indent = column of the run key - 1 (0-indexed).
			indent := strings.Repeat(" ", runKey.Column-1)

			inserts = append(inserts, ins{
				afterLine: runKey.Line - 1, // insert before run: line
				indent:    indent,
				stepName:  stepName,
				jobName:   jobName,
			})
		}
		_ = jobName
	}

	if len(inserts) == 0 {
		return src, nil
	}

	// Sort descending by line so splicing doesn't shift subsequent positions.
	for a := 0; a < len(inserts); a++ {
		for b := a + 1; b < len(inserts); b++ {
			if inserts[b].afterLine > inserts[a].afterLine {
				inserts[a], inserts[b] = inserts[b], inserts[a]
			}
		}
	}

	lines := splitLines(src)
	var changes []Change

	for _, in := range inserts {
		shellLine := fmt.Sprintf("%sshell: %s\n", in.indent, defaultShell)
		lines = spliceLines(lines, in.afterLine, shellLine)
		changes = append(changes, Change{
			File:    path,
			Rule:    "GHA022",
			Line:    in.afterLine + 1,
			Summary: fmt.Sprintf("added shell: %s to step %q in job %q", defaultShell, in.stepName, in.jobName),
		})
	}

	// Flip changes back to file order.
	for a, b := 0, len(changes)-1; a < b; a, b = a+1, b-1 {
		changes[a], changes[b] = changes[b], changes[a]
	}

	return joinLines(lines), changes
}

// wfDefaultShell returns the workflow-level defaults.run.shell value, or "".
func wfDefaultShell(m *yaml.Node) string {
	defaultsNode := findNodeKey(m, "defaults")
	if defaultsNode == nil {
		return ""
	}
	runNode := findNodeKey(defaultsNode, "run")
	if runNode == nil {
		return ""
	}
	shellNode := findNodeKey(runNode, "shell")
	if shellNode == nil {
		return ""
	}
	return shellNode.Value
}

// jobDefaultShell returns the job-level defaults.run.shell value, or "".
func jobDefaultShell(jobNode *yaml.Node) string {
	defaultsNode := findNodeKey(jobNode, "defaults")
	if defaultsNode == nil {
		return ""
	}
	runNode := findNodeKey(defaultsNode, "run")
	if runNode == nil {
		return ""
	}
	shellNode := findNodeKey(runNode, "shell")
	if shellNode == nil {
		return ""
	}
	return shellNode.Value
}

// findNodeKey returns the value node for key in a MappingNode, or nil.
func findNodeKey(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// findNodeKeyNode returns the key node itself (not the value) for key in a MappingNode, or nil.
// Used when we need the line/column of the key rather than the value.
func findNodeKeyNode(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i]
		}
	}
	return nil
}
