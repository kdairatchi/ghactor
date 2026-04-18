// Package trial wraps nektos/act for local workflow execution.
package trial

import (
	"fmt"
	"os"
	"os/exec"
)

// Run invokes `act` with the given extra args. Streams stdout/stderr.
func Run(event string, workflow string, extra []string) error {
	if _, err := exec.LookPath("act"); err != nil {
		return fmt.Errorf("`act` not found in PATH — install nektos/act: https://github.com/nektos/act")
	}
	args := []string{}
	if event != "" {
		args = append(args, event)
	}
	if workflow != "" {
		args = append(args, "-W", workflow)
	}
	args = append(args, extra...)
	cmd := exec.Command("act", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}
