//go:build windows

package sandbox

import (
	"os"
	"os/exec"
)

// setProcessGroup is a no-op on Windows: creation flags for process trees
// stay at the stdlib default so the build stays portable. Timeout cleanup
// kills the direct child; nested grandchildren are best-effort.
func setProcessGroup(cmd *exec.Cmd) {}

// cancelProcessTree kills the direct child on timeout.
func cancelProcessTree(cmd *exec.Cmd) func() error {
	return func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		return cmd.Process.Kill()
	}
}

// killProcessTree is best-effort cleanup for a child that raced the timeout.
func killProcessTree(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
