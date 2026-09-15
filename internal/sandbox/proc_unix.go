//go:build !windows

package sandbox

import (
	"os"
	"os/exec"
	"syscall"
)

// setProcessGroup puts the child in its own process group so a timeout can
// kill the entire tree, not just the parent. Unix only.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// cancelProcessTree is the CommandContext Cancel func: SIGKILL the group.
func cancelProcessTree(cmd *exec.Cmd) func() error {
	return func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if err == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return err
	}
}

// killProcessTree is best-effort cleanup for a child that raced the timeout.
func killProcessTree(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
