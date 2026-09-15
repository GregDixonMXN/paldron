//go:build !linux

package sandbox

import (
	"fmt"
	"runtime"
)

// OS process isolation (Landlock/seccomp) is Linux-only. Policy gating
// (paldron check) and degraded exec with require_os_isolation=false work on
// this platform; full kernel-boundary exec does not.
func isolationSupported(bool) error {
	return fmt.Errorf("OS process isolation is currently supported only on Linux (this host is %s); use require_os_isolation=false for policy-gate-only mode", runtime.GOOS)
}

func isolationHelperPath() (string, error) {
	return "", isolationSupported(false)
}

func runIsolated(isolationRequest) error {
	return isolationSupported(false)
}
