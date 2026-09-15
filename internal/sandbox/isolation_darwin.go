//go:build darwin

package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// isolationSupported reports whether this Mac can enforce the Seatbelt
// boundary. sandbox-exec ships with macOS; without it there is no kernel
// boundary and callers must fail closed.
func isolationSupported(bool) error {
	fi, err := os.Stat(sandboxExecPath)
	if err != nil {
		return fmt.Errorf("sandbox-exec unavailable at %s: %w", sandboxExecPath, err)
	}
	if fi.IsDir() || fi.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("sandbox-exec at %s is not executable", sandboxExecPath)
	}
	return nil
}

// isolationHelperPath returns the enforcement binary so the shared
// pre-flight (non-empty helper path + IsolationSupported) works unchanged.
// The darwin path never re-execs paldron as a helper; executeParts calls
// newDarwinSandboxCommand directly.
func isolationHelperPath() (string, error) {
	if err := IsolationSupported(false); err != nil {
		return "", err
	}
	return sandboxExecPath, nil
}

// newDarwinSandboxCommand wraps req.Command in sandbox-exec with a generated
// Seatbelt profile stored under tempHome (removed by the caller with the
// rest of the ephemeral home).
func newDarwinSandboxCommand(ctx context.Context, tempHome string, req isolationRequest) (*exec.Cmd, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}
	profile := seatbeltProfile(req, home)
	path := filepath.Join(tempHome, "paldron.sbpl")
	if err := os.WriteFile(path, []byte(profile), 0o600); err != nil {
		return nil, fmt.Errorf("write sandbox profile: %w", err)
	}
	args := append([]string{"-f", path}, req.Command...)
	return exec.CommandContext(ctx, sandboxExecPath, args...), nil
}

// runIsolated is unused on darwin: isolation goes through sandbox-exec,
// not the Linux re-exec helper. Kept to satisfy the platform interface;
// reaching it is a bug, so it fails closed.
func runIsolated(isolationRequest) error {
	return fmt.Errorf("darwin isolation runs via sandbox-exec, not the re-exec helper")
}
