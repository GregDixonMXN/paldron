//go:build !darwin

package sandbox

import (
	"context"
	"fmt"
	"os/exec"
)

// newDarwinSandboxCommand is darwin-only. This stub keeps the shared
// execute path compiling on other platforms; reaching it means a bug, so
// it fails closed.
func newDarwinSandboxCommand(context.Context, string, isolationRequest) (*exec.Cmd, error) {
	return nil, fmt.Errorf("darwin sandbox-exec path used on a non-darwin host")
}
