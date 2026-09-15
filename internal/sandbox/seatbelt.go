package sandbox

import (
	"fmt"
	"path/filepath"
	"strings"
)

// sandboxExecPath is the macOS Seatbelt enforcement binary.
const sandboxExecPath = "/usr/bin/sandbox-exec"

// seatbeltProfile renders the Seatbelt (SBPL) profile enforcing req.
//
// v1 scope: the kernel denies network (when the policy disables it) and
// denies access to credential vaults even if policy missed them. Workspace
// file policy stays in the argv gate + post-run output scan.
//
// (allow default) keeps the profile fail-safe: unlisted operations are
// allowed, listed denies are the boundary. A malformed profile makes
// sandbox-exec exit non-zero, which fails the run closed (exit 1),
// never open.
func seatbeltProfile(req isolationRequest, home string) string {
	var sb strings.Builder
	sb.WriteString("(version 1)\n(allow default)\n")
	if !req.AllowNetwork {
		sb.WriteString("(deny network*)\n")
	}
	for _, dir := range secretVaultDirs(home) {
		fmt.Fprintf(&sb, "(deny file-read* (subpath %q))\n", dir)
		fmt.Fprintf(&sb, "(deny file-write* (subpath %q))\n", dir)
	}
	return sb.String()
}

// secretVaultDirs lists credential stores the kernel always denies.
// Rules reference paths whether or not they exist yet, so vaults created
// mid-run are covered too. Empty home disables the rules.
func secretVaultDirs(home string) []string {
	if home == "" {
		return nil
	}
	return []string{
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".aws"),
		filepath.Join(home, ".gnupg"),
	}
}
