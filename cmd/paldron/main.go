// Package main implements the paldron CLI: policy decisions over tool calls
// and sandboxed command execution.
//
// paldron check --policy p.toml -- toolname '{"json":"args"}'
// paldron exec  --policy p.toml -- argv...
// paldron schema --tool name
//
// Exit 0 allow, 2 policy deny, 1 sandbox/setup broken (same numbers as
// annalist gate). Annalist records what happened; paldron decides whether
// it may run.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/GregDixonMXN/paldron/internal/paldron"
	"github.com/GregDixonMXN/paldron/internal/sandbox"
	"github.com/GregDixonMXN/paldron/internal/schema"
)

// builtinDefs states the file/code tool contracts (names, args, descriptions).
// without importing the registry (cloud/memory entanglement stays out).
func builtinDefs() map[string]schema.ToolDefinition {
	mk := func(name, desc string, params map[string]schema.JSONSchema, required ...string) schema.ToolDefinition {
		return schema.ToolDefinition{
			Name:        name,
			Description: desc,
			Parameters:  schema.ObjectSchema(params, required...),
		}
	}
	str := func(desc string) schema.JSONSchema { return schema.JSONSchema{Type: "string", Description: desc} }
	return map[string]schema.ToolDefinition{
		"read_file": mk("read_file", "Read file contents from an allowed directory",
			map[string]schema.JSONSchema{"path": str("Absolute path to the file")}, "path"),
		"write_file": mk("write_file", "Write content to a file in an allowed directory",
			map[string]schema.JSONSchema{
				"path":    str("Absolute path to the file"),
				"content": str("Complete content to write"),
			}, "path", "content"),
		"edit_file": mk("edit_file", "Replace the first occurrence of old_text with new_text in a file",
			map[string]schema.JSONSchema{
				"path":     str("Absolute path to the file"),
				"old_text": str("Exact text to replace"),
				"new_text": str("Replacement text"),
			}, "path", "old_text", "new_text"),
		"list_dir": mk("list_dir", "List files and directories at a path",
			map[string]schema.JSONSchema{"path": str("Absolute directory path")}, "path"),
		"execute_code": mk("execute_code", "Execute a single binary command in a sandboxed directory. Shell chaining, pipes, redirects, and subshells are blocked.",
			map[string]schema.JSONSchema{
				"command": str("Single command with no shell operators"),
				"dir":     str("Absolute working directory"),
			}, "command", "dir"),
	}
}

func newPaldron(p *Policy) *paldron.Paldron {
	g := paldron.New(paldron.SecurityConfig{
		EnableGuardrails: true,
		AllowNetwork:     p.AllowNetwork,
	})
	for name, def := range builtinDefs() {
		g.RegisterDefinition(def)
		_ = name
	}
	return g
}

func fail(msg string, args ...any) int {
	fmt.Fprintf(os.Stderr, "paldron: "+msg+"\n", args...)
	return 1
}

func deny(msg string, args ...any) int {
	fmt.Fprintf(os.Stderr, "paldron: deny: "+msg+"\n", args...)
	return 2
}

func runCheck(p *Policy, toolName, rawArgs string) int {
	var args map[string]any
	if err := json.Unmarshal([]byte(rawArgs), &args); err != nil {
		return fail("bad JSON args: %v", err)
	}
	if args == nil {
		args = map[string]any{}
	}
	call := &schema.ToolCall{Name: toolName, Args: args}
	if err := newPaldron(p).Check(call); err != nil {
		return deny("%s", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return fail("getwd: %v", err)
	}
	for key, val := range args {
		s, ok := val.(string)
		if !ok || s == "" || strings.HasPrefix(s, "-") {
			continue // non-strings, empty, and flags are not paths
		}
		if reason := p.EvalPath(cwd, s); reason != "" {
			return deny("%s (%s)", s, reason)
		}
		_ = key
	}
	fmt.Printf("paldron: allow %s\n", toolName)
	return 0
}

func runExec(p *Policy, argv []string) int {
	if len(argv) == 0 {
		return fail("usage: paldron exec --policy p.toml -- argv...")
	}
	bin := filepath.Base(argv[0])
	if len(p.AllowBinaries) > 0 && !containsFold(p.AllowBinaries, bin) {
		return deny("binary '%s' not in allow_binaries", bin)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return fail("getwd: %v", err)
	}
	for _, a := range argv[1:] {
		if a == "" || strings.HasPrefix(a, "-") {
			continue // flags are not paths
		}
		if reason := p.EvalPath(cwd, a); reason != "" {
			return deny("%s (%s)", a, reason)
		}
	}
	cfg := sandbox.SandboxConfig{
		Enabled:            true,
		RequireOSIsolation: p.RequireOSIsolation,
		AllowNetwork:       p.AllowNetwork,
		AllowedDirs:        []string{cwd},
		BlockedPatterns:    p.DenyGlobs,
		AllowedBinaries:    p.AllowBinaries,
		TimeoutSec:         intOr(p.TimeoutSec, 30),
		MaxOutputBytes:     1024 * 1024,
		CPUTimeSec:         intOr(p.CPUTimeSec, defaultCPUTimeSec),
		MaxMemoryBytes:     int64(intOr(p.MaxMemoryMB, defaultMaxMemoryMB)) * 1024 * 1024,
		MaxProcesses:       intOr(p.MaxProcesses, defaultMaxProcesses),
		MaxFileSizeBytes:   int64(intOr(p.MaxFileSizeMB, defaultMaxFileSizeMB)) * 1024 * 1024,
		MaxOpenFiles:       intOr(p.MaxOpenFiles, defaultMaxOpenFiles),
	}
	if p.RequireOSIsolation {
		helperPath, helperErr := sandbox.IsolationHelperPath()
		isolationErr := sandbox.IsolationSupported(p.AllowNetwork)
		switch {
		case helperErr != nil:
			return fail("OS isolation unavailable (helper): %v", helperErr)
		case isolationErr != nil:
			return fail("OS isolation unavailable: %v", isolationErr)
		default:
			cfg.HelperPath = helperPath
		}
	}
	sb := sandbox.NewSandbox(cfg)
	if p.RequireOSIsolation && !sb.HasOSIsolation() {
		return fail("OS isolation required but not active; refusing to run")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.TimeoutSec+5)*time.Second)
	defer cancel()
	start := time.Now()
	res := sb.ExecuteArgs(ctx, argv, cwd, nil)
	fmt.Print(res.String())
	if res.Error != "" {
		return fail("sandbox: %s", res.Error)
	}
	if res.TimedOut {
		return fail("command timed out")
	}
	if res.ExitCode != 0 {
		return fail("command exited %d", res.ExitCode)
	}
	// Post-run verdict: argv gating cannot see files the process creates at
	// runtime. Any deny/secret-glob file (re)written by this run flips the
	// verdict to deny — same rule as the check path, applied to outputs.
	if hit := scanOutputs(cwd, p, start); hit != "" {
		return deny("run produced %s", hit)
	}
	return 0
}

// scanOutputs returns the first deny/secret-glob file under root modified
// at or after start, or "" when the run produced none.
func scanOutputs(root string, p *Policy, start time.Time) string {
	hit := ""
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if hit != "" || err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".annalist" || d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil || info.ModTime().Before(start) {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		for _, g := range p.DenyGlobs {
			if globMatch(g, rel) {
				hit = fmt.Sprintf("%s (policy deny_glob)", rel)
				return nil
			}
		}
		for _, g := range DefaultSecretGlobs {
			if globMatch(g, rel) {
				hit = fmt.Sprintf("%s (secret)", rel)
				return nil
			}
		}
		return nil
	})
	return hit
}

func runSchema(tool string) int {
	def, ok := builtinDefs()[tool]
	if !ok {
		return fail("unknown tool '%s'", tool)
	}
	out, err := json.MarshalIndent(def, "", "  ")
	if err != nil {
		return fail("encode schema: %v", err)
	}
	fmt.Println(string(out))
	return 0
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

func intOr(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

func usage() int {
	fmt.Fprintln(os.Stderr, `paldron — policy gate and sandboxed exec (exits 0 allow, 2 deny, 1 broken)

  paldron check --policy p.toml -- toolname '{"json":"args"}'
  paldron exec  --policy p.toml -- argv...
  paldron schema --tool name
  paldron version`)
	return 1
}

// version is baked at release time: go build -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

func runVersion() int {
	fmt.Printf("paldron %s\n", version)
	return 0
}

func main() {
	// Sandbox helper re-exec: restricted child, never the CLI.
	if sandbox.IsSandboxHelperInvocation(os.Args) {
		if err := sandbox.RunSandboxHelper(os.Args); err != nil {
			fmt.Fprintln(os.Stderr, "paldron helper:", err)
			os.Exit(1)
		}
		return
	}
	args := os.Args[1:]
	if len(args) == 0 {
		os.Exit(usage())
	}
	cmd, args := args[0], args[1:]
	policyPath := ""
	rest := []string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			rest = append(rest, args[i+1:]...)
			break
		}
		if a == "--policy" {
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "paldron: --policy needs a file")
				os.Exit(1)
			}
			policyPath = args[i]
			continue
		}
		if strings.HasPrefix(a, "--policy=") {
			policyPath = strings.TrimPrefix(a, "--policy=")
			continue
		}
		if cmd == "schema" && a == "--tool" {
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "paldron: --tool needs a name")
				os.Exit(1)
			}
			rest = append(rest, a, args[i])
			continue
		}
		rest = append(rest, a)
	}
	policy := DefaultPolicy()
	if policyPath != "" {
		var err error
		policy, err = LoadPolicy(policyPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "paldron:", err)
			os.Exit(1)
		}
	}
	switch cmd {
	case "check":
		if len(rest) < 1 {
			fmt.Fprintln(os.Stderr, "paldron: usage: paldron check --policy p.toml -- toolname '{\"args\"}'")
			os.Exit(1)
		}
		raw := "{}"
		if len(rest) > 1 {
			raw = rest[1]
		}
		os.Exit(runCheck(policy, rest[0], raw))
	case "exec":
		os.Exit(runExec(policy, rest))
	case "version":
		os.Exit(runVersion())
	case "schema":
		name := ""
		for i := 0; i < len(rest); i++ {
			if rest[i] == "--tool" && i+1 < len(rest) {
				name = rest[i+1]
			}
		}
		if name == "" {
			fmt.Fprintln(os.Stderr, "paldron: usage: paldron schema --tool name")
			os.Exit(1)
		}
		os.Exit(runSchema(name))
	default:
		os.Exit(usage())
	}
}
