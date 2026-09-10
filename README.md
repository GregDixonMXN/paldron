# Paldron

**Decide whether it may run.** Policy gate and sandboxed exec for commands
invoked by coding agents. Exits 0 allow, 2 deny, 1 broken (same numbers as
`annalist gate`: Annalist records what happened, Paldron decides whether it
may run).

Linux only. No model, no chat, no cloud.

```sh
paldron exec --policy policy.toml -- python3 -c 'open(".env","w")'
# paldron: deny: run produced .env (secret)   (exit 2, no model running)
```

## Policy

```toml
allow_paths = ["src/", "docs/"]
deny_globs = [".env", ".env.*", "*.pem", "**/secrets/**"]
allow_network = false
allow_binaries = ["ls", "cat", "python3", "git"]
require_os_isolation = true
timeout_sec = 30
# Resource ceilings (all optional, 0 = default). max_processes counts every
# task of the invoking user (NPROC semantics), so keep it in the thousands.
max_processes = 4096   # default 4096
max_memory_mb = 8192   # default 8192
max_open_files = 1024  # default 1024
cpu_time_sec = 60      # default 60
max_file_size_mb = 1024 # default 1024
```

Secrets are denied even with no policy file. Unknown keys are an error.
`exec` gates argv, runs the command behind Landlock/seccomp/resource
limits, then flips a successful run to deny if it produced a denied file
(argv gating cannot see runtime writes). Flags are not paths.

## Commands

```sh
paldron check --policy policy.toml -- write_file '{"path":"/abs/src/a.txt","content":"hi"}'
paldron exec  --policy policy.toml -- python3 src/tool.py
paldron schema --tool execute_code
```

## Build

Requires Go 1.24+. `go test -race ./...`. Extracted from Reeve's
guardrail + sandbox (see reeve/docs/cut.md); the registry, models,
memory, and desktop stayed behind.
