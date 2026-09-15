# Paldron

**Decide whether it may run.** Policy gate and sandboxed exec for commands
invoked by coding agents. Exits 0 allow, 2 deny, 1 broken (same numbers as
`annalist gate`: Annalist records what happened, Paldron decides whether it
may run).

No model, no chat, no cloud.

## Platform support

| Platform | `check` (policy gate) | `exec` policy + output scan | OS isolation (Landlock/seccomp) |
|---|---|---|---|
| Linux x86_64 | yes | yes | yes |
| Linux arm64 | yes | yes | builds; kernel isolation untested on arm64 |
| macOS arm64 / amd64 | yes | yes | partial (kernel: network + credential vaults; files: policy + scan) |
| Windows amd64 | yes | yes (`require_os_isolation = false`) | no — fails closed |

Requesting `require_os_isolation = true` where no kernel backend exists
(Windows) exits 1 with a clear message instead of running unisolated.
Degraded mode prints a warning to stderr on every run.

## Install

Prebuilt tarballs for Linux, macOS, and Windows are on the
[releases page](https://github.com/GregDixonMXN/paldron/releases).
Or build from source (requires Go 1.24+):

```sh
go install github.com/GregDixonMXN/paldron/cmd/paldron@latest
# or
git clone https://github.com/GregDixonMXN/paldron && cd paldron && go build -o paldron ./cmd/paldron
```

Versioned tarballs: `scripts/package.sh v0.2.0` (cross-targets via
`GOOS`/`GOARCH`, e.g. `GOOS=darwin GOARCH=arm64 scripts/package.sh v0.2.0`).

## Quickstart (2 minutes)

```sh
printf 'open(".env", "w").write("x=1\\n")\n' > src/leak.py
paldron exec --policy policy.toml -- python3 src/leak.py
# paldron: deny: run produced .env (policy deny_glob)   (exit 2, no model running)
```

1. Copy `examples/paldron-exec/policy.toml` (Linux) or
   `examples/paldron-exec/policy.mac.toml` (Mac/Windows).
2. Run your agent command behind it:
   `paldron exec --policy policy.toml -- <command>`.
3. Try to exfiltrate or write a secret — expect exit 2 with a reason.

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
limits (Linux; policy gate + output scan elsewhere), then flips a
successful run to deny if it produced a denied file (argv gating cannot
see runtime writes). Flags are not paths.

## Commands

```sh
paldron check --policy policy.toml -- write_file '{"path":"/abs/src/a.txt","content":"hi"}'
paldron exec  --policy policy.toml -- python3 src/tool.py
paldron schema --tool execute_code
```

See `examples/paldron-exec/` for the composed fixture, including the
Mac/Windows policy.

## Build

Requires Go 1.24+. `go test ./...`. Extracted from Reeve's
guardrail + sandbox (see reeve/docs/cut.md); the registry, models,
memory, and desktop stayed behind.
