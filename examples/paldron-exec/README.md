# paldron exec fixture

The composition, copy-paste:

```sh
annalist run -- paldron exec --policy policy.toml -- python3 src/tool.py
# exit 0, src/out.txt written, session recorded
```

A tool that writes `.env` instead exits 2 (`run produced .env`), and the
annalist session records the denial. Paldron decides, annalist records.

## Mac / Windows (policy gate only, no kernel boundary)

```sh
paldron exec --policy policy.mac.toml -- python3 src/tool.py
# warns: running without OS isolation (policy gate + output scan only)
```

`policy.mac.toml` sets `require_os_isolation = false`. Path policy,
binary whitelist, blocked patterns, and the post-run denied-file scan all
enforce; Landlock/seccomp isolation does not exist on these platforms.
Requesting `require_os_isolation = true` off Linux fails closed (exit 1)
instead of running unisolated.

macOS now has a Seatbelt backend: with `require_os_isolation = true` the
kernel denies network egress (when the policy disables it) and denies
access to ~/.ssh, ~/.aws, ~/.gnupg even if policy missed them. Workspace
files stay policy gate + output scan. Verify on a Mac with
`sh scripts/probe-mac.sh`.
