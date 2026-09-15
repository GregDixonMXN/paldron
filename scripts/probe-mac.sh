#!/bin/sh
# Mac verification probe for the paldron Seatbelt backend.
# Run on a Mac after pulling:  sh scripts/probe-mac.sh
# Exits 0 only if every check passes. Paste the full output back on failure.
set -eu
cd "$(dirname "$0")/.."
[ "$(uname -s)" = Darwin ] || { echo 'SKIP: probe-mac runs on macOS only'; exit 0; }

go build -o /tmp/paldron-probe ./cmd/paldron
P=/tmp/paldron-probe
WORK=/tmp/paldron-probe-work
rm -rf "$WORK"; mkdir -p "$WORK/src"
cd "$WORK"

cat > policy.toml <<'EOF'
allow_paths = ["src/"]
deny_globs = [".env", ".env.*", "*.pem", "**/secrets/**"]
allow_network = false
allow_binaries = ["python3", "sh"]
require_os_isolation = true
timeout_sec = 30
EOF

pass=0; fail=0
check() { # check <name> <expected-exit> <command...>
  name=$1; want=$2; shift 2
  set +e; out=$("$@" 2>&1); got=$?; set -e
  if [ "$got" = "$want" ]; then echo "PASS: $name (exit $got)"; pass=$((pass+1));
  else echo "FAIL: $name (want $want, got $got)"; echo "$out" | head -n 10; fail=$((fail+1)); fi
}

echo 'print("hello")' > src/tool.py
check "allowed write in src" 0 $P exec --policy policy.toml -- python3 src/tool.py
check "secret write denied" 2 $P exec --policy policy.toml -- python3 -c 'open(".env","w")'
rm -f .env

# Kernel network deny: socket creation must fail inside the sandbox.
set +e
netout=$($P exec --policy policy.toml -- python3 -c 'import socket; socket.create_connection(("example.com", 80), timeout=5)' 2>&1); netcode=$?
set -e
if [ "$netcode" != 0 ] && printf '%s' "$netout" | grep -qiE 'permitted|denied|network|unreachable|timed out|refused'; then
  echo "PASS: network egress blocked (exit $netcode)"; pass=$((pass+1))
else
  echo "FAIL: network egress NOT blocked (exit $netcode)"; echo "$netout" | head -n 10; fail=$((fail+1))
fi

# Kernel vault deny: reading ~/.ssh must fail even though policy is silent.
if [ -d "$HOME/.ssh" ]; then
  set +e
  sshout=$($P exec --policy policy.toml -- python3 -c 'import os; print(os.listdir(os.path.expanduser("~/.ssh")))' 2>&1); sshcode=$?
  set -e
  if printf '%s' "$sshout" | grep -qiE 'permitted|denied'; then
    echo "PASS: ~/.ssh read blocked by kernel"; pass=$((pass+1))
  else
    echo "FAIL: ~/.ssh read NOT blocked (exit $sshcode)"; echo "$sshout" | head -n 10; fail=$((fail+1))
  fi
else
  echo 'SKIP: no ~/.ssh to test vault deny'
fi

check "check gate allows" 0 $P check --policy policy.toml -- write_file '{"path":"/tmp/paldron-probe-work/src/a.txt","content":"hi"}'

echo "--- probe: $pass passed, $fail failed"
[ "$fail" = 0 ]
