#!/usr/bin/env bash
# Week-1 spike (PRD open question 1): does `strace -f` work inside the sandbox container
# under the FR-4.7 hardened flags, unmodified? Exit 0 = yes, 1 = no.
#
#   docker build -f sandbox/sandbox.Dockerfile -t pipguard-sandbox:dev .
#   bash sandbox/spike.sh pipguard-sandbox:dev
#
# The spike wheel is our own code: on import it opens the seeded AWS credentials, spawns
# `sh -c true` and attempts connect() to a TEST-NET address. Artifacts go in via a tar on
# stdin because FR-4.7 forbids bind mounts.
set -euo pipefail

IMAGE="${1:-pipguard-sandbox:dev}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/src/spikepkg" "$WORK/in"
cat > "$WORK/src/spikepkg/__init__.py" <<'PY'
import socket, subprocess
open("/home/sandbox/.aws/credentials").read()
subprocess.run(["sh", "-c", "true"], check=False)
s = socket.socket()
s.settimeout(1)
try:
    s.connect(("203.0.113.7", 443))
except OSError:
    pass
PY
PYTHON="$(command -v python3 || command -v python)"
"$PYTHON" "$(dirname "$0")/../scripts/make_wheel.py" "$WORK/in" spikepkg 0.0.1 "$WORK/src" >/dev/null

# FR-4.7 exactly. tmpfs mounts keep Docker's default noexec,nosuid,nodev.
FLAGS=(
  --rm -i
  --network none
  --read-only
  --tmpfs /tmp:rw,size=256m,mode=1777
  --tmpfs /sandbox/site-packages:rw,size=512m,mode=1777
  --tmpfs /home/sandbox/.cache:rw,size=256m,mode=1777
  --cap-drop ALL
  --security-opt no-new-privileges
  --memory 1g
  --pids-limit 256
  --user 10001:10001
)
echo "flags: ${FLAGS[*]}"

STRACE="strace -f -qq -s 256 -e trace=network,process,file"
SCRIPT="set -e
mkdir -p /tmp/in && tar -x -C /tmp/in
$STRACE -o /tmp/install.trace pip install --no-deps --no-index --target /sandbox/site-packages /tmp/in/*.whl >/tmp/pip.log 2>&1 || { cat /tmp/pip.log; exit 10; }
$STRACE -o /tmp/import.trace python -c 'import spikepkg' || exit 11
echo '--- install trace lines:' \$(wc -l < /tmp/install.trace)
echo '--- import trace (filtered):'
grep -E 'credentials|execve|connect\\(' /tmp/import.trace || true"

set +e
OUT="$(tar -c -C "$WORK/in" . | docker run "${FLAGS[@]}" "$IMAGE" sh -c "$SCRIPT" 2>&1)"
RC=$?
set -e
echo "$OUT"
echo "container exit: $RC"

ok=1
grep -q 'openat(.*\.aws/credentials' <<<"$OUT" || { echo "MISSING: credential openat"; ok=0; }
grep -q 'execve(.*"sh"' <<<"$OUT" || { echo "MISSING: subprocess execve"; ok=0; }
grep -q 'connect(.*203\.0\.113\.7' <<<"$OUT" || { echo "MISSING: connect()"; ok=0; }
if [[ $RC -eq 0 && $ok -eq 1 ]]; then echo "SPIKE_RESULT=pass"; exit 0; fi
echo "SPIKE_RESULT=fail"; exit 1
