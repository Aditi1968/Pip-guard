#!/usr/bin/env bash
# Map the `pipguard ci` exit code to the job outcome (FR-6.6, FR-7.4). Fails closed:
# anything that is not exactly 0 fails the job, including an empty or garbled code
# (e.g. the scan step never ran).
code="${1-}"
case "$code" in
  0)
    echo "pip guard: pass (allow, or warn without fail-on-warn)"
    exit 0 ;;
  1)
    echo "::error title=pip guard::warn with fail-on-warn: failing the job"
    exit 1 ;;
  2)
    echo "::error title=pip guard::blocked: a dependency looks malicious, see the job summary"
    exit 2 ;;
  3)
    echo "::error title=pip guard::error/incomplete: failing closed, a dependency was not fully examined"
    exit 3 ;;
  *)
    # Echo the code only if short and alphanumeric, so it cannot inject a workflow command.
    shown="(unprintable)"
    if [[ "$code" =~ ^[A-Za-z0-9]{0,16}$ ]]; then shown="'$code'"; fi
    echo "::error title=pip guard::unexpected exit code $shown, failing closed"
    exit 3 ;;
esac
