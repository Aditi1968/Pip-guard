# pip guard demo (Track C)

Everything needed to stand up the public demo repository whose pull requests show pip guard
failing a check on a planted malicious package and on every error case.

- `planted/requets/`: a typosquat of `requests` that, **on import**, reads `~/.aws/credentials`,
  spawns `sh -c "curl --version"` and attempts `connect()` to `203.0.113.50:443`. Harmless by
  design: it sends nothing, and the address is TEST-NET-3 (RFC 5737), which routes nowhere.
  pip guard only runs it inside the network-less sandbox.
- `planted/sleepy/`: import never returns, to force a sandbox timeout.
- `build_wheels.py`: builds both into wheels without running any package code.
- `template/`: the demo repo's initial contents (`requirements.txt`, `pipguard.toml`, workflow).
  The workflow passes `local-index: vendor/wheels`, so the planted wheels come from the repo and
  every other spec comes from PyPI as usual. Planted packages are never published to PyPI.
- `make_prs.sh`: creates the public repo and the five PRs.

## Run it

```bash
# 1. push pip guard itself to a public GitHub repo and note a commit SHA
# 2. then:
gh auth login
bash demo/make_prs.sh <you>/pipguard-demo <you>/pip-guard <commit-sha>
```

| PR | Change | Expected verdict | Check |
| --- | --- | --- | --- |
| add-planted | `requets==2.31.0` | `block`: typosquat of `requests` (distance 1, top-100); credential file read plus subprocess/`connect()` | fails |
| benign-bump | `six` 1.16.0 → 1.17.0 | `allow` | passes |
| unpinned-spec | `flask>=3` | `warn`: not an exact pin, not scanned | passes with warning |
| forced-timeout | `sleepy==1.0.0` | `incomplete:timeout` | fails (fail closed) |
| download-failure | `six==99.0.0` | `error`: PyPI has no such release | fails (fail closed) |

Record the planted-package PR's job summary as the README GIF (`vhs` or `asciinema` + `agg`).

## Try it locally first

```bash
uv run python -m demo.build_wheels /tmp/pg-wheels
docker build -f sandbox/sandbox.Dockerfile -t pipguard-sandbox:local .
uv run pipguard scan --no-sandbox --pretty --artifact /tmp/pg-wheels/requets-2.31.0-py3-none-any.whl
# The sandbox runs local wheels only as PR-proposed packages: see the end-to-end `pipguard ci`
# run in docs/log/08-integration-demo.md, or push the demo repo.
```
