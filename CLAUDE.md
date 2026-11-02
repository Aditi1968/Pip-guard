# pip guard

A CI gate that judges a Python dependency by what it does, not only by whether it is already known to be bad. When a PR adds or changes a pinned direct dependency, pip guard downloads the exact artifact, analyses it statically, installs and imports it in a disposable network-less container under strace, scores the evidence, and fails the GitHub check with readable reasons when the package looks malicious.

Before any task, read `docs/PRD.md` (source of truth for scope: FR-IDs, non-goals, success criteria), `docs/DESIGN.md` (how the pieces fit) and `docs/PLAN.md` (phase checklist and current status). If the PRD and anything else disagree, the PRD wins; say so and update the other file.

## Stack (v1)

- Python 3.12, managed with `uv`; `src/` layout
- CLI: `typer`; contracts: `pydantic` v2
- Tests: `pytest` + `pytest-cov` + `hypothesis` (parser fuzzing); lint/format: `ruff`; types: `pyright`
- Static analysis: stdlib `ast`, `rapidfuzz`
- Sandbox: Docker with `runc`, default seccomp, `--network none`, hardened flags (PRD FR-4.7); tracing with `strace -f -e trace=network,process,file`
- Scoring: rules in `rules.yaml` → scikit-learn logistic regression → LightGBM (each step only if it wins on held-out data)
- Cache: SQLite via stdlib `sqlite3`, keyed by artifact hash + scanner + model + config
- CI: GitHub Actions on a public repo; composite action
- Logging: stdlib `logging` with a JSON formatter
- NOT in v1: FastAPI service, network sinkhole, gVisor, eBPF, fine-tuned models, SARIF, lockfile parsing. Do not add them.

## Hard rules

- Never execute downloaded package code outside the sandbox container. Fetch, extraction, static analysis and trace parsing never run package code.
- Dynamic analysis runs only on our own fixture packages and on packages a PR proposes. Archived real-world malware is handled as files and never executed (PRD FR-4.10).
- Never weaken container isolation to make tracing work. If strace does not work under the hardened flags, record it in `docs/DESIGN.md` and reduce scope instead.
- Fail closed: `error` and `incomplete` must fail the check. Never produce `allow` for an unexamined package.
- Treat strace output, downloaded archives and restored caches as untrusted input.
- Zero spend: no paid service, no card-gated free tier, no API key with billing. Evaluation runs locally, not in CI.
- Ask before adding a dependency. Prefer the standard library when reasonable.

## Working rules

- One task at a time. Finish, test, commit, then move on. Do not start the next PLAN.md checkbox until the current one is green.
- Write the test first when the behaviour is clear. Every stage function has unit tests with fixtures; no network in unit tests.
- Run `uv run pytest` and `uv run ruff check . && uv run ruff format --check . && uv run pyright` before every commit; do not commit if any fails.
- Do not modify files outside the scope of the current task without saying so first.
- Explain any non-obvious design choice in a short comment or in your reply so the author can understand and defend it in an interview.
- When a PLAN.md step is done, tick it. When a decision changes the design, update `docs/DESIGN.md` in the same commit.
- Commit messages: imperative mood, one-line summary, optional body. Example: `Add safe extraction with path and size limits`.

## Project layout (target)

```
src/pipguard/
  cli.py          # typer entry point: pipguard scan / explain
  models.py       # pydantic: PackageSpec, Artifact, FetchedPackage, StaticFeatures, BehaviorTrace, Verdict
  fetch.py        # PyPI JSON API, download, hash check, declared deps
  extract.py      # safe archive extraction (path/link/size/count limits)
  static.py       # ast-based indicators, entropy, URLs/IPs, typosquat
  sandbox.py      # Docker run: deps preinstall (untraced) -> target --no-deps + import (traced)
  trace.py        # strace parser -> BehaviorTrace (defensive, fuzz-tested)
  rules.py        # blocking + warning rules from rules.yaml
  scoring.py      # rules + model -> Verdict with reasons and coverage
  report.py       # job summary Markdown, JSON report, optional PR comment
  cache.py        # SQLite verdict cache
  diff.py         # pinned direct-dependency diff for requirements.txt / pyproject.toml
sandbox/          # sandbox.Dockerfile, fake credential files, manifest
action/           # action.yml + exit-code mapping
tests/
  fixtures/       # suspicious fixtures, each with a benign counterexample
docs/             # PRD.md, DESIGN.md, PLAN.md, EVAL.md, COSTS.md
.github/workflows/
```
