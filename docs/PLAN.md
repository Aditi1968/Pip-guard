# pip guard — Build Plan (v0.2)

Budget: ~118 hours over 10 weeks at 10–12 h/week. Rules: thinnest end-to-end slice first; one phase per git branch; one checkbox per Claude Code conversation; every phase ends with something that runs, is tested and is committed. Tick `[x]` as steps complete. Requirements referenced as FR-x.y live in `docs/PRD.md`.

Three gates are never skipped: the behavioural fixture suite passes (M2), the evaluation is published (M3), the demo PR fails its check (M4). If the Sandbox phase runs past its 24-hour cap, the dynamic stage shrinks to a fixture demonstration and the remaining hours go to the static scanner, evaluation and Action — never to loosening isolation.

## Phase 0 — Foundation + spike (week 1, ~10 h)

Goal: "run tests" and "CI is green" are habits from day one, and we know whether strace works under hardened Docker.

- [x] `uv init`, Python 3.12, `src/pipguard/` layout, `pyproject.toml` with `typer`, `pydantic`, `pytest`, `pytest-cov`, `hypothesis`, `ruff`, `pyright`
- [x] `pipguard --help` and a stub `pipguard scan <name==version>` that validates the spec is an exact pin (FR-1.2) and exits 3 otherwise
- [x] `models.py` with `PackageSpec`, `Artifact`, `Verdict` (levels allow/warn/block/error/incomplete; `coverage` field) and `schema_version`
- [x] One passing test; `pre-commit` with ruff + pyright — one passing test: yes; `pre-commit` skipped by the author's decision (2026-11-02), CI enforces ruff + pyright
- [x] `.github/workflows/ci.yml`: lint, types, tests on push and PR; `permissions: contents: read`
- [x] `sandbox/sandbox.Dockerfile`: slim Python pinned by digest + strace, non-root user
- [x] **Spike:** run `strace -f` inside the container on `ubuntu-latest` with `--cap-drop ALL --security-opt no-new-privileges --network none --read-only` + tmpfs, non-root. Record result and exact flags in `docs/DESIGN.md` → "Week-1 spike"
- [x] `README.md`: one paragraph, "status: in progress", limitations placeholder
- [x] `docs/COSTS.md` started: "Phase 0 — ₹0; free tiers touched: GitHub Actions (public repo)"

Done when: `uv run pipguard --help` works, CI badge green, spike result recorded.

## Phase 1 — Fetch, safe extraction, static scan (weeks 2–3, ~24 h)

Goal: `pipguard scan --no-sandbox requests==2.31.0` prints a JSON report with artifact identity and indicators.

- [x] `fetch.py`: PyPI JSON API lookup; pick wheel for the runner's tags and the sdist if published; record filename/kind/sha256/tags (FR-2.1)
- [x] `fetch.py`: SHA-256 verification; mismatch → `error` verdict (FR-2.2)
- [x] `fetch.py`: read declared dependencies from wheel METADATA; download their wheels (FR-2.5)
- [x] `extract.py`: safe extraction with path containment, link rejection, 100 MB / 500 MB / 20,000-file limits (FR-2.3); tests with traversal, symlink and zip-bomb fixtures
- [x] `fetch.py`: metadata — release date, version count, maintainer count (missing flag), days since release/first release (FR-2.4)
- [x] `static.py`: `ast` walk with syntax errors recorded as a feature (FR-3.1)
- [x] `static.py`: install-time indicators as presence flags — `cmdclass`, overridden install commands, `.pth` import lines, PEP 517 backend in sdist (FR-3.2)
- [x] `static.py`: suspicious-indicator counts (FR-3.3)
- [x] `static.py`: entropy ≥ 4.5 bits/char over ≥ 40 chars (FR-3.4)
- [x] `static.py`: URL / IP / shortener extraction (FR-3.5)
- [x] `static.py`: typosquat — PEP 503 normalise, Damerau-Levenshtein via `rapidfuzz`, frozen dated top-5,000 snapshot committed under `data/` (FR-3.6)
- [x] `static.py`: network/subprocess/fs/env imports in top level or hook code (FR-3.7)
- [x] `StaticFeatures` model; CLI JSON output with `--pretty`; `--artifact <path>` for local wheels (FR-7.1)
- [x] Fixtures: one benign package and one hand-made suspicious package per indicator family; no network in unit tests

Done when: the suspicious fixtures and benign fixtures produce the expected indicator flags in a deterministic test, and extraction tests pass.

## Phase 2 — Sandbox (weeks 4–5, ~24 h, capped)

Goal: observe what the target package does during install and import, attribute behaviour to the target only, and never fail open.

- [x] `BehaviorTrace` model with `completeness` states (FR-4.5, FR-4.6)
- [x] Fake credential **files** + `sandbox/manifest.json` (FR-4.3)
- [x] `sandbox.py`: run container with the hardened flag set from FR-4.7 and `--network none` (FR-4.4); no bind mounts; artifacts copied in
- [x] `sandbox.py`: step 1 — preinstall declared deps `--no-index --find-links`, untraced
- [x] `sandbox.py`: step 2 — `pip install --no-deps` of the target under `strace -f -e trace=network,process,file`; step 3 — import modules from `top_level.txt`/`RECORD` under strace (FR-4.1, FR-4.2) — modules now come from the installed files, not `top_level.txt`/`RECORD` (review fix, see DESIGN)
- [x] Timeouts 90 s / 60 s; kill process tree; `incomplete:timeout` (FR-4.6)
- [x] `trace.py`: parser for writes outside allowed dirs, credential-file opens, subprocess argv, `connect()` with address/port, exit codes; field caps and escaping (FR-4.5, FR-4.11)
- [x] `hypothesis` fuzz tests for the parser
- [x] Policy guard: refuse to run the sandbox on anything not under `tests/fixtures/` or not flagged as a PR candidate (FR-4.10)
- [x] Fixture suite: suspicious fixtures (connect during install, credential-file read + subprocess, `.pth` import, obfuscated exec) each paired with a benign counterexample using the same API legitimately; one fixture with a noisy dependency to verify `--no-deps` attribution
- [x] Unit tests mock Docker; integration tests behind a `docker` marker

Done when: every fixture's expected observation appears in `BehaviorTrace`, benign counterexamples are clean, attribution is verified, and the container is destroyed after each run.

## Phase 3 — Rules, model ladder, evaluation (weeks 6–8, ~30 h)

Goal: a verdict with reasons and coverage, and `docs/EVAL.md` with numbers you can defend.

- [x] `rules.yaml` + `rules.py`: blocking rules and warning rules with fixed reason strings (FR-5.1)
- [x] `scoring.py`: `Verdict` assembly — blocking hit → block; warning hit → ≥ warn; coverage from stage completeness; overrides named (FR-5.3, FR-5.4, FR-7.2)
- [ ] Data: download Datadog archive (local only, never committed, never executed); fetch the fetchable subset of OpenSSF reports and record the count; benign sample stratified by band from the frozen snapshot plus a random band beyond top-5,000
- [ ] `data/manifest.csv`: name, version, artifact, sha256, label, source, campaign group, band, split; payload dedup by normalised-source hash; manual review of 50 benign samples
- [ ] Batch runner: static pipeline over the corpus locally, results appended to the manifest; nothing in CI
- [ ] Model ladder: rules alone → logistic regression (Platt-calibrated or labelled "score") → LightGBM only if recall at the FPR target improves ≥ 3 points (FR-5.2)
- [ ] Thresholds chosen on the validation fold at per-band FPR ≤ 0.05 and stored with the model artifact (FR-5.8)
- [ ] `docs/EVAL.md`: Track A counts, 95% Wilson CIs, per-band FPR, PR-AUC, calibration, blocking-rule precision, ablations; Track B fixture results; explicit statement that behavioural features are not evaluated on Track A — Track B done (15/15 locally); Track A pending the local corpus run
- [x] Explanations: LR coefficient contributions (SHAP if LightGBM adopted) through fixed reason templates (FR-5.5, P1)

Done when: `pipguard scan` outputs a verdict with reasons and coverage, and `docs/EVAL.md` is published with the numbers above.

## Phase 4 — CLI + Action (week 9, ~14 h)

Goal: a PR on the demo repo fails its check for a planted package and for every error case.

- [x] `diff.py`: added/changed exact pins between base and head in `requirements.txt` and PEP 621 `pyproject.toml` (FR-1.1); non-pins → `unsupported` + warn (FR-1.2)
- [x] `cache.py`: SQLite keyed by artifact sha256 + scanner + model + config; skip writes on fork PRs (FR-1.3)
- [x] `report.py`: job summary table with `allow` rows collapsed (FR-6.1); gzip JSON artifact always, traces only on non-allow, 5 MB cap (FR-6.3)
- [x] Exit codes 0/2/3 and `--fail-on-warn` (FR-7.4); `action/action.yml` composite action with explicit exit-code → outcome mapping and a test per mapping (FR-6.2, FR-6.6)
- [x] Same-repo PR comment, skipped silently on fork PRs (FR-6.4, P1)
- [ ] Demo repo with PRs: planted package, benign bump, unpinned spec, forced timeout, forced download failure (Track C) — `demo/` (planted wheels, template, `make_prs.sh`) done and dry-run locally; repo push pending (author)
- [x] README warning about `continue-on-error`

Done when: the planted-package PR fails with ≥ 2 reasons; forced error and timeout fail; benign bump passes; mapping tests green.

## Phase 5 — Docs, demo, buffer (week 10, ~16 h)

Goal: a repo a reviewer understands in two minutes and a build that is green from a fresh clone.

- [ ] README: problem, 30-second demo GIF (`vhs` or `asciinema` + `agg`), architecture diagram (Mermaid), how to run, evaluation summary with CIs, known limitations verbatim from the PRD
- [x] `docs/COSTS.md` complete: ₹0 per phase, free tiers touched
- [ ] Fresh clone check: `uv sync` then `uv run pytest` with network disabled passes; one CI job does exactly this — `offline` CI job written (`unshare --net`); passes locally offline-by-guard; not yet run on GitHub
- [x] Clean docstrings; `pyright` clean; coverage ≥ 80% on `static.py`, `scoring.py`, `trace.py`, exit-code mapping — measured 2026-11-03: static 97%, scoring 100%, trace 99%, report (exit codes) 100%
- [ ] Tag `v0.1.0`

## Deferred to v2 (do not build in v1)

- `docker network create --internal` + DNS/TCP sinkhole capturing payload prefixes (FR-4.4 P2)
- gVisor runtime; eBPF tracer behind a tracer interface; Python audit hooks (FR-4.8, FR-4.9)
- GuardDog rules evaluated separately (FR-3.8)
- Lockfiles (`uv.lock`, `poetry.lock`), extras and markers (FR-1.4, FR-1.5)
- Static version-diff reasons (FR-2.6, FR-5.7)
- FastAPI service with shared cache (FR-8); Hugging Face Spaces only if a live URL is ever wanted
- Transitive dependencies; other ecosystems

## Cut (not coming back without a new PRD)

- Fine-tuned code model (FR-5.6)
- SARIF output (FR-6.5)
- Declared-vs-imported mismatch (FR-3.9)
- Oracle Cloud (requires a card)
