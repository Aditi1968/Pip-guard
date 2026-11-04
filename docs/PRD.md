# pip guard — Product Requirements Document

Nov 2, 2026 · Aditi Vadmal

## Overview

pip guard is a CI gate that judges a Python dependency by what it does, not only by whether it is already known to be bad. When a pull request adds or changes a pinned direct dependency, pip guard downloads the exact artifact, analyses it statically, installs and imports it in a disposable, network-less container while tracing its system calls, scores the evidence, and fails the GitHub check with readable reasons when the package looks malicious.

**Problem.** Anyone can publish to PyPI, and installed code runs with the full trust of the project: files, credentials, network. Attackers exploit this with typosquats (`requets` for `requests`), hijacked releases of abandoned packages, and packages that behave normally but exfiltrate secrets during installation or on first import. Existing scanners (pip-audit, Dependabot, Snyk) match names and versions against databases of reported incidents, so the first victims of any new attack are unprotected.

**One-line pitch.** Airport security for the code your project downloads: a sandboxed behavioural check on every new dependency, running inside GitHub Actions, built entirely on free tooling.

**Owner and status.** Personal portfolio project by Aditi Vadmal. Version 1 target: an exact-artifact scanner that statically analyses PyPI packages, demonstrates controlled behavioural tracing on fixtures and PR-proposed packages, fails a GitHub check on a planted malicious package in a demo repository, and publishes an evaluation with provenance and confidence intervals. Budget: ₹0 / $0, about 118 hours over 10 weeks.

**Revision 0.3 (4 Nov 2026).** Added FR-4.12 and the matching known limitation: wheels with native extensions are `incomplete` in the `noexec` sandbox and fail the check.

**Revision 0.2 (2 Nov 2026).** Incorporates two independent senior engineering reviews. Scope was cut to fit the hour budget; sandbox, tracing and CI claims were narrowed to what the chosen tools can actually observe and enforce; several internal contradictions were resolved. Every verdict now carries a coverage state so a clean result is never confused with an unexamined one.

**Related documents.** `docs/DESIGN.md` (architecture detail) and `docs/PLAN.md` (phase checklist) live in the repository and are updated from this PRD, which is the source of truth for scope and requirements.

## Goals, non-goals and success criteria

Version 1 is done when a planted malicious package in a demo PR fails the check with readable reasons, the behavioural fixture suite passes deterministically, and the static classifier's numbers are published with provenance, counts and confidence intervals.

**Goals (v1)**

1. Detect suspicious behaviour in a new or changed pinned direct PyPI dependency before it enters a project, including attacks with no prior CVE or report.
2. Explain every verdict with observable evidence a developer can act on ("attempted a TCP connection to 185.x.x.x:443 during `pip install`", "opened `~/.aws/credentials` then spawned `curl`"), never with claims the tooling cannot support.
3. Run entirely inside GitHub Actions on a public repository with no hosted service.
4. Finish an uncached scan of one typical package in under 3 minutes of CI time.
5. Publish an evaluation that states exactly what was measured on which population: static classification on archived real-world samples, behavioural detection on a fixture suite, end-to-end on demo PRs.
6. Never fail open: a scanner error, timeout or incomplete analysis fails the check.
7. Cost ₹0 to build, run and demo.

**Non-goals (v1)**

- Replacing CVE-based scanners; pip guard complements them.
- Executing archived real-world malware dynamically. The sandbox runs only on pip guard's own fixtures and on packages a PR actually proposes; the malicious corpus is analysed statically.
- A hardened, escape-proof sandbox. The container is a monitoring tool for CI with strong defaults, not a production security boundary.
- Building source distributions. sdists are inspected statically; PEP 517 build-backend behaviour is reported as not exercised.
- Transitive dependencies, unpinned specs, lockfile parsing (deferred).
- Commenting on pull requests from forks (token is read-only there); the job summary and check status are the product.
- A hosted service, billing or user accounts (deferred to v2).
- Ecosystems other than PyPI.
- Detecting behaviour that triggers only on specific inputs, timers or environment checks.

**Success criteria**

| Criterion | Target | How it is measured |
| --- | --- | --- |
| Demo PR blocked | Planted bad package fails the check with ≥ 2 observable reasons in the job summary | Manual run on the demo repo, recorded as a GIF |
| Fail-closed behaviour | Forced scanner error, timeout and incomplete trace each fail the check | Integration tests in the Action |
| Behavioural fixture suite | Every fixture's expected observation is detected; no benign counterexample fixture is flagged | Deterministic `pytest` suite with Docker marker |
| Static classifier, real-world corpus | Recall at per-band FPR ≤ 0.05; research target ≥ 0.80, reported with counts and 95% CI | `docs/EVAL.md`, package- and campaign-grouped split |
| Blocking-rule precision | ≥ 0.95 on the stratified benign sample | Same evaluation; rules evaluated alone |
| Scan time per package (p50) | ≤ 3 min uncached on `ubuntu-latest`; ≤ 10 s on cache hit | Timings logged by the Action |
| Reproducibility | After `uv sync`, `uv run pytest` passes with network disabled, from a fresh clone | CI badge; one offline CI job |
| Spend | ₹0 | `docs/COSTS.md`; no paid plan, card-gated tier or API key at any point |
| Explainability and coverage | Every `warn`/`block` has ≥ 1 reason; every verdict names which stages completed | Unit tests on `Verdict` |

The recall figure is a research target for a defined population, not a hard acceptance gate: with a few hundred independent malicious samples the confidence interval will be wide, and the report says so.

## Users and use cases

The primary user is a developer on a small team who wants a dependency check that runs in CI with zero setup beyond adding one workflow file.

**Personas**

| Persona | What they need | How pip guard serves them |
| --- | --- | --- |
| Solo developer / small OSS maintainer | Protection from typosquats and hijacked packages without a paid security product | Add the Action; read the job summary and check status |
| Security-minded engineer on a small team | Evidence and coverage, not a black-box score | Observable reasons on every verdict, stage-completion state, downloadable report |
| Hiring manager / interviewer (secondary) | Understand the project in two minutes | README demo GIF, architecture diagram, evaluation numbers with their limits |

**Use cases**

1. A PR adds `requets==2.31.0`. pip guard reports a typosquat distance of 1 to `requests`, observes a `connect()` attempt during install, and fails the check with both reasons.
2. A PR bumps `somelib` from 1.4.2 to 1.4.3. Static analysis finds a new `cmdclass` install hook in the sdist that 1.4.2 did not have; the wheel install shows no behaviour. Verdict: `warn`, with the coverage note that sdist build behaviour was not exercised.
3. A PR adds `numpy==2.1.0`. The artifact hash matches a cached verdict from a previous scan with the same scanner and model version: `allow` in under 10 seconds.
4. A developer runs `pipguard scan requests==2.31.0` locally before opening a PR and reads the JSON report, including which stages completed.
5. A maintainer allowlists a package that legitimately spawns subprocesses on import via `pipguard.toml`; pip guard still reports the observation but does not block on it, and the override is named in the summary.
6. The PyPI download fails or the sandbox times out. The verdict is `error` or `incomplete`, the check fails, and the summary says why.

**End-to-end flow**

1. A developer opens a PR that changes `requirements.txt` or `pyproject.toml`.
2. The Action (running under a read-only `GITHUB_TOKEN`) diffs the pinned direct dependencies between base and head.
3. For each added or changed spec, it looks up the cache by artifact hash, scanner version, model version and config hash.
4. On a miss: download the wheel for the runner's platform (and the sdist for static inspection), verify hashes, extract safely, run static analysis, preinstall declared dependencies untraced, then install the target with `--no-deps` and import it under `strace` in a container with no network, score the result, store the verdict.
5. The Action writes a job summary with a verdict table and reasons, uploads a compressed report artifact, and on same-repository PRs also posts or updates one comment.
6. `block` and `error`/`incomplete` fail the check; `warn` passes with a visible warning; `allow` passes silently.

## Functional requirements

Each requirement has an ID so it can be referenced from issues, tests and the plan. Priority: P0 = must ship in v1, P1 = should ship in v1 if the hour budget allows, P2 = deferred past v1. Cut = removed from the project.

**FR-1 Dependency diff (Action layer)**

| ID | Requirement | Priority |
| --- | --- | --- |
| FR-1.1 | Detect added or changed **exactly pinned** (`==`) direct dependencies between the PR base and head in `requirements.txt` and PEP 621 `pyproject.toml` `[project.dependencies]`. A dependency counts as changed when its name or pinned version differs | P0 |
| FR-1.2 | Any spec that is not an exact pin (`>=`, `~=`, unpinned, URL, path) is reported as `unsupported` with a `warn` verdict and a reason; no resolution is attempted | P0 |
| FR-1.3 | Cache verdicts keyed by (artifact SHA-256, scanner version, model version, config hash). A hit skips all stages. Cache writes are skipped on fork PRs; the cache is best-effort, never load-bearing | P0 |
| FR-1.4 | Extras and environment markers: strip and scan the base package; record that extras were ignored | P2 |
| FR-1.5 | `uv.lock`, `poetry.lock`, Poetry `pyproject.toml` tables and `requirements*.txt` globs | P2 |

**FR-2 Fetch and extract**

| ID | Requirement | Priority |
| --- | --- | --- |
| FR-2.1 | Resolve `name==version` via the PyPI JSON API. Download the wheel matching the runner's Python and platform for dynamic analysis, and the sdist (if published) for static inspection. Record for each artifact: filename, type, SHA-256, Python/platform tags | P0 |
| FR-2.2 | Verify every download against the SHA-256 published by PyPI; a mismatch produces an `error` verdict | P0 |
| FR-2.3 | **Safe extraction**: reject entries whose resolved path leaves the extraction directory, symlinks and hardlinks, and any archive exceeding 100 MB compressed, 500 MB extracted or 20,000 files; never execute anything during extraction; tests include traversal, link and zip-bomb fixtures | P0 |
| FR-2.4 | Collect metadata: release date, version count, maintainer count (reported as missing when unavailable), days since this version, days since first release, project URLs | P0 |
| FR-2.5 | Resolve the target's **declared dependencies** from wheel metadata and download their wheels, so the sandbox can preinstall them untraced (see FR-4.1) | P0 |
| FR-2.6 | Fetch the previous version when the PR is a bump, for a static-only diff of indicators | P2 |

**FR-3 Static analysis**

| ID | Requirement | Priority |
| --- | --- | --- |
| FR-3.1 | Parse all `.py` files with the `ast` module; record syntax errors as a feature rather than failing | P0 |
| FR-3.2 | Install-time **indicators**, reported as present or absent, never as executed: `setup.py` with custom `cmdclass` or overridden `install`/`develop`/`egg_info`; `.pth` files containing `import` lines; a PEP 517 build backend in `pyproject.toml` (sdist only) | P0 |
| FR-3.3 | **Suspicious indicator** counts (renamed from "dangerous calls"; legitimate code uses all of these): `exec`, `eval`, `compile`, `__import__` / `importlib.import_module` with non-literal arguments, `base64.b64decode`, `zlib.decompress`, `marshal.loads`, `pickle.loads`, `ctypes` | P0 |
| FR-3.4 | High-entropy string literals: Shannon entropy ≥ 4.5 bits/char over ≥ 40 characters | P0 |
| FR-3.5 | Extract URLs, IPv4/IPv6 literals and domain-like strings; flag raw IPs and known URL shorteners | P0 |
| FR-3.6 | Typosquat score: PEP 503-normalise names; Damerau-Levenshtein distance (via `rapidfuzz`) to a **frozen, dated snapshot** of the top 5,000 PyPI names, excluding the package itself. Indicator fires at distance ≤ 1 to a top-500 name or ≤ 2 to a top-100 name; thresholds are re-tuned on validation data | P0 |
| FR-3.7 | Flag network, subprocess, filesystem and environment-access imports in module top level or install-hook code | P0 |
| FR-3.8 | GuardDog Semgrep rules as an additional signal, evaluated **separately** from the main model because much of the Datadog corpus was discovered with GuardDog | P2 |
| FR-3.9 | Declared-vs-imported dependency mismatch | Cut |

**FR-4 Sandbox**

| ID | Requirement | Priority |
| --- | --- | --- |
| FR-4.1 | Two-step install: preinstall the target's declared dependencies **untraced**, then install the target wheel with `--no-deps` and import it, both traced. Behaviour is attributed to the target only. Modules to import come from the wheel's `top_level.txt` / `RECORD`; a package with no importable module, or an import that fails, is recorded as `incomplete` with the reason | P0 |
| FR-4.2 | All installs are offline from local wheels (`--no-index --find-links`); the container has no network, so any `connect()` is itself a signal | P0 |
| FR-4.3 | Seed **fake credential files**, not environment variables: `~/.aws/credentials`, `~/.ssh/id_rsa`, `~/.netrc`, `.env`, with realistic formats and invalid values. The word "fake" appears in a manifest, never in the values. Opening these files is observable via `openat` | P0 |
| FR-4.4 | `--network none`. Connection attempts are observed as `connect()` syscalls with destination IP and port. DNS names are **not** observable in v1. A `docker network create --internal` sinkhole with a DNS responder that captures payload prefixes is deferred | P2 |
| FR-4.5 | Trace schema (`BehaviorTrace`): files opened for write outside the allowed directories; files opened for read among the seeded credential files; subprocesses with argv; `connect()` attempts (family, address, port); exit codes; per-step wall time; completeness state. Environment-variable reads are **not** in the schema (not observable with strace) | P0 |
| FR-4.6 | Hard timeouts: 90 s install, 60 s import. A timeout kills the container's process tree and sets completeness to `incomplete:timeout` | P0 |
| FR-4.7 | Container hardening: non-root user; read-only root filesystem with tmpfs mounted at `/tmp`, `/sandbox/site-packages` and the pip cache dir; `--cap-drop ALL`; `--security-opt no-new-privileges`; Docker's default seccomp profile (strace must work under it: verified by the week-1 spike); `--memory 1g`; `--pids-limit 256`; no bind mounts; no Docker socket | P0 |
| FR-4.8 | Pluggable tracer interface (eBPF / Tetragon) | P2 |
| FR-4.9 | gVisor (`runsc`) runtime, once the spike shows strace works under it on `ubuntu-latest` | P2 |
| FR-4.10 | Dynamic analysis runs **only** on pip guard's own fixture packages and on packages a PR actually proposes. Archived real-world malware is never executed | P0 |
| FR-4.11 | strace output is **attacker-influenced**: parse defensively, cap every field length, escape before rendering, and fuzz-test the parser | P0 |
| FR-4.12 | Wheels containing native extensions (`.so`, `.pyd`, `.dylib`) cannot load in the `noexec` sandbox: they return `incomplete` with a reason naming the extension and fail the check. Isolation is never relaxed to run them | P0 |

**FR-5 Scoring**

| ID | Requirement | Priority |
| --- | --- | --- |
| FR-5.1 | Two rule classes in `rules.yaml`. **Blocking rules** (≥ 0.95 precision on the stratified benign sample) force `block`: e.g. `connect()` during install; credential file read followed by a subprocess or `connect()`; typosquat ≤ 1 to a top-100 name. **Warning rules** force at least `warn`: e.g. install hook present in sdist; raw IP literal in source | P0 |
| FR-5.2 | Model ladder, each step adopted only if it beats the previous on held-out data: rules alone → regularised logistic regression (scikit-learn) → LightGBM. All operate on tabular static (+ behavioural where available) features | P0 |
| FR-5.3 | `Verdict` = `level` ∈ {allow, warn, block, error, incomplete}, `score` ∈ \[0,1\] (labelled "calibrated probability" only if calibration is applied, else "score"), `reasons: list[str]`, `coverage` (which stages completed and on which artifact), `overrides` applied | P0 |
| FR-5.4 | Every `warn`/`block` carries ≥ 1 reason tied to an observation or indicator; a blocking-rule hit always yields `block`; a warning-rule hit never yields `allow` | P0 |
| FR-5.5 | Per-instance explanations: coefficient contributions for logistic regression; SHAP for LightGBM if adopted. Rendered through fixed reason templates per feature | P1 |
| FR-5.6 | Fine-tuned code model | Cut |
| FR-5.7 | Version-diff reasons ("new in 1.4.3: install hook") from static indicators | P2 |
| FR-5.8 | `warn`/`block` thresholds are chosen on validation data at the FPR target and stored with the model artifact; the 0.5/0.85 defaults are placeholders until then | P0 |

**FR-6 Reporting and CI integration**

| ID | Requirement | Priority |
| --- | --- | --- |
| FR-6.1 | GitHub Actions **job summary** with a verdict table (package, artifact, verdict, coverage, top reasons); `allow` rows collapsed | P0 |
| FR-6.2 | Check outcome: `block`, `error` and `incomplete` **fail** the job; `warn` and `allow` pass. The README warns that `continue-on-error: true` on the step defeats enforcement | P0 |
| FR-6.3 | Upload a gzip-compressed JSON report as a workflow artifact always; include raw traces only for `warn`/`block`/`error`/`incomplete`, capped at 5 MB per package | P0 |
| FR-6.4 | On same-repository PRs, post or update one PR comment mirroring the summary. On fork PRs (read-only token) skip silently and say so in the summary | P1 |
| FR-6.5 | SARIF output | Cut |
| FR-6.6 | The composite Action maps CLI exit codes to job outcomes explicitly and has a test for each mapping | P0 |

**FR-7 CLI and configuration**

| ID | Requirement | Priority |
| --- | --- | --- |
| FR-7.1 | `pipguard scan <name==version>` prints JSON; `--pretty` for a human table; `--no-sandbox` for static only; `--artifact <path>` to scan a local wheel | P0 |
| FR-7.2 | `pipguard.toml`: thresholds, timeouts, watched files, and an **allowlist** whose semantics are: the package is still fully scanned and reported, but its verdict is capped at `warn`; every applied override is named in the summary | P0 |
| FR-7.3 | `pipguard explain <spec>` prints the full trace, feature values and rule evaluations | P1 |
| FR-7.4 | Exit codes: 0 `allow` or `warn`, 2 `block`, 3 `error`/`incomplete`; `--fail-on-warn` makes `warn` exit 1 | P0 |

**FR-8 Hosted service**

Deferred to v2 in its entirety (FR-8.1 `POST /scan`, FR-8.2 shared cache, FR-8.3 metrics). It contradicts the v1 non-goals and Goal 3, and the Action-native mode covers the use case.

## Non-functional requirements

The scanner must be safe to run on untrusted code, must never fail open, must be fast enough for PR feedback, and must be free to operate.

| Area | Requirement |
| --- | --- |
| Security: what executes where | Downloaded package code executes only inside the sandbox container, and only for pip guard's own fixtures and PR-proposed packages (FR-4.10). Extraction, static analysis and parsing never execute package code. Archived real-world malware is handled as data on disk, never run. |
| Security: container | Non-root; read-only root FS with named tmpfs mounts; `--cap-drop ALL`; `no-new-privileges`; default seccomp; `--network none`; 1 GB memory; 256 PIDs; no bind mounts; no Docker socket. Fake credentials use realistic formats with invalid values; the "fake" marker lives in a manifest, not in the values, so sandbox-aware code cannot trivially spot them and a leaked value harms no one. |
| Security: CI trust model | The workflow runs on `pull_request` with `permissions: contents: read` (plus `pull-requests: write` only for the same-repo comment job). `pull_request_target` is never used. The Action is pinned to a commit SHA in consuming repos. Restored caches, downloaded artifacts and strace output are treated as untrusted input. Secrets are never passed into the sandbox. |
| Security: pip guard's own supply chain | All dependencies pinned with hashes in `uv.lock`; Dependabot enabled; sandbox image built from a pinned base digest and published to GHCR with its digest recorded. |
| Reliability: fail closed | A scanner crash, download failure, hash mismatch, timeout or failed import produces `error` or `incomplete` and **fails the check**. A neutral or passing outcome is never produced for an unexamined package. External calls (PyPI) retry with backoff, then fail closed. |
| Performance | p50 ≤ 3 min and p95 ≤ 6 min per uncached package on `ubuntu-latest`; cache hits ≤ 10 s. Install and import have hard timeouts (FR-4.6). Trace files capped at 5 MB per package before parsing. |
| Reproducibility | After a documented `uv sync`, `uv run pytest` passes with network disabled, using fixture packages; one CI job runs exactly this. The model artifact, its training manifest and chosen thresholds are versioned together. |
| Explainability and coverage | Every `warn`/`block` has a human-readable reason tied to an observation or indicator. Every verdict states which stages completed, on which artifact (filename and hash), and what was not evaluated (e.g. sdist build behaviour, DNS names, environment reads). |
| Cost | ₹0 at every stage; no card-gated free tier. See the zero-cost section. |
| Privacy | In Action-native mode pip guard contacts only PyPI (downloads) and GitHub (summary, artifact, optional comment). No telemetry. |
| Portability | Linux with Docker (CI and development); macOS via Docker Desktop or Colima; Windows via WSL2. |
| Observability | Standard-library `logging` with a JSON formatter and a per-scan correlation ID; per-stage timings in the report. No metrics endpoint in v1. |
| Maintainability | Type hints throughout, `ruff` and `pyright` clean, ≥ 80% line coverage on `static.py`, `scoring.py`, the trace parser and the Action's exit-code mapping. One module per stage with a versioned pydantic contract between them. |
| Licensing and data terms | Apache-2.0 for pip guard. Only permissive-licence dependencies. The Datadog dataset's terms are checked before any derived model or per-sample numbers are published; OpenSSF data under its published licence; no redistribution of malware samples. |

## Tech stack

Python is the right primary language on merit: the target ecosystem is Python, static analysis needs Python's own `ast`, and the ML tooling is Python-native. The non-Python pieces (Docker, strace, GitHub Actions YAML) are each a thin, well-documented layer. The v1 stack is deliberately smaller than the first draft: one runtime, one tracer, no network layer, no service.

| Layer | v1 choice | Why this, and what was rejected | Deferred (v2) | Cost |
| --- | --- | --- | --- | --- |
| Language | Python 3.12 | PyPI is the target; `ast`; ML libraries native. Go/Rust would mean re-implementing Python parsing and losing the ML stack. | — | Free |
| Package / env management | `uv` | Fast, hash-pinned lockfile, replaces pip + venv + pip-tools. | — | Free |
| CLI | `typer` | Type-hint driven, minimal boilerplate. | — | Free |
| Data contracts | `pydantic` v2 | Validation and JSON schema for `PackageSpec`, `Artifact`, `StaticFeatures`, `BehaviorTrace`, `Verdict`; shared by CLI and Action. | — | Free |
| Archive handling | stdlib `zipfile`/`tarfile` wrapped in a safe-extraction module | Explicit path, link, size and count checks; `tarfile`'s `filter='data'` where available. No third-party extractor. | — | Free |
| Static analysis | Python `ast` + `rapidfuzz` | Exact and dependency-free; `rapidfuzz` for Damerau-Levenshtein. Regex-only scanners miss obfuscation. | GuardDog Semgrep rules, evaluated separately (dataset circularity) | Free |
| Sandbox runtime | Docker with `runc`, default seccomp, hardened flags (FR-4.7) | Installed on GitHub-hosted runners and every dev machine. One runtime, verified by a week-1 spike that strace works under it. | gVisor (`runsc`) once compatibility with tracing is shown | Free |
| Behaviour tracing | `strace -f -e trace=network,process,file` inside the container | Works without kernel privileges on the chosen runtime; narrow filter keeps traces small. Cannot see env reads or DNS names, and the schema says so. | eBPF (Tetragon) behind a tracer interface; Python audit hooks as a supplement | Free |
| Network | `--network none` | Simplest provable isolation; `connect()` attempts still visible with destination. | `docker network create --internal` + DNS/TCP sinkhole capturing payload prefixes | Free |
| Scoring: rules | Pure Python over a `rules.yaml` with blocking and warning classes | Testable, explainable, no dependency. | — | Free |
| Scoring: model | Ladder: rules → scikit-learn logistic regression → LightGBM, each adopted only if it wins on held-out data | Tabular features, a few thousand rows: start interpretable, escalate on evidence. A neural model was never the right baseline here. | — | Free |
| Explanations | Coefficient contributions (LR); SHAP (LightGBM, if adopted) | Rendered through fixed reason templates. | — | Free |
| Experiment tracking | Committed CSV/JSON summary tables and the dataset manifest | Sufficient at this scale; MLflow dropped. | — | Free |
| Datasets | Datadog malicious-software-packages-dataset (primary archive); fetchable subset of OpenSSF malicious-packages; `hugovk/top-pypi-packages` snapshot; PyPI JSON API | Datadog is the only source that still holds the artifacts; many OpenSSF entries are yanked from PyPI and are counted, not used. | deps.dev API for extra metadata | Free |
| Cache | SQLite file (stdlib `sqlite3`), keyed by artifact hash + scanner + model + config | Zero infrastructure; GitHub Actions cache carries the file between runs, best-effort. | Shared cache behind the v2 service | Free |
| Service | None in v1 | Action-native mode is the product. | FastAPI + `uvicorn`; Hugging Face Spaces (Docker Space, no card) if a live URL is ever wanted | Free |
| CI/CD | GitHub Actions on a **public** repository | Unlimited free minutes for public repos; Docker preinstalled; read-only `GITHUB_TOKEN` suffices for summary + check status. | — | Free |
| Action packaging | Composite action (`action.yml`) calling the CLI, with explicit exit-code mapping | Simplest to publish and test. | — | Free |
| Quality | `pytest` + `pytest-cov`, `ruff`, `pyright`, `pre-commit`, `hypothesis` for parser fuzzing | Standard, fast, free. | — | Free |
| Logging | stdlib `logging` + JSON formatter | Enough at this scale; `structlog` optional. | — | Free |
| Docs & demo | Markdown + Mermaid; `vhs` or `asciinema` + `agg` for the GIF | Renders on GitHub. | — | Free |
| Dev environment | VS Code + Claude Code; Docker Desktop (personal use) / Colima / WSL2 | Already in use. | — | Free |

**Alternatives explicitly rejected**

- A host-side sinkhole in v1: a full networking subsystem (routing, DNS, TLS) competing with the scanner for time.
- Fine-tuning a code model: no evidence it would beat a tabular baseline on this data; heavy dependencies; GPU quota uncertainty.
- gVisor as a v1 requirement: valuable, but its interaction with strace and GitHub runners is unverified.
- A hosted service in v1: deployment, auth and abuse concerns for no v1 benefit; contradicts the Action-native goal.
- Oracle Cloud always-free: requires a card to activate, which violates the project's own zero-cost rule.
- Running untrusted code in a subprocess or `venv` on the host: no isolation.
- Kubernetes for the sandbox: over-scoped for one container per scan.

## Architecture and deployment modes

The scanner is one Python package with a versioned contract between four stages; the Action and the CLI are thin shells around it, and there is no service in v1.

_(Architecture diagram: see the "Architecture" section of docs/DESIGN.md for the ASCII version.)_

The Action diffs the PR's pinned direct dependencies and consults the cache by artifact hash; a miss runs Fetch → Static → Sandbox → Scoring, stores the verdict, and the result lands on the PR as a job summary, a passed or failed check, and a compressed report artifact. Every verdict carries the artifact it examined and which stages completed.

**Deployment modes**

| Mode | What runs where | When to use | Status |
| --- | --- | --- | --- |
| Action-native | Everything runs on the GitHub-hosted runner for the PR under a read-only token; the SQLite cache file travels in GitHub Actions cache, best-effort | Any public repo; zero infrastructure | v1 default |
| Local CLI | `pipguard scan` on the developer's machine with Docker | Pre-PR checks, debugging, developing pip guard itself, running the evaluation | v1 |
| Hosted service | FastAPI + shared cache; Action calls `POST /scan` | Many repos sharing scans; a live demo URL | v2, deferred |

**Stage contracts** (pydantic models in `models.py`, each with `schema_version`)

- `PackageSpec` (name, exact version) → `fetch.fetch(spec) -> FetchedPackage` (list of `Artifact`: filename, type wheel/sdist, SHA-256, tags, extraction path; metadata; declared dependencies with their wheels)
- `FetchedPackage` → `static.analyze(pkg) -> StaticFeatures` (per artifact, with indicator presence flags and the typosquat snapshot date)
- `FetchedPackage` → `sandbox.run(pkg) -> BehaviorTrace` (target wheel only, `--no-deps`; completeness ∈ {complete, incomplete:timeout, incomplete:import\_failed, incomplete:no\_importable\_module, skipped:policy})
- `(StaticFeatures, BehaviorTrace | None, metadata)` → `scoring.score(...) -> Verdict` (level, score, reasons, coverage, overrides, model\_version, thresholds)
- `Verdict` → `report.render(...)` for the job summary (Markdown), the artifact (JSON) and the optional PR comment

Cached verdicts from a different scanner, model or config version are invalidated rather than trusted; a cached behavioural result is reused only for the identical artifact hash and runtime image digest.

## Data, ML and evaluation

The evaluation runs on three separate tracks so that no number is claimed for a population it was not measured on: static classification on archived real-world samples, behavioural detection on a fixture suite, and end-to-end checks on demo PRs.

**Data sources**

| Source | Role | Notes |
| --- | --- | --- |
| [Datadog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) | Primary malicious corpus: the only source that still holds the artifacts (encrypted archives) | Most samples were discovered with GuardDog; GuardDog is therefore not a feature in the main model. Terms checked before publishing derived numbers |
| [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) | Secondary malicious list (OSV reports) | Many entries are yanked from PyPI. Only still-fetchable artifacts are used; the fetchable count is reported |
| [hugovk/top-pypi-packages](https://github.com/hugovk/top-pypi-packages) | Benign sampling frame and the frozen typosquat target list | Snapshot date recorded in the manifest |
| PyPI JSON API | Metadata, hashes, download URLs | Polite rate limiting; responses cached locally |
| `tests/fixtures/` | Deterministic unit tests, the behavioural fixture suite and the demo's planted package | \~10 suspicious fixtures, each with a benign counterexample |

**Labelling and splitting**

- Malicious = present in the Datadog archive or a fetchable OpenSSF report. Near-identical payloads are deduplicated by a hash of normalised source, and samples from the same campaign are grouped so that a group lands in exactly one split.
- Benign = sampled from the frozen top-5,000 snapshot, **stratified** across popularity bands (top 100; 101–1,000; 1,001–5,000) plus a random band of packages outside the top 5,000, and absent from both malicious sets. Fifty benign samples are manually reviewed; "not known to be malicious" is a weak label and the report says so.
- Split by package name **and** campaign group, never by version. 5-fold grouped cross-validation for model selection; one frozen held-out fold for the reported numbers.
- `data/manifest.csv` (committed) records name, version, artifact filename, SHA-256, label, source, campaign group, popularity band and split. Raw samples are never committed.

**Feature set (v1)**

- Static: install-time indicator flags (present/absent), suspicious-indicator counts, max string entropy, URL/IP counts, typosquat distance and target rank, days since release, version count, maintainer count (with missing flag), package size, file count, compiled extensions present, artifact type.
- Behavioural (fixtures and PR-proposed packages only): `connect()` attempts (count, during install vs import), credential-file reads, subprocess count and whether any argv contains `curl`/`wget`/`sh`/`bash`/`powershell`, writes outside allowed dirs, timeout or import failure.
- Derived: interaction flags such as `credential_read AND (connect OR subprocess)`.

**Model ladder**

1. **Rules alone**, in two classes (blocking, warning). Precision and recall measured on their own.
2. **Regularised logistic regression** (scikit-learn) on the static features; coefficients inspected; calibrated with Platt scaling on the validation fold or the output is labelled "score".
3. **LightGBM** with class weighting, adopted only if it improves recall at the FPR target by ≥ 3 points on the held-out fold. SHAP explanations if adopted.

**Evaluation tracks**

| Track | Population | What is measured | Targets |
| --- | --- | --- | --- |
| A. Static classification | Held-out fold of the real-world corpus (static features only) | Recall at per-band FPR ≤ 0.05, with counts and 95% Wilson CIs; PR-AUC; calibration curve; blocking-rule precision; ablations: rules only vs rules + LR vs rules + LightGBM | Recall ≥ 0.80 (research target) |
| B. Behavioural detection | Fixture suite: each suspicious fixture paired with a benign counterexample using the same API legitimately | Every expected observation detected; no counterexample flagged; parser fuzz tests pass | 100% deterministic |
| C. End-to-end | Demo repository PRs: planted package, benign bump, unpinned spec, forced timeout, forced download failure | Correct verdict and check outcome; p50/p95 timing; fail-closed on every error case | All cases pass |

Behavioural features are **not** claimed to improve Track A, because Track A samples are never executed. The README states this plainly.

**Compute plan**

Static analysis takes roughly 5–15 s per package on a laptop, so a corpus of \~3,000 benign plus the malicious set runs in under a day locally, in batches, with results appended to the manifest. Nothing in the evaluation runs in CI. The model trains in minutes on CPU.

**Thresholds and lifecycle**

`warn`/`block` thresholds are chosen on the validation fold at the FPR target and stored with the model artifact; the 0.5/0.85 defaults are placeholders until then. The model artifact, thresholds, training manifest and snapshot dates are versioned together (`model_version` in every verdict). Retraining is manual when the corpus is refreshed.

## Zero-cost constraint

The project must cost ₹0 from first commit to final demo; every tool is open source or on a free tier that needs no card on file, and the design avoids anything that only works when paid.

**Hard rule.** No paid plan, no API key with a billing account, no cloud resource that can accrue charges, and no free tier that requires a credit card to activate. Oracle Cloud's always-free tier fails that last test and is not used.

**What is free and why it stays free**

| Need | Free option used | Limit to respect | Fallback |
| --- | --- | --- | --- |
| CI minutes, Docker on runners | GitHub Actions on a **public** repo | Unlimited minutes for public repos; 6-hour job limit | Keep the repo public; pull the sandbox image from GHCR rather than rebuilding |
| Code hosting, check status, artifacts | GitHub free account, read-only `GITHUB_TOKEN` | 500 MB artifact storage, 90-day retention | Compressed reports always; traces only on `warn`/`block`/`error`, capped at 5 MB |
| Container runtime locally | Docker Desktop (free for personal use), Colima or Podman | Docker Desktop free only for individuals and small companies | Podman is fully open source |
| Sandbox image hosting | GitHub Container Registry | Free for public images | Build in the workflow |
| Static analysis, rules, parser fuzzing | stdlib `ast`, `rapidfuzz`, `hypothesis` | None | — |
| Training and evaluation | Local CPU; scikit-learn, LightGBM | Hours on a laptop for the static corpus | Smaller benign sample |
| Experiment records | Committed CSV/JSON tables | None | — |
| Datasets | Public GitHub repos and PyPI API | Datadog terms checked before publishing derived numbers; polite PyPI rate limits | — |
| Model hosting | GitHub Releases | None at this size | Commit the small model file |
| Demo recordings | `vhs`, `asciinema` + `agg` | — | Screen recorder |
| Diagrams and docs | Mermaid in Markdown | — | — |
| Development assistant | Claude Code via the existing Claude subscription | Already paid for other reasons; not a project cost | — |
| v2 only: live service URL | Hugging Face Spaces, Docker Space (no card required) | Sleeps when idle; 2 vCPU | Do not deploy |

**Traps that would quietly cost money or break the free path**

- Making the repository private: Actions minutes become metered. Keep it public.
- Any free trial or always-free tier that asks for a card (Snyk, Socket, Semgrep Cloud, Oracle Cloud, most cloud GPUs). Not used.
- Commercial LLM or security APIs for classification. Not used; the classifier is local.
- Uploading raw strace dumps on every run: a few PRs would exhaust the artifact quota. Compressed and capped (FR-6.3).
- Storing datasets in GitHub (LFS bandwidth is metered). Raw data stays local; only the manifest is committed.
- Running the evaluation corpus in CI. It runs locally; CI runs fixtures only.

**Cost ledger.** `docs/COSTS.md` records, per phase, that no spend occurred and which free tiers were touched. This becomes a README line: "Built and operated for $0."

## Risks, limitations and mitigations

The risks most likely to sink the project are the sandbox eating the schedule and a classifier whose numbers cannot be trusted; both are addressed by a week-1 spike, a thin end-to-end slice, and an evaluation that only claims what it measured.

| Risk | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- |
| strace does not work under Docker's default seccomp/capability settings on `ubuntu-latest` | Medium | High | Half-day spike in week 1. If tracing needs weakened isolation, the dynamic stage is reduced to a fixture demonstration and the static scanner, evaluation and Action are completed instead. Isolation is never loosened to save the feature. |
| Sandbox work balloons and stalls the project | High | High | No network layer, one runtime, one tracer, narrow trace filter; a deliberately-bad fixture defines "done"; 24-hour cap on the phase. |
| Behaviour mis-attributed to the target when dependencies also run code | High | High | Untraced dependency preinstall, then `--no-deps` traced install of the target only (FR-4.1). Dependency behaviour is out of scope and documented. |
| Analysing a wheel misses sdist build-time behaviour | Certain | Medium | Artifact type and coverage are recorded on every verdict; sdist indicators are inspected statically; the summary says build behaviour was not exercised. |
| Scanner fails open through a neutral check, a swallowed exit code or `continue-on-error` | Medium | High | `error`/`incomplete` fail the job; explicit exit-code mapping with tests; README warning about `continue-on-error`. |
| PR comment fails on fork PRs (read-only token) | Certain | Low | Job summary and check status are the product; comment is best-effort on same-repo PRs; `pull_request_target` is never used. |
| Sandbox-aware malware behaves benignly in the container | Medium | Medium | Documented limitation. Fake credentials look real; static indicators still fire on obfuscation; static version-diff (P2) catches new hooks. |
| High false-positive rate on legitimate packages that spawn subprocesses or decode data | Medium | High | Suspicious indicators are warnings, not blocks; blocking rules need ≥ 0.95 measured precision; per-band FPR target; allowlist caps at `warn` while still reporting. |
| Small, biased or leaky dataset | Medium | High | Campaign grouping and payload dedup; stratified benign bands with a manual-review sample; GuardDog excluded from the main model; counts and CIs reported; no generalisation claims beyond the measured population. |
| OpenSSF entries cannot be fetched (yanked) | Certain | Low | Datadog is the primary archive; fetchable count reported. |
| Attacker-controlled strace output breaks or poisons the parser | Medium | Medium | Defensive parsing, field caps, escaping, `hypothesis` fuzz tests (FR-4.11). |
| Artifact quota exhausted by trace uploads | Medium | Low | Compressed reports; traces only on non-`allow`, capped at 5 MB. |
| Scanning time exceeds the 3-minute target | Medium | Medium | Offline installs from pre-downloaded wheels; narrow strace filter; cache by artifact hash; fetch and static in parallel. |
| Free tier changes (Actions policy, Docker Desktop terms) | Low | Low | Every free dependency has a listed fallback; Action-native mode needs nothing beyond GitHub. |
| Legal: dataset terms, handling live malware | Low | Medium | Datadog terms checked before publishing derived numbers; samples stay local and are never executed or redistributed. |
| "Not novel" because Socket, Phylum, GuardDog exist | Certain | Low | Positioned as an open, Action-native scanner with a published, honest evaluation. Novelty is not the goal; a working, measured, defensible system is. |

**Known limitations stated in the README**

- Docker is not a VM; a kernel exploit could escape. Acceptable for a CI scanner analysing PR candidates, not for analysing targeted malware.
- Dynamic results exist only for fixtures and PR-proposed packages; the real-world corpus is evaluated statically.
- Wheels only in the sandbox; sdist build-backend behaviour is not exercised.
- Packages with compiled extensions (`.so`, `.pyd`) are never fully observed: the sandbox's writable mounts are `noexec`, so native code cannot load. Such packages are `incomplete` with a reason naming the extension, and the check fails.
- Environment-variable reads and DNS names are not observable; credential-file reads and `connect()` destinations are.
- Only exactly pinned direct dependencies in `requirements.txt` and `pyproject.toml`.
- Behaviour triggered by specific inputs, timers or environment checks is not observed.
- Verdicts are probabilistic; `warn` exists for a reason and humans still review.

## Milestones and open questions

About 118 hours over ten weeks at 10–12 hours a week, with a week-1 sandbox spike and three gates that are not skipped: the fixture suite passes, the evaluation is published, and the demo PR fails its check.

_(Roadmap: six phases over ten weeks with gates after Sandbox, Scoring and CI; see the Effort budget table below.)_

If the Sandbox phase runs past its cap, the dynamic stage shrinks to a fixture demonstration and the remaining hours go to the static scanner, evaluation and Action, never to loosening isolation. Per-step checklists live in `docs/PLAN.md`.

**Effort budget**

| Phase | Weeks | Hours | Contents |
| --- | --- | --- | --- |
| Foundation + spike | 1 | 10 | Repo, `uv`, CI, fixtures skeleton; **spike: strace under hardened Docker on `ubuntu-latest`** |
| Fetch, safe extraction, static scan | 2–3 | 24 | FR-2, FR-3; static fixtures; typosquat snapshot |
| Sandbox (capped) | 4–5 | 24 | FR-4; `--no-deps` two-step install; trace parser + fuzz tests; fixture suite |
| Rules, model ladder, evaluation | 6–8 | 30 | FR-5; corpus manifest; Tracks A and B; `docs/EVAL.md` |
| CLI + Action | 9 | 14 | FR-1, FR-6, FR-7; exit-code mapping tests; demo repo; Track C |
| Docs, demo, buffer | 10 | 16 | README, GIF, limitations, `docs/COSTS.md`, `v0.1.0` |
| **Total** | 10 | **118** |  |

**Milestone definitions**

| Milestone | Evidence it is done |
| --- | --- |
| M0 Foundation + spike | `uv run pipguard --help` works; CI badge green; spike result recorded in `docs/DESIGN.md` (strace works / does not under the chosen flags) |
| M1 Static scanner | `pipguard scan --no-sandbox requests==2.31.0` prints JSON with artifact identity and indicators; extraction tests (traversal, links, zip bomb) pass |
| M2 Sandbox | Every fixture's expected observation appears in `BehaviorTrace`; benign counterexamples are clean; `--no-deps` attribution verified against a fixture with a noisy dependency; container destroyed after each run |
| M3 Scoring and evaluation | `Verdict` with reasons and coverage; `docs/EVAL.md` with Track A counts, CIs, per-band FPR, rule precision and ablations; thresholds stored with the model |
| M4 Action | Demo-repo PRs: planted package fails the check with ≥ 2 reasons; forced error and timeout fail the check; benign bump passes; exit-code mapping tests green |
| M5 Polish | README with GIF, diagram, numbers and limitations; `docs/COSTS.md` shows ₹0; `v0.1.0` tagged |

**Open questions**

- [ ] Week-1 spike: does `strace -f` work under Docker's default seccomp with `--cap-drop ALL` on `ubuntu-latest`? If not, which single minimal change makes it work, and is that change acceptable?
- [ ] Which Python/platform wheel to pick when several match the runner; what to do when a package publishes only an sdist (static-only verdict with `incomplete:no_wheel`?).
- [ ] Benign sample sizes per band (e.g. 100 / 400 / 1,000 / 500 random) given the static scan time budget.
- [ ] Datadog dataset terms: what exactly may be published about individual samples.
- [ ] Should the allowlist be per package or per (package, rule)?
- [ ] Name check: confirm `pipguard` is not already taken on PyPI and GitHub before publishing.

**References**

- [pip documentation: installing from wheels vs building sdists (PEP 517)](https://pip.pypa.io/en/stable/)
- [GitHub Docs: `GITHUB_TOKEN` permissions and `pull_request_target` risks](https://docs.github.com/en/actions)
- [Docker Docs: seccomp security profiles](https://docs.docker.com/engine/security/seccomp/)
- [Datadog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) · [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages)
- [GuardDog (Datadog)](https://github.com/DataDog/guarddog) · [gVisor](https://gvisor.dev/) · [uv](https://github.com/astral-sh/uv) · [LightGBM](https://github.com/microsoft/LightGBM) · [SHAP](https://github.com/shap/shap)
