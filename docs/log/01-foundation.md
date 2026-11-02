# Build log 01: foundation

Shared contract and infrastructure that every workstream builds on: `models.py`, `features.py`, `config.py`, `log.py`, `errors.py`, the CI workflow, the sandbox image, build-time fake credentials, and the week-1 spike.

Commits: `bf5d51f` (shared contract, CI, image, spike script), `056b9ef` (feature vector and model artifact), `d33a598` (spike result and explicit seccomp profile).

## What was built

| Piece | File | Serves |
| --- | --- | --- |
| Stage contracts | `src/pipguard/models.py` | All stages; PRD "Stage contracts", FR-5.3 |
| One feature vector for training and inference | `src/pipguard/features.py` | FR-5.2, PRD "Feature set (v1)" |
| `pipguard.toml` loader and config hash | `src/pipguard/config.py` | FR-7.2, FR-1.3 (cache key) |
| JSON logging with a correlation ID | `src/pipguard/log.py` | PRD "Observability" |
| Exception hierarchy | `src/pipguard/errors.py` | Fail closed (PRD "Reliability") |
| Scanner version in every cache key | `src/pipguard/__init__.py:5` | FR-1.3 |
| CI: lint, tests, offline tests, Docker job | `.github/workflows/ci.yml` | PRD "Reproducibility", spike on `ubuntu-latest` |
| Sandbox image | `sandbox/sandbox.Dockerfile` | FR-4.7 (image side) |
| Fake credential files, generated at build | `sandbox/seed_credentials.py`, `sandbox/manifest.json` | FR-4.3 |
| Week-1 spike | `sandbox/spike.sh`, `sandbox/seccomp-default.json` | PRD open question 1 |
| Deterministic wheel builder for fixtures | `scripts/make_wheel.py` | Fixtures, spike, demo |

## How it works

### The contract (`models.py`)

Every stage takes and returns a pydantic model: `PackageSpec` → `FetchedPackage` → `StaticFeatures` and `BehaviorTrace` → `Verdict` → `ScanReport`. All models inherit `_Model` with `frozen=True, extra="forbid"` (`models.py:33-35`): a contract is a value, and a misspelt field name is a bug, not data that is silently ignored. Top-level models carry `schema_version` so a cached result from an older contract is rejected (`cache.py:194-202`).

Notable invariants enforced by the models themselves:

- `PackageSpec.parse` accepts only `name==version`; anything else raises (`models.py:66-72`). Name and version are checked by regex and length.
- `Completeness` lists every way a sandbox run can end (`models.py:216-228`); only `complete` counts as complete.
- `BehaviorTrace` has no field for environment reads or DNS names, because strace cannot see them (`models.py:263-282`).
- `Verdict` refuses to exist without a reason when its level is not `allow` (`models.py:389-394`). This is how the PRD success criterion "every warn/block has at least one reason" is enforced by construction rather than by review.
- `Thresholds` refuses `warn > block` (`models.py:326-330`).
- `ModelArtifact` refuses a logistic-regression artifact whose coefficient, mean and scale lists do not match its feature list (`models.py:358-368`).
- `Config.allowlist` is PEP 503-normalised on load, so `Foo_Bar` and `foo-bar` are the same entry (`models.py:436-439`).
- `DependencyChange` must have exactly one of `spec` or `unsupported_reason` (`models.py:415-419`).

### The feature vector (`features.py`)

`vectorize(static, trace)` returns a dict whose keys are exactly `FEATURE_NAMES`, in order (`features.py:156-159`). Training (`scripts/eval/train.py`) and inference (`scoring.py`, `rules.py`) both call it, so they cannot disagree about what a feature means.

- Static features are aggregated over wheel and sdist: `max` for counts that would otherwise be double-counted (the two usually contain the same files), `any` for flags, union size for URL/IP lists (`features.py:80-127`).
- Missing metadata is `0` plus a `*_missing` flag (`features.py:76-77`), never a sentinel like `-1` that a linear model would read as a real number.
- Typosquat distance is clipped at 3 (`TYPOSQUAT_FAR`), which also means "no close name".
- Behavioural features are all zero with `behaviour_available = 0` when there is no trace (`features.py:134-153`), including the PRD's derived interaction flag `credential_read_and_connect_or_subprocess`.

### Config, logging, errors

- `load_config` returns defaults when `pipguard.toml` is absent, accepts the keys either at top level or under `[pipguard]`, and turns malformed TOML or invalid values into `PipGuardError` (`config.py:13-21`). A broken config is an error, not "use defaults".
- `config_hash` is the first 16 hex characters of SHA-256 over the validated config's JSON (`config.py:24-26`), so changing a threshold or the allowlist invalidates cached verdicts.
- Logs go to stderr as one JSON object per line with a per-scan correlation ID from a `ContextVar` (`log.py:19-38`). stdout is reserved for the report.
- `errors.py` defines `PipGuardError` and subclasses (`FetchError`, `HashMismatchError`, `ExtractionError`, `SandboxError`, `PolicyError`, `InvalidSpecError`). The pipeline turns every one of them into an `error` verdict.

### CI (`.github/workflows/ci.yml`)

Four jobs, all with `permissions: contents: read` at the workflow level, every action pinned to a commit SHA:

- `lint`: `ruff check`, `ruff format --check`, `pyright`.
- `test`: `pytest` with coverage.
- `offline` (`ci.yml:33`): runs pytest inside `unshare --user --map-root-user --net`, a network namespace with no interfaces, to prove the PRD criterion "tests pass with the network disabled". It lowers `kernel.apparmor_restrict_unprivileged_userns` first because `ubuntu-latest` blocks unprivileged user namespaces through AppArmor.
- `docker` (`ci.yml:46`): builds the image, runs `sandbox/spike.sh`, and runs `pytest -m docker` on the PRD's real target runner.

The unit test suite also has its own guard: an autouse fixture replaces `socket.connect` for AF_INET/AF_INET6 with one that raises, except in Docker-marked tests (`tests/conftest.py:13-25`). `pyproject.toml` sets `addopts = "-m 'not docker'"` so `uv run pytest` never needs Docker.

CI has not run on GitHub yet.

### The sandbox image (`sandbox/sandbox.Dockerfile`)

- Base `python:3.12-slim-bookworm` pinned by digest (`sandbox.Dockerfile:6`), so the image cannot change under the scanner. Bookworm ships glibc 2.36, which is why `fetch.py` refuses manylinux wheels newer than `2_36`.
- Installs `strace`, creates user `sandbox` with uid 10001 and no login shell (`sandbox.Dockerfile:8-13`).
- Runs `seed_credentials.py` at build time (`sandbox.Dockerfile:16-18`), copies the runner to `/opt/pipguard/runner.py`, sets `USER 10001:10001` and `WORKDIR /home/sandbox/project`.
- The image carries no hardening flags itself; they are applied at `docker run` by `sandbox.py`, so they cannot be lost by someone running the image differently through pip guard.

### Build-time fake credentials (FR-4.3)

`seed_credentials.py` writes `~/.aws/credentials`, `~/.ssh/id_rsa`, `~/.netrc` and `~/project/.env` with realistic formats (an `AKIA…` key id, an OpenSSH private-key block, a `ghp_…` token, an `sk_live_…` key) and random values from `secrets` (`seed_credentials.py:32-55`). Then it checks that the set of files written equals the list in `sandbox/manifest.json` and fails the build if not (`seed_credentials.py:59-63`).

Two decisions here:

- **Generated at build, never committed.** Credential-shaped strings in a public repo trip GitHub push protection and look like a leak. Random per build also means a leaked value is worthless.
- **The word "fake" lives only in `manifest.json`.** A sandbox-aware package that greps for "fake" or "example" in the values learns nothing. The parser uses the same manifest to recognise credential reads (`sandbox.py:241-242`).

### The week-1 spike and the explicit seccomp finding

The PRD's riskiest assumption was that strace works under the hardened flags. `sandbox/spike.sh` answers it with a tiny wheel (built by `scripts/make_wheel.py`, no build backend) whose import opens the AWS credentials, spawns `sh -c true` and connects to `203.0.113.7:443`. It runs the container with the FR-4.7 flags, traces install and import, and greps for the three observations.

Result (2026-11-02, local, Docker Desktop 27.5.1 on WSL2): **pass, no relaxation needed.** Inside the container: `CapEff: 0`, `NoNewPrivs: 1`, `Seccomp: 2` (filter mode), uid 10001. All three observations were present; the connect failed with `ENETUNREACH`.

Finding: `docker info` on Docker Desktop reported `seccomp profile=unconfined`, even though a filter was active. Rather than trust the daemon's configuration, the repo carries moby v27.5.1's default profile as `sandbox/seccomp-default.json` and passes it on every run (`sandbox.py:71-72`, `spike.sh`). It is the same profile `ubuntu-latest` applies by default, so this tightens isolation and never relaxes it.

The spike has not yet run on `ubuntu-latest`; the CI `docker` job does that on every push once CI runs.

## Key design decisions

| Decision | Reason | Rejected alternative |
| --- | --- | --- |
| Frozen, `extra="forbid"` pydantic models between stages | Stages can be built and tested in parallel by different people; a contract change fails loudly | Plain dicts (typos pass silently), dataclasses (no validation of untrusted JSON from cache or container) |
| `Verdict` validator requires a reason for non-`allow` | Explainability enforced by the type, not by convention | A unit test per call site |
| One `vectorize()` for training and inference | Train/serve skew is a classic ML bug | Separate feature code in `scripts/eval` |
| Missing value = 0 plus a flag | A linear model reads `-1` as a real, very small value | Sentinel values, or dropping rows with missing metadata |
| Credentials generated at build time from a manifest | No secrets-shaped strings in git; the marker is not in the values | Committed sample files, or environment variables (PRD: env reads are not observable) |
| Explicit seccomp profile | The daemon's default is not trustworthy (Docker Desktop reported unconfined) | Relying on `docker info` |
| Base image pinned by digest | Reproducible sandbox; the image digest is part of the cache key | Floating `python:3.12-slim` tag |
| CI job with no network interfaces | Proves the reproducibility criterion instead of claiming it | Trusting the conftest guard alone |

## Limitations and known gaps

- `SANDBOX_PYTHON_TAGS` and `SANDBOX_PLATFORM_PREFIXES` in `models.py:21-22` are not used anywhere; wheel selection lives in `fetch.py`. They are harmless but stale.
- The image's `ENV PYTHONPATH` and `PYTHONDONTWRITEBYTECODE` are ignored by the runner, which starts every interpreter with `-I` (isolated mode). The runner passes `-B` explicitly for that reason (see log 04).
- The spike flag set in `spike.sh` predates the `/sandbox/deps` tmpfs and writes traces to files in `/tmp`; the production command in `sandbox.docker_run_argv` differs in those two respects. The spike answers "does strace work under these flags", not "is this the production runner".
- PRD's supply-chain row asks for the image to be published to GHCR with its digest recorded. v1 builds the image in the action instead; the digest is still recorded per run (`sandbox.image_digest`).
- `docs/PLAN.md` checkboxes for Phase 0 are mostly unticked even though the work exists.

## How it is tested

- `tests/test_models.py`: spec parsing, the reason-required validator, thresholds ordering, allowlist normalisation, the change invariant.
- `tests/test_features.py`: key order equals `FEATURE_NAMES`, aggregation rules, missing flags, behaviour all-zero without a trace.
- `tests/test_config.py`, `tests/test_log.py`: defaults, malformed TOML is an error, hash changes with config; JSON log shape and correlation ID.
- `tests/test_seed_credentials.py`: formats, randomness, manifest match, no "fake" in values.
- `tests/test_make_wheel.py`: deterministic bytes and SHA-256.
- `tests/test_no_network.py`: the conftest guard really blocks an inet connect.
- The spike itself: `bash sandbox/spike.sh` (local pass recorded in `docs/DESIGN.md`).

## Interview questions

**Why pydantic models between stages instead of passing dicts around?**
The stages were built in parallel workstreams, and the models are the agreement between them. `extra="forbid"` and `frozen=True` make a misspelt field or an accidental mutation fail immediately. The same models validate untrusted JSON coming back from the cache and from the container, so validation is not optional.

**How do you guarantee every warn or block has a reason?**
The `Verdict` model has a validator that raises if the level is not `allow` and `reasons` is empty (`models.py:389-394`). So it is impossible to construct such a verdict anywhere in the code, including error paths. The scoring and error helpers always supply one.

**Why generate the fake credentials at image build time rather than commit them?**
Credential-shaped strings in a public repository trigger GitHub push protection and look like a real leak to anyone scanning the repo. Generating random values at build time also means a value that escapes is worthless. The list of files lives in a manifest, which is also where the word "fake" lives, so the values give a sandbox-aware package no hint.

**What exactly did the spike test, and what would you have done if it failed?**
It ran strace inside the container with no capabilities, no-new-privileges, a read-only root, no network, a non-root user and the default seccomp profile, and checked that a credential open, an exec and a connect were all visible. If it had failed, the PRD rule was to shrink the dynamic stage to a fixture demonstration and spend the hours on static analysis and evaluation; isolation is never weakened to make tracing work. It passed with no change.

**Why pass the seccomp profile explicitly if Docker applies it by default?**
During the spike, Docker Desktop reported `seccomp profile=unconfined`, so the default cannot be assumed on every machine. Passing moby's own default profile file makes the filter independent of daemon configuration. It is the same profile `ubuntu-latest` uses, so it never loosens anything.

**Why is missing metadata encoded as 0 plus a flag?**
A linear model multiplies each feature by a coefficient, so a sentinel like `-1` would be treated as a real, meaningful value. Zero plus an explicit `*_missing` feature lets the model learn a separate weight for "unknown". It also keeps the feature vector the same shape for every package.

**How do you prove unit tests do not use the network?**
Two layers: an autouse fixture replaces `socket.connect` for IPv4/IPv6 with a function that raises, and a CI job runs the whole suite inside a network namespace that has no interfaces at all. The first catches mistakes during development; the second proves the PRD reproducibility criterion on a clean runner.
