# pip guard — Design (v0.2)

This document explains how the pieces fit. Scope, requirements and priorities live in `docs/PRD.md`; if the two disagree, the PRD wins.

## Problem

Python projects pull most of their code from PyPI, and anything installed from there runs with the full trust of the project: files, credentials, network. Anyone can publish to PyPI, so attackers use typosquats (`requets` for `requests`), hijacked releases of abandoned packages, and packages that behave normally but exfiltrate secrets during installation or on first import.

Existing scanners (pip-audit, Dependabot, Snyk) match name and version against databases of reported incidents. They cannot catch an attack nobody has reported yet.

## Idea

Judge a package by what it does, not only by whether it is already known to be bad. For each pinned direct dependency a PR adds or changes:

1. Fetch the exact artifact and extract it safely without executing anything.
2. Extract static indicators from the files.
3. Install and import the target in a disposable, network-less container under strace, with dependencies preinstalled untraced so behaviour is attributed to the target only.
4. Score the evidence with rules plus a small tabular model, producing a verdict with reasons and a coverage state.
5. Report in the GitHub Actions job summary and fail the check on `block`, `error` or `incomplete`.

## What v1 is not

- Not an escape-proof sandbox. Docker shares the host kernel; this is a monitoring tool for CI with strong defaults.
- Not a dynamic analyser of archived real-world malware. The real corpus is analysed statically; the sandbox runs only on our fixtures and on PR-proposed packages.
- Not a builder of source distributions. sdists are inspected statically; PEP 517 build behaviour is reported as not exercised.
- Not a hosted service, not a fork-PR commenter, not a lockfile parser. All deferred.

## Architecture

```
GitHub PR (requirements.txt / pyproject.toml, pinned) --> pip guard Action (read-only token)
                                                                |
                                            diff pinned direct deps; cache lookup by artifact hash
                                                                |
            +----------------+----------------+-----------------+----------------+
            v                v                v                                   v
        fetch.py        extract.py        static.py                          sandbox.py + trace.py
   PyPI JSON API,   safe unpack:       ast indicators,          deps preinstall (untraced), then
   wheel + sdist,   path/link/size     entropy, URLs/IPs,       target --no-deps + import (traced),
   SHA-256, deps    limits             typosquat snapshot       --network none, strace -f
            |                |                |                                   |
            +----------------+----------------+-----------------+----------------+
                                                                v
                                                   rules.py + scoring.py
                                        blocking/warning rules + LR/LightGBM -> Verdict
                                        {level, score, reasons, coverage, overrides}
                                                                |
                                           +--------------------+--------------------+
                                           v                                         v
                                   cache.py (SQLite, best-effort)        report.py: job summary, check
                                                                         outcome, gzip JSON artifact,
                                                                         optional same-repo PR comment
```

## Stage contracts (pydantic, `models.py`, each with `schema_version`)

- `PackageSpec(name, version)` — exact pin only.
- `Artifact(filename, kind: wheel|sdist, sha256, python_tag, platform_tag, path)`.
- `FetchedPackage(spec, artifacts, metadata, declared_deps: list[Artifact])`.
- `StaticFeatures` — per artifact: indicator presence flags, counts, entropy max, URL/IP lists, typosquat distance + target + snapshot date, metadata features.
- `BehaviorTrace` — target wheel only: writes outside allowed dirs, credential-file opens, subprocesses with argv, `connect()` attempts (family, address, port), exit codes, step timings, `completeness ∈ {complete, incomplete:timeout, incomplete:import_failed, incomplete:no_importable_module, incomplete:no_wheel, skipped:policy}`.
- `Verdict(level ∈ {allow, warn, block, error, incomplete}, score, reasons, coverage, overrides, model_version, thresholds)`.

## Component notes

### fetch.py
PyPI JSON API → pick the wheel matching the runner's Python/platform tags (and the sdist for static inspection). Verify SHA-256 against PyPI; mismatch → `error`. Read declared dependencies from the wheel's METADATA and download their wheels for the untraced preinstall. Record every artifact's identity.

### extract.py
Wrap `zipfile`/`tarfile`. Reject entries whose resolved path leaves the extraction directory, all symlinks and hardlinks, and archives over 100 MB compressed / 500 MB extracted / 20,000 files. Use `tarfile`'s `filter='data'` where available. Tests include traversal, link and zip-bomb fixtures.

### static.py
`ast` over every `.py` (syntax errors recorded, not fatal). Indicators are reported as present/absent and are called *suspicious indicators*, never proof. Install-time indicators (`cmdclass`, overridden install commands, `.pth` import lines, PEP 517 backend in sdist) are static presence only. Typosquat: PEP 503-normalise, Damerau-Levenshtein via `rapidfuzz` against a frozen dated snapshot of the top 5,000 names.

### sandbox.py and trace.py
Image: slim Python + strace, non-root, pinned base digest. Run flags: `--network none --read-only --tmpfs /tmp --tmpfs /sandbox/site-packages --tmpfs <pip cache> --cap-drop ALL --security-opt no-new-privileges --memory 1g --pids-limit 256`, no bind mounts, no Docker socket. Fake credential **files** (`~/.aws/credentials`, `~/.ssh/id_rsa`, `~/.netrc`, `.env`) with realistic formats and invalid values; the word "fake" lives in `sandbox/manifest.json`, never in the values.

Two-step install: `pip install --no-index --find-links <deps>` untraced, then `strace -f -e trace=network,process,file -o ... pip install --no-deps --no-index <target>` and `strace ... python -c "import <top_level>"`. Timeouts 90 s / 60 s; a timeout kills the process tree and sets `incomplete:timeout`.

What strace can and cannot see: subprocess argv, file opens/writes and `connect()` destinations — yes; environment-variable reads and DNS names — no. The schema contains only the former. strace output is attacker-influenced: the parser caps field lengths, escapes before rendering, and is fuzz-tested with `hypothesis`.

### rules.py and scoring.py
`rules.yaml` holds **blocking rules** (require ≥ 0.95 measured precision on the stratified benign sample; any hit → `block`) and **warning rules** (any hit → at least `warn`). Model ladder: rules → logistic regression → LightGBM, each adopted only if it improves recall at the FPR target by ≥ 3 points on the held-out fold. Thresholds are chosen on validation data and stored with the model artifact; 0.5/0.85 are placeholders. Allowlist entries cap a package at `warn` but never hide the observation.

### report.py and the Action
Job summary with a verdict table (package, artifact, verdict, coverage, top reasons). Exit codes: 0 allow/warn, 2 block, 3 error/incomplete; `--fail-on-warn` makes warn exit 1. The composite action maps codes to job outcomes explicitly, with a test per mapping. `continue-on-error: true` on the step defeats enforcement and the README says so. Compressed JSON report always; traces only on non-`allow`, capped at 5 MB. PR comment only on same-repo PRs (fork PRs have a read-only token); never `pull_request_target`.

### cache.py
SQLite file keyed by (artifact sha256, scanner version, model version, config hash). Carried between runs by GitHub Actions cache, best-effort; cache writes skipped on fork PRs. A behavioural result is reused only for the identical artifact hash and runtime image digest.

## Evaluation (three tracks, never mixed)

- **A. Static classification** on the real-world corpus (Datadog archive primary; fetchable OpenSSF subset; stratified benign bands from the frozen top-5,000 snapshot plus a random band beyond it). Split by package name and campaign group; payload dedup by normalised-source hash. Report recall at per-band FPR ≤ 0.05 with counts and 95% Wilson CIs, PR-AUC, calibration, blocking-rule precision, and rules vs LR vs LightGBM ablations. GuardDog is not a feature here (dataset circularity).
- **B. Behavioural detection** on the fixture suite: each suspicious fixture paired with a benign counterexample using the same API legitimately. Deterministic; 100% expected.
- **C. End-to-end** on demo-repo PRs: planted package, benign bump, unpinned spec, forced timeout, forced download failure.

Behavioural features are not claimed to improve Track A, because Track A samples are never executed.

## Threat model and limitations

- Docker is not a VM; a kernel exploit could escape. Acceptable for a CI scanner of PR candidates, not for targeted malware.
- Sandbox-aware code can behave benignly in the container.
- Wheels only in the sandbox; sdist build-backend behaviour is not exercised.
- Env-var reads and DNS names are not observable; credential-file opens and `connect()` destinations are.
- Only exactly pinned direct dependencies in `requirements.txt` and `pyproject.toml`.
- Behaviour that triggers on specific inputs, timers or environment checks is not observed.
- Verdicts are probabilistic; `warn` exists for a reason and humans still review.

## Week-1 spike (record the result here)

Question: does `strace -f` work inside a Docker container on `ubuntu-latest` with `--cap-drop ALL`, `no-new-privileges`, the default seccomp profile and a non-root user? Record: yes/no, the exact flags, and if no, the single minimal change that makes it work and whether that change is acceptable. If it is not, the dynamic stage reduces to a fixture demonstration and hours move to the static scanner, evaluation and Action.

Result: _not yet run_

## Decisions log

- 2026-11-02 — v0.2 after two external reviews: cut fine-tune, hosted service, sinkhole, SARIF; gVisor and lockfiles to v2; `--network none`; `--no-deps` two-step install; fail closed on error/incomplete; job summary primary, PR comment best-effort; three evaluation tracks.
