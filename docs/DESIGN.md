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
- `BehaviorTrace` — target wheel only: writes outside allowed dirs, credential-file opens, subprocesses with argv, `connect()` attempts (family, address, port), exit codes, step timings, `completeness ∈ {complete, incomplete:timeout, incomplete:import_failed, incomplete:no_importable_module, incomplete:no_wheel, incomplete:sandbox_error, incomplete:trace_truncated, skipped:policy}`.
- `Verdict(level ∈ {allow, warn, block, error, incomplete}, score, reasons, coverage, overrides, model_version, thresholds)`.

## Component notes

### fetch.py
PyPI JSON API → pick the wheel matching the runner's Python/platform tags (and the sdist for static inspection). Verify SHA-256 against PyPI; mismatch → `error`. Read declared dependencies from the wheel's METADATA and download their wheels for the untraced preinstall. Record every artifact's identity.

Wheel choice targets the *sandbox* (CPython 3.12, python:3.12-slim-bookworm, glibc 2.36), never the host: `py3-none-any` first, then manylinux x86_64 with the highest glibc ≤ 2.36 (cp312 ABI over abi3), then `linux_x86_64`. musllinux is never picked (the image is glibc). No compatible wheel → sdist only, and the sandbox reports `incomplete:no_wheel`. Declared deps: markers evaluated against the sandbox environment, extras never installed, non-pinned specifiers resolved to the newest stable non-yanked release with a sandbox wheel via a minimal PEP 440 subset (no `packaging`); closure capped at 50 wheels / depth 10. Unresolvable requirements (URL deps, unknown markers, sdist-only deps) are skipped with a log line; the sandbox import then fails closed.

### extract.py
Wrap `zipfile`/`tarfile`. Reject entries whose resolved path leaves the extraction directory, all symlinks and hardlinks, and archives over 100 MB compressed / 500 MB extracted / 20,000 files. Use `tarfile`'s `filter='data'` where available. Tests include traversal, link and zip-bomb fixtures.

### static.py
`ast` over every `.py` (syntax errors recorded, not fatal). Indicators are reported as present/absent and are called *suspicious indicators*, never proof. Install-time indicators (`cmdclass`, overridden install commands, `.pth` import lines, PEP 517 backend in sdist) are static presence only. Typosquat: PEP 503-normalise, Damerau-Levenshtein via `rapidfuzz` against a frozen dated snapshot of the top 5,000 names.

Implementation choices (all in `static.py` as module constants with justifying comments):
- Files over 5 MB are not read. An oversize `.py` file, an undecodable or pathologically nested `.py` file, and a malformed sdist `pyproject.toml` all count in `syntax_error_count` (the contract has no separate field). Only a missing or unreadable directory raises `PipGuardError`.
- Call targets are resolved through import aliases collected module-wide; aliases created by assignment (`d = base64.b64decode`) are not followed. `getattr(obj, "<literal>")` counts when the literal names a tracked call. All base64 decoders share the `b64decode` counter. A literal `__import__("ctypes")` counts as a ctypes import.
- FR-3.7 counts names reached at module top level (including module-level `if`/`try` and class bodies) or in install-hook code: the project's own `setup.py` (root or the sdist's top folder; vendored or test `setup.py` files never run at install), `.pth` import lines, and bodies of classes overriding `install`/`develop`/`egg_info`. `ssl`, `pathlib`, `os.path` and `tempfile` are excluded as too common to carry signal.
- Raw IPs are globally routable IPv4 literals or IPv6 global unicast (`2000::/3`), plus the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) so fixtures can use them. LAN, loopback, link-local, CGNAT and reserved values such as netmasks do not count. requests' sdist has 17 of those in its tests, and an exfiltration target is routable. A version string that is a valid public IPv4 (`1.2.3.4`) still counts.
- Install-command overrides (`overridden_install_command`) count only when the artifact has a root `setup.py`. Without one, nothing runs them: numpy 2.1's meson sdist has such classes in vendored code.
- Typosquat: a package that is itself in the popularity snapshot gets no typosquat result. `six` is 2 edits from `pip`, and both are top-100 projects. This goes beyond FR-3.6, which only excludes the package itself as a candidate: attackers' packages are by construction not popular. Caveat for Track A: benign rows from the top-5,000 bands then never show a typosquat signal, so only the random band measures that signal's false-positive rate honestly. Scheme-less domains count only with a TLD from a short list that excludes file-extension TLDs (`py`, `sh`, `cc`). Hosts inside URLs always count. Lists are deduplicated and capped at 50 entries of 200 characters.
- Typosquat snapshot: `data/top-pypi-5000.json` (hugovk/top-pypi-packages, `last_update` date). Candidates within distance 2 are computed with `rapidfuzz.process.extract`. A candidate that fires is preferred over a nearer one that does not.

### sandbox.py and trace.py
Image: slim Python + strace, non-root, pinned base digest, plus our in-container runner (`sandbox/runner.py`, copied to `/opt/pipguard/runner.py`). Fake credential **files** (`~/.aws/credentials`, `~/.ssh/id_rsa`, `~/.netrc`, `.env`) with realistic formats and invalid values; the word "fake" lives in `sandbox/manifest.json`, never in the values.

Run command (fixed; FR-4.7; `sandbox.docker_run_argv`): `docker run --rm -i --name pipguard-<uuid> --network none --read-only --tmpfs /tmp:rw,size=256m,mode=1777 --tmpfs /sandbox/site-packages:rw,size=512m,mode=1777 --tmpfs /sandbox/deps:rw,size=512m,mode=1777 --tmpfs /home/sandbox/.cache:rw,size=256m,mode=1777 --cap-drop ALL --security-opt no-new-privileges --security-opt seccomp=<repo>/sandbox/seccomp-default.json --memory 1g --pids-limit 256 --user 10001:10001 <image> python -I /opt/pipguard/runner.py <install_s> <import_s>`. No bind mounts, no Docker socket, no environment passthrough. The host shells out to the `docker` CLI with list arguments and a timeout on every call.

**Policy guard (FR-4.10, `policy_allows`).** `origin="pypi"` runs only when the caller marks it as a PR candidate. `origin="fixture"` runs only when every artifact file (target, sdist, dependency wheels) resolves inside `fixtures_root` (default `tests/fixtures`; the Docker tests build wheels into a temp dir and pass that). `origin="local_artifact"` runs only when the caller marks it as a PR candidate: a wheel the PR itself ships, i.e. the demo's `--local-index`. `pipguard scan --artifact` and the evaluation batch runner never set that flag, so arbitrary local files and the archived corpus never run. `origin` is a required field with no default; `origin="unknown"` (and anything else) is always refused. A denial returns `skipped:policy` without starting a container; a package without a wheel returns `incomplete:no_wheel`, also without a container.

**Transport.** The target wheel and dependency wheels go in as a tar on stdin. Results come back as one envelope on the runner's stdout: `PIPGUARD-ENVELOPE-V1 <len>\n<json>` with per-step exit code, wall time, timeout flag and base64 trace, the module list and per-module import results. The host reads at most 12 MB of stdout, validates the envelope with a strict pydantic model (extra fields forbidden, module names must be identifiers, lengths capped) and caps decoded trace text at 5 MB per package before parsing. Garbled envelope → `incomplete:sandbox_error`; oversize output or trace → `incomplete:trace_truncated` with `truncated=True`.

**Runner steps.** All interpreters run with `-I -B` (isolated; no `.pyc` writes, because `-I` ignores `PYTHONDONTWRITEBYTECODE` and stdlib bytecode writes would otherwise appear as write attempts on the read-only root).
1. Untar into `/tmp/in`.
2. Untraced: `pip install --no-deps --no-index --find-links /tmp/in/deps --target /sandbox/deps <dep wheels>`. `--no-deps` because fetch.py already resolved the closure; a dependency it could not resolve then fails the traced import (`incomplete:import_failed`). A failed preinstall is `incomplete:sandbox_error`.
3. Traced install: `strace -f -qq -s 256 -e trace=network,process,file -o /dev/stderr python -I -B -c <pip wrapper> install --no-deps --no-index --target /sandbox/site-packages <target wheel>`. The wrapper switches off the `lsb_release -a` / `uname -rs` probe that pip's vendored `distro` runs to build a User-Agent even with `--no-index`; without that, every package would show two install-time subprocesses. A failed install is `incomplete:sandbox_error`.
4. Traced import: one interpreter appends `/sandbox/deps` to `sys.path`, calls `site.addsitedir('/sandbox/site-packages')`, then imports every top-level module **found on disk** under `/sandbox/site-packages`: top-level `*.py` files and directories containing any `.py`, excluding `*.dist-info`, `*.data`, `*.egg-info`, `__pycache__` and `bin`; identifiers only, at most 50. The wheel's own `top_level.txt`/`RECORD` is not trusted: a wheel listing `json` would otherwise import the stdlib and report an unexecuted package as complete. After each import, the module's `__file__`/`__path__` must resolve inside `/sandbox/site-packages`; otherwise the result is `NotFromTarget` → `incomplete:import_failed`. Any failed import → `incomplete:import_failed` (observations kept); no module → `incomplete:no_importable_module`.
5. Timeouts (FR-4.6): the runner enforces install/import timeouts itself (SIGTERM to the step's process group so strace can flush, SIGKILL 2 s later) and still reports the partial trace → `incomplete:timeout`. The host keeps a backstop timeout of `2 × install + import + 30 s` (preinstall, install, import, slack); on expiry it runs `docker kill`. `docker rm -f <name>` runs in a `finally` after every run.

**Attribution (PRD M2).** Dependency wheels are installed before tracing starts. In the traced import, `/sandbox/deps` is appended to `sys.path` rather than added as a site dir, so dependency `.pth` files never run there, while the target's `.pth` files do (as they would in a real environment). Appending, not `PYTHONPATH`, also stops a dependency from shadowing a stdlib module such as `site`. Module code of a dependency that the target itself imports does run in the traced step and is attributed to the target, which chose to import it. The `noisy_dependency` fixture (a dependency whose `.pth` connects) proves the dependency start-up hook is not observed.

**Install-step realism.** Installing a *wheel* runs no package code: pip unzips files and writes `RECORD`. So behaviour almost never appears in the install step; it appears at import, and via a target `.pth` at interpreter start. The fixture suite is built around that, and a Docker test asserts that a real `pip install` trace has zero connects, subprocesses, writes outside the allowed dirs and credential reads, so the install-step rules (`B_CONNECT_INSTALL`, `W_CONNECT_INSTALL`) do not fire on every package.

**Parser (`trace.py`, FR-4.11).** strace output is attacker-influenced. Input is capped at 5 MB and lines at 64 KB before parsing; regexes are anchored or bounded with no nested quantifiers; arguments are split by a linear scanner that respects quotes and brackets; fields are capped (path 512, argv 32 × 256, address 64; 100 distinct observations per category per step); NUL and control characters are stripped; nothing is evaluated, and nothing is Markdown-escaped (report.py escapes once at render). It handles `PID syscall(...) = ret`, `<unfinished ...>` / `<... resumed>` stitched by pid, `+++ exited +++`, `--- SIG... ---`, `"..."...` truncation and `\x`/octal/`\n`/`\"` escapes; anything else is counted as garbage. Observations:
- writes: `open`/`openat`/`openat2`/`creat` with `O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND` outside `/tmp`, `/sandbox/site-packages`, `/sandbox/deps`, `/home/sandbox/.cache`, `/dev/null`, `/dev/tty`, `/dev/pts`, `/dev/shm`, `/proc/self`, including failed attempts (EROFS/EACCES: the attempt is the signal). Paths are normalised; relative `AT_FDCWD` paths resolve against the WORKDIR (`chdir` is not tracked); paths relative to another directory fd are kept as written and never count as allowed.
- credential reads: any open of a path listed in `sandbox/manifest.json`. `stat`/`access` do not count.
- subprocesses: `execve`/`execveat` argv, excluding the root command we launched (its first successful exec and PATH-search ENOENT attempts with the same argv). A later exec by the root pid is reported. PATH search in a child (one ENOENT per directory) is reported once per (pid, argv). Note: `dash` looks commands up with `stat()`, so `sh -c 'curl …'` with no curl installed shows the `sh` exec with `curl` in its argv, not a curl exec. There is no `timeout` wrapper under strace (the runner times steps itself), so nothing needs excluding for it.
- connects: `connect()` family, address, port (AF_INET, AF_INET6, AF_UNIX path, else `other`). AF_UNIX connects to glibc's nscd sockets (`/var/run/nscd/socket`, `/run/nscd/socket`) are dropped: name-service lookups (`getpwuid`, `getaddrinfo`) try them as libc plumbing, which would otherwise make `W_CONNECT_INSTALL` fire on ordinary code.

Field and list caps set `truncated=True` but keep the observation (the evidence is still there). Only an over-size input means the trace was not fully parsed, which is `incomplete:trace_truncated`. Step exit codes come from the runner's process results, not from trace text, because `-qq` hides exit lines and trace text is forgeable.

**Tamper resistance and its limits.** The package runs as the same uid as the runner and strace. Mitigations: strace writes to a pipe the runner reads (`-o /dev/stderr`), not a file in `/tmp` the package could rewrite or truncate; the traced programs move their own fds 1 and 2 to log files before any package code runs, so package output cannot enter the trace pipe or the envelope; the runner (PID 1) makes itself non-dumpable, so the package cannot open `/proc/1/fd/1` to forge the envelope. Residual limits, accepted for v1: the package can open strace's pipe through `/proc/<strace pid>/fd` and inject text. That cannot remove lines strace already wrote, but an injected partial line can corrupt the next real line, which the parser then counts as garbage. It can kill strace (exit code ≠ 0 → `incomplete`), and code running in the same interpreter can forge the per-module import results. None of this is fixable without a second uid or a tracer outside the container (eBPF, P2).

**noexec consequence.** Docker's tmpfs default is `noexec`, so compiled extensions (`.so`) in `/sandbox/site-packages` cannot be mapped. Decided 2026-11-04: keep `noexec`. `sandbox.compiled_extensions` lists native files from the wheel's zip index (nothing is extracted), and any wheel containing them is `incomplete:import_failed` with a reason naming the extension, even if the import happened to succeed (an optional extension may have been skipped silently). The check fails (exit 3).

What strace can and cannot see: subprocess argv, file opens/writes and `connect()` destinations, yes; environment-variable reads and DNS names, no. The schema contains only the former.

### rules.py and scoring.py
`rules.yaml` holds **blocking rules** (require ≥ 0.95 measured precision on the stratified benign sample; any hit → `block`) and **warning rules** (any hit → at least `warn`). Model ladder: rules → logistic regression → LightGBM, each adopted only if it improves recall at the FPR target by ≥ 3 points on the held-out fold. Thresholds are chosen on validation data and stored with the model artifact; 0.5/0.85 are placeholders. Allowlist entries cap a package at `warn` but never hide the observation.

Decisions (Workstream D):
- Rule conditions are a tiny interpreted language (`feature op value`, nested `all`/`any`), validated at load against `FEATURE_NAMES` plus rule-only extras; reasons are fixed templates filled only with `safe_text()` values (length-capped, control characters removed). Markdown/HTML escaping happens exactly once, in `report.py`, so the JSON report stays readable and the job summary is never double-escaped.
- Blocking rules are the three the PRD names; `connect()` during install only counts non-loopback IP connects (loopback/Unix sockets warn). All blocking rules still need their >= 0.95 precision confirmed in `docs/EVAL.md`.
- Level order: rules (block/warn) -> model can raise, never lower -> allowlist caps block at warn -> incomplete evidence gives `incomplete` unless already `block`. So an allowlisted, incomplete package is `incomplete`, never `warn`; `error`/`incomplete` are never capped.
- `skipped:policy` counts as incomplete when the sandbox was requested; with `--no-sandbox` the level comes from static evidence and coverage says behaviour was not run.
- Thresholds: the model artifact's win unless `pipguard.toml` sets non-default ones.
- Logistic regression runs as a pure-Python dot product; Platt is applied to the logit as `1/(1+exp(a*z+b))`. A LightGBM artifact raises until it is adopted. No `model/model.json` means rules-only; a malformed one is an error.

### report.py and the Action
Job summary with a verdict table (package, artifact, verdict, coverage, top reasons). Exit codes: 0 allow/warn, 2 block, 3 error/incomplete; `--fail-on-warn` makes warn exit 1. The composite action maps codes to job outcomes explicitly, with a test per mapping. `continue-on-error: true` on the step defeats enforcement and the README says so. Compressed JSON report always; traces only on non-`allow`, capped at 5 MB. PR comment only on same-repo PRs (fork PRs have a read-only token); never `pull_request_target`.

### cache.py
SQLite file keyed by (artifact sha256, scanner version, model version, config hash). Carried between runs by GitHub Actions cache, best-effort; cache writes skipped on fork PRs. A behavioural result is reused only for the identical artifact hash and runtime image digest, so the image digest is part of the key (empty for static-only verdicts). Only `allow`/`warn`/`block` are cached; `error`/`incomplete` describe a failed run and are always retried. The restored file is untrusted: any sqlite error, invalid row, oversized row, or row whose own versions/artifact disagree with its key is a miss plus a warning.

## Evaluation (three tracks, never mixed)

- **A. Static classification** on the real-world corpus (Datadog archive primary; fetchable OpenSSF subset; stratified benign bands from the frozen top-5,000 snapshot plus a random band beyond it). Split by package name and campaign group; payload dedup by normalised-source hash. Report recall at per-band FPR ≤ 0.05 with counts and 95% Wilson CIs, PR-AUC, calibration, blocking-rule precision, and rules vs LR vs LightGBM ablations. GuardDog is not a feature here (dataset circularity).
- **B. Behavioural detection** on the fixture suite: each suspicious fixture paired with a benign counterexample using the same API legitimately. Deterministic; 100% expected.
- **C. End-to-end** on demo-repo PRs: planted package, benign bump, unpinned spec, forced timeout, forced download failure.

Behavioural features are not claimed to improve Track A, because Track A samples are never executed.

## Threat model and limitations

- Docker is not a VM; a kernel exploit could escape. Acceptable for a CI scanner of PR candidates, not for targeted malware.
- Sandbox-aware code can behave benignly in the container.
- Wheels only in the sandbox; sdist build-backend behaviour is not exercised.
- Packages with compiled extensions (`.so`, `.pyd`) are never fully observed: the sandbox's writable mounts are `noexec`, so native code cannot load. Such packages are `incomplete` with a reason naming the extension, and the check fails.
- Env-var reads and DNS names are not observable; credential-file opens and `connect()` destinations are.
- Only exactly pinned direct dependencies in `requirements.txt` and `pyproject.toml`.
- Behaviour that triggers on specific inputs, timers or environment checks is not observed.
- Verdicts are probabilistic; `warn` exists for a reason and humans still review.

## Week-1 spike (record the result here)

Question: does `strace -f` work inside a Docker container on `ubuntu-latest` with `--cap-drop ALL`, `no-new-privileges`, the default seccomp profile and a non-root user? Record: yes/no, the exact flags, and if no, the single minimal change that makes it work and whether that change is acceptable. If it is not, the dynamic stage reduces to a fixture demonstration and hours move to the static scanner, evaluation and Action.

Result (2026-11-02, local): **yes, strace works under the hardened flags. No relaxation was needed.**

- Host: Docker Desktop 27.5.1 on WSL2 (kernel 5.15.167.4-microsoft-standard-WSL2). This is not `ubuntu-latest`, so the CI `docker` job re-runs `sandbox/spike.sh` on `ubuntu-latest` on every push.
- Exact flags: `--rm -i --network none --read-only --tmpfs /tmp:rw,size=256m,mode=1777 --tmpfs /sandbox/site-packages:rw,size=512m,mode=1777 --tmpfs /home/sandbox/.cache:rw,size=256m,mode=1777 --cap-drop ALL --security-opt no-new-privileges --security-opt seccomp=sandbox/seccomp-default.json --memory 1g --pids-limit 256 --user 10001:10001`. There are no bind mounts; artifacts go in as a tar on stdin.
- Observed under `strace -f -qq -s 256 -e trace=network,process,file`:
  - `openat("/home/sandbox/.aws/credentials", O_RDONLY)`
  - `execve("/usr/bin/sh", ["sh","-c","true"])`
  - `connect(AF_INET, 203.0.113.7:443) = -1 ENETUNREACH`
  - container exit 0, `SPIKE_RESULT=pass`.
- Inside the container: `CapEff: 0`, `NoNewPrivs: 1`, `Seccomp: 2` (filter mode), uid 10001.
- Finding: `docker info` on Docker Desktop reports `seccomp profile=unconfined`, even though a filter was active in the container. To avoid depending on daemon configuration, the sandbox passes Docker's own default profile explicitly (`sandbox/seccomp-default.json`, moby v27.5.1, sha256 `9c1025c8…9c76`). This is the same profile `ubuntu-latest` applies by default, so it tightens isolation and never relaxes it.
- Known consequence, not a relaxation: Docker's tmpfs default is `noexec`, so compiled extensions (`.so`) cannot be mapped from `/sandbox/site-packages`. Such packages fail import, which yields `incomplete:import_failed` and fails closed. Decided 2026-11-04: `noexec` stays (see Decisions log).
- Docker Desktop was flaky during the spike: one probe container could not be killed. That is a local environment issue, unrelated to the flags.

## Decisions log

- 2026-11-02 — v0.2 after two external reviews: cut fine-tune, hosted service, sinkhole, SARIF; gVisor and lockfiles to v2; `--network none`; `--no-deps` two-step install; fail closed on error/incomplete; job summary primary, PR comment best-effort; three evaluation tracks.
- 2026-11-02 — Week-1 spike passed with no relaxation. Docker's default seccomp profile is passed explicitly, because Docker Desktop reported `unconfined` at the daemon level.
- 2026-11-03 — Review fixes:
  - The sandbox imports modules found on disk and verifies each one's origin (MUST-FIX).
  - The trace parser canonicalises `//` and `/proc/<pid>/root` paths, counts dirfd-relative opens of credential file names and links to credential files, and records `sendto`/`sendmsg` with a destination as connect attempts, so UDP exfiltration is visible.
  - `pipguard ci` reads `pipguard.toml` from the base ref, so a PR cannot disable or loosen its own gate.
  - `--local-index` wheels take precedence over PyPI and are treated as PR-proposed.
- Known differences between the spike and production flags: `sandbox/spike.sh` has no `/sandbox/deps` tmpfs and writes traces to `/tmp` files. Production (`sandbox.docker_run_argv`) adds the deps tmpfs and streams strace to a pipe. Both use the same isolation flags.
- 2026-11-03 — Review findings 6–18:
  - Requirements files are decoded like pip (UTF-8/16/32 BOMs), and index options (`-i`, `--extra-index-url`, `--find-links`, `--no-index`) are reported as unsupported.
  - The cache key now includes a fingerprint of the scanner code, `rules.yaml`, the typosquat snapshot, the runner, the Dockerfile and the seccomp profile. A cache hit is looked up by PyPI's published sha256 *before* any download, so a hit skips every stage (FR-1.3).
  - An unexpected fetch crash is an `error` verdict with a report.
  - The sandbox adds `--memory-swap 1g`, so there is no swap beyond the 1 GB cap.
  - The PR comment can be posted by a separate job (`pull-requests: write`) while the scanning job keeps `contents: read`.
  - Dependabot is added.
  - Still open: model and thresholds (FR-5.2/5.8, need the corpus).
- 2026-11-04 — Author decisions on the remaining open items:
  - Compiled extensions: keep the `noexec` tmpfs; never loosen isolation. A wheel with native code is `incomplete` with a reason naming the extension and fails the check. Added to the known limitations.
  - `strace` pinned with apt as `strace=6.1-0.1` (Debian bookworm, the base image's release; checked on packages.debian.org 2026-11-04). A bookworm point release that replaces 6.1-0.1 makes the build fail loudly rather than drift; bump the pin then. GHCR image publishing waits until the repo is public (PLAN.md TODO).
  - `pipguard explain` prints every rule with `fired` true/false and the feature values its condition read (`rules.evaluate_all`, which shares `_holds` with `evaluate`, so it cannot disagree with the verdict).
  - `FetchedPackage.origin` is required (no default) and gains `"unknown"`, which the sandbox policy always refuses. A caller that forgets to set origin now fails validation instead of silently getting the most permissive value.

