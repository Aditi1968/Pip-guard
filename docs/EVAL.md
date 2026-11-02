# pip guard evaluation

Three tracks, never mixed: each number is reported only for the population it was measured on (PRD "Data, ML and evaluation"). How to reproduce: `scripts/eval/README.md`.

**Status:** Track A has not been run yet; its tables are placeholders until the local corpus evaluation runs. Tracks B and C have been run locally (2026-11-03), as shown below.

## Read this first

- **Behavioural features are not evaluated on Track A.** Track A samples are archived real-world malware and are never installed, imported or executed; only static features are computed for them. No claim is made that behavioural analysis improves Track A numbers. Behaviour is measured only on the fixture suite (Track B) and demo PRs (Track C).
- **Benign is a weak label.** Benign samples are popular or randomly drawn PyPI packages that are *not known* to be malicious. Fifty of them are manually reviewed; the rest are not. Some false positives may be undiscovered malware, and some "benign" packages may be malicious.
- **Confidence intervals are wide.** All rates carry 95% Wilson intervals with their counts. With a few hundred samples per band, an FPR of 0.05 has an interval several points wide; differences inside the intervals are not evidence of a better model.
- **Datadog dataset terms.** The Datadog dataset's terms are checked before any derived model or per-sample result is published. Until then this document carries aggregate numbers only, and no sample is redistributed.
- **Population.** Numbers describe this corpus (Datadog archive, fetchable OpenSSF subset, stratified benign bands from a dated top-5,000 snapshot plus a random band). They are not a claim about PyPI at large or about future attacks. GuardDog is not a feature, because much of the Datadog corpus was found with GuardDog.

<!-- track-a:start -->
## Track A: static classification (real-world corpus)

Not yet run. `scripts/eval/report.py` replaces this section from `data/results/ladder.json`.

### Counts

| Label / source / band | n |
| --- | --- |
| not yet run | |

### Recall at per-band FPR (holdout)

Block threshold: FPR <= 0.05 in every benign popularity band (worst band governs), warn: <= 0.15, both chosen on the validation fold.

| Model | Block threshold | Recall at block (95% CI) | PR-AUC |
| --- | --- | --- | --- |
| Logistic regression | not yet run | not yet run | not yet run |
| LightGBM | not yet run | not yet run | not yet run |

| Model | top-100 FPR | 101-1000 FPR | 1001-5000 FPR | random FPR |
| --- | --- | --- | --- | --- |
| Logistic regression | not yet run | not yet run | not yet run | not yet run |

### Calibration

| Bin | n | Mean predicted | Observed malicious |
| --- | --- | --- | --- |
| not yet run | | | |

### Rules alone

| Class | Precision (95% CI) | Recall (95% CI) |
| --- | --- | --- |
| blocking | not yet run | not yet run |
| warning | not yet run | not yet run |

### Ablations

| Configuration | Recall |
| --- | --- |
| Rules only | not yet run |
| Rules + LR | not yet run |
| LightGBM | not yet run |

Adopted rung: not yet run. Fetchable OpenSSF count: not yet run.

Behavioural features are not evaluated on Track A: these samples are never executed.
<!-- track-a:end -->

## Track B: behavioural detection (fixture suite)

Run locally on 2026-11-03 with `uv run pytest -m docker` (Docker Desktop 27.5.1, WSL2; hardened FR-4.7 flags plus the explicit default seccomp profile). Result: **15 passed, 0 failed**. CI repeats this run on `ubuntu-latest` (the `docker` job).

Each suspicious fixture is paired with a benign counterexample that uses the same API legitimately. Target: every expected observation is detected, no counterexample is flagged, and the parser fuzz tests pass (100%, deterministic).

| Fixture | Expected observation | Detected | Counterexample clean |
| --- | --- | --- | --- |
| connect_import | `connect()` to 203.0.113.10:443 at import | yes | yes (function defined, never called) |
| credential_exfil | `~/.aws/credentials` read and `sh -c 'curl …'` spawned at import | yes | yes (reads its own data file only) |
| pth_import | subprocess spawned from a target `.pth` at interpreter start | yes | yes (path-only `.pth`) |
| obfuscated_exec | `exec(b64decode(…))` opens `~/.netrc` | yes | yes (decodes data, never execs) |
| write_outside | write attempt to `/home/sandbox/.bashrc` (EROFS) | yes | yes (writes in `/tmp`) |
| noisy_dependency | attribution: the dependency's `.pth` connect is **not** attributed to the target | yes (no connect) | n/a |
| timeout | `incomplete:timeout` | yes | n/a |
| import_failed | `incomplete:import_failed` | yes | n/a |
| real pip install | a real wheel install step has zero connects, subprocesses, outside writes or credential reads | yes | n/a |

Parser fuzzing: `tests/test_trace.py` (hypothesis) passes in the default unit-test run.

Note: installing a **wheel** runs no package code, so behaviour shows up at import time and through target `.pth` files, not in the install step. The fixture suite reflects that honestly; no fixture claims an install-time `connect()` from a wheel.

## Track C: end-to-end (demo repository PRs)

Cases: planted package, benign bump, unpinned spec, forced timeout, forced download failure. Target: the correct verdict and check outcome for every case, failing closed on every error case.

**Local dry run (2026-11-03, Windows + Docker Desktop, not `ubuntu-latest`).** These runs used `pipguard ci` on a local copy of `demo/template` and `pipguard scan` for the PyPI cases. The GitHub demo repository has not been pushed yet, so the CI timings below are still pending.

| Case | Expected verdict | Actual verdict (local) | Exit / check | Time (local) |
| --- | --- | --- | --- | --- |
| planted `requets==2.31.0` | block, ≥ 2 reasons | **block**. Reasons: credential file read plus subprocess/`connect()`; 1 edit from top-100 `requests`; raw IP `203.0.113.50` | 2 (fails) | about 68 s for the whole PR, including the next row |
| forced timeout `sleepy==1.0.0` | incomplete | **incomplete:timeout** (`import_s = 30`) | 3 (fails) | (included above) |
| unpinned `flask>=3` | warn | **warn**: not scanned, not an exact pin | 0 (passes) | under 1 s |
| benign bump `six==1.17.0` | allow | **allow** (with sandbox) | 0 (passes) | 21 s |
| download failure `six==99.0.0` | error | **error**: not found on PyPI | 3 (fails) | 3 s |

p50 / p95 scan time on `ubuntu-latest`: pending the demo repository run (`demo/make_prs.sh`).
