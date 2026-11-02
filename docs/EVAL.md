# pip guard evaluation

Three tracks, never mixed: each number is reported only for the population it was measured on (PRD "Data, ML and evaluation"). How to reproduce: `scripts/eval/README.md`.

**Status: not yet run.** Every table below is a placeholder until the local evaluation has been run.

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

Not yet run. Each suspicious fixture is paired with a benign counterexample that uses the same API legitimately. Target: every expected observation detected, no counterexample flagged, parser fuzz tests pass (100%, deterministic).

| Fixture | Expected observation | Detected | Counterexample clean |
| --- | --- | --- | --- |
| not yet run | | | |

## Track C: end-to-end (demo repository PRs)

Not yet run. Cases: planted package, benign bump, unpinned spec, forced timeout, forced download failure. Target: correct verdict and check outcome for every case, fail-closed on every error case.

| Case | Expected verdict | Actual verdict | Check outcome | Time |
| --- | --- | --- | --- | --- |
| not yet run | | | | |

p50 / p95 scan time: not yet run.
