# Build log 07: evaluation scaffolding, Track A (Workstream F)

`scripts/eval/` (`fetch_corpus.sh`, `manifest.py`, `build_manifest.py`, `fetch_artifacts.py`, `batch_static.py`, `train.py`, `metrics.py`, `report.py`, `README.md`) and the `docs/EVAL.md` template. Commit `8bc5c44`.

**Status: scaffolding only. Track A has not been run.** There is no manifest content (`data/manifest.csv` holds a header only), no results, no trained model and no numbers. Every table in `docs/EVAL.md` reads "not yet run". Nothing in this log is a result.

## What was built

| PRD item | Where |
| --- | --- |
| Manifest with name, version, artifact, SHA-256, label, source, campaign group, band, split, fold, review | `scripts/eval/manifest.py`, `data/manifest.schema.json` |
| Malicious = Datadog archive + fetchable OpenSSF; benign = stratified top-5,000 bands + a random band | `build_manifest.py:153-238` |
| Payload dedup by normalised-source hash; campaign grouping; grouped splits; 50-sample manual review | `build_manifest.py:99-136`, `250-326` |
| Batch static runner, local only, resumable, fail closed | `batch_static.py` |
| Model ladder: rules → logistic regression → LightGBM (FR-5.2) | `train.py:258-312` |
| Thresholds on the validation fold at per-band FPR targets, stored with the model (FR-5.8) | `train.py:197-201`, `metrics.py:452-464` |
| Wilson CIs, per-band FPR, PR-AUC, calibration, rule precision | `metrics.py` |
| Render Track A into `docs/EVAL.md` | `report.py` |

## How it works

### Safety first

The Datadog dataset contains live malware in password-protected zips. The scripts treat samples as files only (`scripts/eval/README.md`, "Safety"):

- Samples live under `~/pipguard-data/`, outside the repo; `data/raw/`, `data/samples/` and `data/results/` are gitignored as a second fence.
- An encrypted zip is re-packed unencrypted inside the quarantine directory, copying bytes, names and mode bits unchanged, with the same 20,000-file and 500 MB caps enforced while decrypting (`build_manifest.py:50-70`). Then `pipguard.extract.safe_extract` applies its own checks (`build_manifest.py:73-93`). One hardened extractor for every archive.
- Hashing uses `ast.parse`/`ast.unparse`, which never runs code. Static features come from `pipguard.static.analyze_dir`.
- `batch_static.py` has no sandbox option and never imports `pipguard.sandbox`; a unit test enforces both. This is how FR-4.10 ("archived real-world malware is never executed") is enforced in code, not only in prose.
- Each temporary tree is deleted after use.

### Building the manifest (`build_manifest.py`)

- **Malicious, Datadog:** every `samples/pypi/<category>/<name>/<version>/*.zip`, hashed after extraction. A sample that fails to extract keeps its row with a `hash-error` note (`build_manifest.py:153-176`).
- **Malicious, OpenSSF:** PyPI OSV reports with explicit versions; rows start without an artifact, and `fetch_artifacts.py` downloads the ones still on PyPI through `pipguard.fetch` (polite, 1 s apart, resumable). Unfetchable rows become `excluded` with a `fetch-failed` note; the rest are the "fetchable count" (`build_manifest.py:179-208`, `fetch_artifacts.py`).
- **Benign:** seeded random sample from bands of the committed snapshot: top-100 (default 100), 101-1,000 (400), 1,001-5,000 (1,000), plus a random band of names outside the top 5,000 (500) from the full PyPI name list (`build_manifest.py:36`, `211-238`). A benign name that appears in a malicious set is excluded.
- **Payload dedup** (`build_manifest.py:99-124`): each `.py` file is normalised with `ast.unparse(ast.parse(...))` (comments and formatting gone; raw bytes on a syntax error), hashed, and the **sorted** file hashes hashed again. Paths are ignored, so a payload re-uploaded under a new package name still matches. Among identical malicious payloads, the first (Datadog first, then by name) is kept and the rest are `excluded: duplicate payload`.
- **Campaign groups** (`build_manifest.py:127-136`): samples whose largest normalised `.py` file (≥ 200 characters) is identical share a group. It is a heuristic, marked with a `ponytail:` comment naming near-duplicate clustering (for example MinHash) as the upgrade path.
- **Grouped splits** (`build_manifest.py:250-307`): a union-find joins rows that share a package name or a campaign group. Each connected component goes to the holdout when `sha256(seed:smallest name) % 100 < 20`, otherwise to fold `(hash // 100) % 5`. Hashing the component's smallest name makes the assignment deterministic, and adding unrelated rows never moves existing ones, so the holdout stays frozen.
- **Manual review sample:** 50 benign rows, round-robin across bands, marked `unreviewed` for the author to read and mark `ok` or `suspicious`. An existing review is never overwritten, and the script refuses to overwrite a non-empty manifest without `--force`.

### Static features over the corpus (`batch_static.py`)

For each non-excluded row with an artifact, extract into quarantine, run `static.analyze_dir` and `static.typosquat`, flatten with `features.static_vector`, and append one CSV row with `status`, `error` and `seconds`. Resumable by SHA-256. A failure is written as `status=error`, never dropped and never relabelled benign (`batch_static.py:59-75`).

**Metadata is blank for every row on purpose** (`batch_static.py:31-38`). Datadog samples have no PyPI metadata; giving benign rows real metadata would let the model learn "metadata present means benign", which is label leakage. Constant columns get a zero coefficient, so inference ignores them.

### The ladder (`train.py`)

Protocol (`train.py:1-15`):

- Folds 0-4 are the training split; fold 0 is the validation fold; the holdout is touched only to report.
- **Rung 1, rules alone.** `pipguard.rules` is evaluated on the holdout's static features (no behaviour), giving precision and recall for the blocking and warning classes separately, per-band FPR, and per-rule precision (`train.py:237-255`).
- **Rung 2, logistic regression.** `StandardScaler` + `LogisticRegression(class_weight="balanced")`; `C` from {0.01, 0.1, 1, 10} by grouped 5-fold CV on mean PR-AUC, ties to the smaller `C` (`train.py:105-120`). The final model fits on folds 1-4; Platt scaling is fitted on fold 0 in `scoring.py`'s convention `p = 1/(1+exp(a·z+b))` (`train.py:127-130`). LR is adopted if rules + LR (block if either blocks) has higher holdout recall than rules alone (`train.py:289-307`).
- **Rung 3, LightGBM.** 200 trees, 15 leaves, balanced classes, raw score. Adopted only if its holdout recall at its block threshold beats LR's by at least 3 points (`train.py:189-191`, `308`).
- **Thresholds** (`train.py:197-201`, `metrics.py:452-464`): block = the lowest validation score at which the FPR is ≤ 0.05 in **every** benign band (the worst band governs); warn = the same at 0.15, and never above block. The lowest qualifying threshold gives the highest recall. If nothing qualifies, 1.0.
- **Export.** The LR becomes a `ModelArtifact` with plain means, scales, coefficients, intercept, Platt parameters and thresholds, versioned `lr-YYYYMMDD-<manifest hash>` with the manifest SHA-256, snapshot date and training time (`train.py:137-154`, `365-383`). A LightGBM artifact, if adopted, is written to a separate file because `scoring.py` cannot run it yet. `ladder.json` holds every number for the report.
- Behavioural features are never used: Track A samples are never executed.

### Metrics (`metrics.py`)

Wilson score interval at 95% for every rate, with `k` and `n` (`metrics.py:20-34`); recall; per-band FPR; threshold selection; PR-AUC as average precision; a 10-bin reliability table; precision of a binary rule.

## Key design decisions

| Decision | Reason | Rejected alternative |
| --- | --- | --- |
| Static only for the corpus, enforced by a test | Live malware is never executed (FR-4.10); behaviour is measured only on fixtures and demo PRs | Running archived samples in the sandbox |
| Dedup on AST-normalised source, paths ignored | Campaigns re-upload the same payload under new names with cosmetic changes | Dedup on archive hash (every re-upload looks unique, inflating recall) |
| Split by name **and** campaign group via union-find | Near-identical samples in train and holdout would inflate every number | Random split, or split by version |
| Stable hash-based assignment | Adding data never reshuffles the frozen holdout | Re-randomising on every run |
| Benign bands plus a random band | FPR differs by popularity; the top 100 is not representative of what people add | One pooled benign set |
| Per-band FPR, worst band governs | A threshold that is fine on average can be noisy on one band | Pooled FPR |
| Blank metadata for all rows | Avoid "metadata present = benign" leakage | Real metadata for benign rows only |
| Wilson CIs with counts | Honest about small samples; a few hundred malicious samples give wide intervals | Point estimates only |
| Thresholds chosen on validation, reported on holdout | Choosing on the holdout would overfit the reported numbers | Tuning on the holdout |
| LightGBM only with ≥ 3 points recall gain | Prefer the interpretable model unless the gain is material | Always pick the best scorer |
| GuardDog not a feature | Much of the Datadog corpus was found with GuardDog (circularity) | Using GuardDog rules in the main model (FR-3.8 is P2, evaluated separately) |

## Limitations and known gaps

- **Not run.** No counts, recall, FPR, CIs, calibration or ablations exist yet.
- "Benign" means "not known to be malicious"; only 50 rows are manually reviewed.
- Campaign grouping is exact-match on the largest file; near-duplicates with small edits may straddle splits.
- **Typosquat leakage risk from the popular-package exemption.** Every benign row in the three snapshot bands is in the snapshot, so its typosquat features are always "no close name", while malicious samples are not exempt. The typosquat FPR on those bands is zero by construction, and the model may learn more from typosquat than real-world data justifies. The random band (names outside the top 5,000) is where the typosquat signal is honestly measured; the report should break this out.
- The LR adoption test compares holdout recall of rules + LR against rules alone; it does not separately check that the combined FPR still meets the per-band target.
- Benign packages are fetched at their latest version (sdist preferred), while malicious samples are whatever version was archived; differences in packaging era can be learnable.
- Datadog terms must be checked before publishing; only aggregate numbers are rendered.

## What the author must run (locally, never in CI)

From `scripts/eval/README.md`, after `uv sync`:

1. `bash scripts/eval/fetch_corpus.sh`: clones the Datadog and OpenSSF repos into `~/pipguard-data` and writes the PyPI name list. About 1-3 GB.
2. `uv run python -m scripts.eval.build_manifest --datadog ~/pipguard-data/datadog --ossf ~/pipguard-data/ossf --random-names ~/pipguard-data/pypi-names.txt` (tens of minutes).
3. `uv run python -m scripts.eval.fetch_artifacts --artifacts ~/pipguard-data/artifacts` (hours; prints the fetchable OpenSSF count).
4. Manually review the 50 `unreviewed` benign rows in `data/manifest.csv` (read the source; do not install) and commit the manifest.
5. `uv run python -m scripts.eval.batch_static --datadog ~/pipguard-data/datadog --artifacts ~/pipguard-data/artifacts` (PRD estimate under a day; resumable).
6. `uv run python -m scripts.eval.train --out src/pipguard/model/model.json` (minutes on CPU).
7. `uv run python -m scripts.eval.report` to fill Track A in `docs/EVAL.md`; check the Datadog terms before publishing.
8. Commit `data/manifest.csv`, the model artifact and `docs/EVAL.md`; never anything under `data/results/` or `~/pipguard-data/`.

Use a machine without real cloud credentials and keep antivirus from cleaning the quarantine directory mid-run.

## How it is tested

`tests/eval/` (unit, no network, synthetic data):

- `test_manifest.py`: CSV round trip, the committed manifest and schema match the model, invalid rows (for example a fold without `split=train`) are rejected.
- `test_build_manifest.py`: the normalised hash is stable under comments, whitespace and paths, and hashing never executes code; payload groups; decrypt-and-repack preserves names and link bits and enforces the size and count caps; extraction goes through `safe_extract`; Datadog, OpenSSF and stratified benign rows; exclusions and dedup; the review sample is kept; finalisation is deterministic and the holdout frozen; and a hypothesis test that a grouped split never leaks a name or group across splits.
- `test_fetch_artifacts.py`: success and recorded failure with a fake fetcher.
- `test_batch_static.py`: errors recorded, not dropped, and the run is resumable; extraction failure is an error row; the module never imports `pipguard.sandbox` and has no dynamic option.
- `test_metrics.py`: Wilson known values, per-band FPR, the worst band governs threshold selection, PR-AUC, calibration table.
- `test_train.py`: the exported LR matches scikit-learn's predictions, a constant feature gets zero weight, `C` selection, thresholds on separable data, the LightGBM adoption margin, the ladder with and without rules, both labels required, and an end-to-end `main`.
- `test_report.py`: required template sections, only the Track A section is replaced, missing markers rejected.

## Interview questions

**What exactly will Track A measure, and what will it not?**
Static classification of archived real-world malicious packages against a stratified sample of benign PyPI packages, using static features only. It will report recall at a per-band false-positive target with counts and 95% Wilson intervals, PR-AUC, calibration, blocking-rule precision and ablations. It will not measure behavioural detection, because those samples are never run; that is Track B on fixtures.

**How do you stop near-duplicate malware from inflating your numbers?**
Two layers. Payloads are deduplicated by hashing AST-normalised source with file paths ignored, so a re-upload under a new name is one sample. Then a union-find joins samples that share a package name or the same largest file, and each connected group goes into exactly one split, so a campaign cannot appear in both training and holdout.

**Why choose thresholds per popularity band?**
False-positive rates differ by band: very popular packages are well maintained and rarely odd, while long-tail packages vary a lot. A threshold chosen on the pooled set can look fine on average and still flag one band heavily. Requiring FPR ≤ 0.05 in every band means the worst band sets the threshold.

**Why are metadata features blank in training?**
The malicious samples come from an archive with no PyPI metadata, while benign packages would have real metadata. The model would then learn "has metadata means benign", which is a property of the dataset, not of malware. Blanking metadata for every row removes that shortcut, at the cost of not learning from release age or version count yet.

**When would you adopt LightGBM over logistic regression?**
Only if its recall at the block threshold on the holdout beats logistic regression by at least 3 points, as the PRD requires. Logistic regression is interpretable through its coefficients, cheap to run in pure Python, and easy to audit, so a more complex model has to earn its place. If LightGBM is adopted, `scoring.py` still needs inference support before it can be used.

**How do you keep live malware safe on your machine during evaluation?**
The samples stay encrypted on disk outside the repo, are decrypted only into a quarantine directory with size and count caps, extracted by the same hardened extractor as the scanner, parsed with `ast`, and deleted afterwards. The batch runner has no sandbox option and a test checks that it never imports the sandbox module. Nothing is installed, imported or executed.

**What is the weakest point of this evaluation design?**
The benign label: "not known to be malicious" is weak, and only 50 benign packages are manually reviewed. The popular-package typosquat exemption also makes the typosquat signal look perfect on the top-5,000 bands, so the random band is the honest test for it. These limits are stated in `docs/EVAL.md` rather than hidden.
