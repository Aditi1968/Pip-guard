# Track A evaluation: how to run it locally

Static classification of real-world malicious packages against a stratified benign sample (PRD "Data, ML and evaluation", FR-5.2, FR-5.8). Everything here runs on your machine, never in CI, and costs nothing.

## Safety (read before step 1)

- The Datadog dataset holds **live malware** in password-protected zips (password `infected`, from its README). Leave them zipped. Never unzip, `pip install`, import or run a sample by hand.
- Samples live **outside the repo**, under `~/pipguard-data/` (override with `PIPGUARD_DATA` for the download script). They are never committed or redistributed. `data/raw/`, `data/samples/` and `data/results/` are gitignored as a second fence.
- The scripts treat samples as files only: encrypted zips are re-packed unencrypted inside the quarantine dir and extracted by `pipguard.extract.safe_extract` (path traversal, link, size and count checks), then parsed with `ast`. Nothing is executed. `batch_static.py` has no sandbox option and never imports `pipguard.sandbox` (a unit test enforces this): real-world corpus samples are **static only** (FR-4.10).
- Extraction happens in a quarantine dir (`~/pipguard-data/quarantine`, `--work-dir`) and each temporary tree is deleted after use. Prefer a machine without real cloud credentials, and keep antivirus from "cleaning" the quarantine dir mid-run (exclude it, or expect `status=error` rows).
- A sample whose extraction or analysis fails is recorded with `status=error` and counted in the report. It is never dropped or treated as benign.

## Steps

Run from the repo root after `uv sync`.

1. **Download the sources** (clones and downloads only; about 1-3 GB):

   ```bash
   bash scripts/eval/fetch_corpus.sh
   ```

   Equivalent by hand:

   ```bash
   git clone --depth 1 https://github.com/DataDog/malicious-software-packages-dataset ~/pipguard-data/datadog
   git clone --depth 1 https://github.com/ossf/malicious-packages ~/pipguard-data/ossf
   ```

   The script also writes `~/pipguard-data/pypi-names.txt` (every PyPI project name), the sampling frame for the random benign band. The top-5,000 snapshot `data/top-pypi-5000.json` (`{"snapshot_date", "source", "names"}`) is already committed.

2. **Build the manifest** (extracts every Datadog sample once to hash it; tens of minutes):

   ```bash
   uv run python -m scripts.eval.build_manifest \
     --datadog ~/pipguard-data/datadog \
     --ossf ~/pipguard-data/ossf \
     --random-names ~/pipguard-data/pypi-names.txt
   ```

   Band sizes default to 100 / 400 / 1,000 / 500 (`--band-top-100`, `--band-101-1000`, `--band-1001-5000`, `--band-random`); `--seed` (default 0) makes sampling and splits deterministic. It refuses to overwrite a manifest that already has rows unless you pass `--force` (it would discard manual reviews).

3. **Download OpenSSF and benign artifacts** through `pipguard.fetch` (polite, 1 s between packages; resumable; a few hours):

   ```bash
   uv run python -m scripts.eval.fetch_artifacts --artifacts ~/pipguard-data/artifacts
   ```

   It prints the fetchable OpenSSF count. Unfetchable rows get `fetch-failed: ...` in `notes` and become `excluded`; rerunning retries them.

4. **Manually review the 50 benign rows** with `manual_review=unreviewed` in `data/manifest.csv`: read the source (do not install), set `ok` or `suspicious`, and commit the manifest.

5. **Static analysis over the corpus** (PRD estimate 5-15 s per package, about 4,000-5,000 artifacts: under a day; resumable, so stop and restart freely):

   ```bash
   uv run python -m scripts.eval.batch_static \
     --datadog ~/pipguard-data/datadog --artifacts ~/pipguard-data/artifacts
   ```

   Results go to `data/results/static_features.csv` (gitignored), one row per artifact with `status`, `error` and `seconds`.

6. **Train the model ladder and choose thresholds** (minutes on CPU):

   ```bash
   uv run python -m scripts.eval.train --out src/pipguard/model/model.json
   ```

   Writes the `ModelArtifact` (LR coefficients, scaler, Platt parameters, thresholds, manifest hash, snapshot date, `model_version` `lr-YYYYMMDD-<manifest hash>`) and `data/results/ladder.json`. If LightGBM is adopted it is written next to it as `model-lightgbm.json`; `scoring.py` must gain LightGBM inference before that file can be used.

7. **Render the report**:

   ```bash
   uv run python -m scripts.eval.report
   ```

   Replaces only the Track A section of `docs/EVAL.md`. Check the Datadog terms before publishing it (aggregates only, never per-sample numbers).

8. Commit `data/manifest.csv`, the model artifact and `docs/EVAL.md`. Never commit anything under `data/results/` or `~/pipguard-data/`.

## What the scripts do

| Script | Role |
| --- | --- |
| `manifest.py` | `ManifestRow` (pydantic), CSV read/write, `--write-schema` regenerates `data/manifest.schema.json` |
| `build_manifest.py` | Labels, payload dedup (`normalized_source_hash`), campaign groups, grouped splits, review sample |
| `fetch_artifacts.py` | Downloads OpenSSF/benign artifacts via `pipguard.fetch`, records hashes |
| `batch_static.py` | Static features for each artifact, resumable, fail closed |
| `train.py` | Rules -> logistic regression -> LightGBM ladder, thresholds, `ModelArtifact` export |
| `metrics.py` | Wilson CI, per-band FPR, threshold selection, PR-AUC, calibration table, rule precision |
| `report.py` | Renders Track A of `docs/EVAL.md` |

Design choices worth knowing:

- **Dedup**: each `.py` file is normalised with `ast.unparse(ast.parse(...))` (comments and formatting gone; raw bytes on a syntax error), hashed, and the sorted file hashes are hashed again. Paths are ignored so a payload re-uploaded under another name still matches. Among identical malicious payloads the first (Datadog first, then by name) is kept and the rest are `excluded: duplicate payload`.
- **Campaign groups** (heuristic): samples whose largest normalised `.py` file (>= 200 characters) is identical share a group. Splits union package names and campaign groups, so a name or a group never lands in two splits.
- **Splits**: each group component goes to the holdout when `sha256(seed:smallest name) % 100 < 20`, otherwise to fold `(hash // 100) % 5`. Adding unrelated rows never moves existing ones, so the holdout stays frozen.
- **Metadata is blank for every row**: Datadog samples have no PyPI metadata, so using it for benign rows only would leak the label.
- **Validation fold** is fold 0: models fit on folds 1-4, Platt scaling and thresholds use fold 0, the holdout is used only to report.
- **Thresholds**: block = lowest score with FPR <= 0.05 in every benign band (worst band governs); warn uses 0.15.
