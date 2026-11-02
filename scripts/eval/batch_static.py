"""Static analysis over the corpus, appended to ``data/results/static_features.csv``.

    python -m scripts.eval.batch_static --datadog ~/pipguard-data/datadog \\
        --artifacts ~/pipguard-data/artifacts

STATIC ONLY (PRD FR-4.10): this module extracts files and parses them with ``ast``. It has no
sandbox or dynamic option and never imports ``pipguard.sandbox``; a test enforces both.
Resumable: an artifact whose SHA-256 is already in the results file is skipped. Fail closed:
a sample whose analysis fails is written with ``status=error``, never dropped or relabelled.
"""

from __future__ import annotations

import argparse
import csv
import shutil
import tempfile
import time
from pathlib import Path

from pipguard.features import STATIC_FEATURE_NAMES, static_vector
from pipguard.models import ArtifactKind, PackageMetadata, PackageSpec, StaticFeatures
from scripts.eval.build_manifest import DATADOG_PASSWORD, extract_sample
from scripts.eval.manifest import DATA, MANIFEST_CSV, ManifestRow, read_manifest

RESULTS_CSV = DATA / "results" / "static_features.csv"
META = ["sha256", "name", "version", "label", "status", "error", "seconds"]
COLUMNS = [*META, *STATIC_FEATURE_NAMES, "static_features_json"]


def _static_features_for(root: Path, row: ManifestRow) -> StaticFeatures:
    """The only call into Workstream B's ``pipguard.static`` (imported lazily).

    Metadata is left empty for every row on purpose: Datadog samples have no PyPI metadata,
    so real metadata on benign rows only would let the model learn "metadata present =
    benign" (leakage). Constant columns get a zero coefficient, so inference ignores them.
    """
    import pipguard.static as static  # pyright: ignore[reportMissingImports]

    filename = Path(row.artifact_filename).name
    kind = ArtifactKind.WHEEL if filename.endswith(".whl") else ArtifactKind.SDIST
    return StaticFeatures(
        spec=PackageSpec(name=row.name, version=row.version),
        artifacts=[static.analyze_dir(root, filename, row.sha256, kind)],
        typosquat=static.typosquat(row.name, static.default_top_packages()),
        metadata=PackageMetadata(),
    )


def analyze_row(row: ManifestRow, path: Path, work_dir: Path, password: str | None) -> dict:
    """One results record; any failure becomes ``status=error`` with the reason."""
    t0 = time.perf_counter()
    rec: dict = {"sha256": row.sha256, "name": row.name, "version": row.version}
    rec |= {"label": row.label, "status": "ok", "error": ""}
    work_dir.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(dir=work_dir))
    try:
        sf = _static_features_for(extract_sample(path, tmp / "x", password), row)
        rec |= static_vector(sf)
        rec["static_features_json"] = sf.model_dump_json()
    except Exception as e:
        rec |= {"status": "error", "error": f"{type(e).__name__}: {e}"[:500]}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    rec["seconds"] = round(time.perf_counter() - t0, 3)
    return rec


def done_hashes(results: Path) -> set[str]:
    if not results.exists():
        return set()
    csv.field_size_limit(2**31 - 1)
    with results.open(newline="", encoding="utf-8") as f:
        return {r["sha256"] for r in csv.DictReader(f)}


def locate(row: ManifestRow, datadog: Path | None, artifacts: Path) -> tuple[Path, str | None]:
    """Local path of a row's artifact and the zip password it needs (Datadog only)."""
    if row.source == "datadog":
        if datadog is None:
            return Path("/nonexistent"), None
        return datadog / row.artifact_filename, DATADOG_PASSWORD
    return artifacts / row.artifact_filename, None


def run(
    rows: list[ManifestRow],
    datadog: Path | None,
    artifacts: Path,
    work_dir: Path,
    results: Path = RESULTS_CSV,
) -> tuple[int, int]:
    """Analyse every pending row whose artifact exists; return ``(analysed, missing)``."""
    done = done_hashes(results)
    results.parent.mkdir(parents=True, exist_ok=True)
    new_file = not results.exists()
    analysed = missing = 0
    with results.open("a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS, restval="", lineterminator="\n")
        if new_file:
            w.writeheader()
        for row in rows:
            if row.split == "excluded" or not row.sha256 or row.sha256 in done:
                continue
            path, password = locate(row, datadog, artifacts)
            if not path.is_file():
                missing += 1
                continue
            rec = analyze_row(row, path, work_dir, password)
            w.writerow(rec)
            f.flush()
            done.add(row.sha256)
            analysed += 1
            print(f"{rec['status']:5} {rec['seconds']:7.2f}s {row.name} {row.version}")
    return analysed, missing


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--datadog", type=Path, help="Datadog dataset checkout")
    p.add_argument("--artifacts", type=Path, default=Path.home() / "pipguard-data" / "artifacts")
    p.add_argument("--work-dir", type=Path, default=Path.home() / "pipguard-data" / "quarantine")
    p.add_argument("--manifest", type=Path, default=MANIFEST_CSV)
    p.add_argument("--results", type=Path, default=RESULTS_CSV)
    args = p.parse_args(argv)
    analysed, missing = run(
        read_manifest(args.manifest), args.datadog, args.artifacts, args.work_dir, args.results
    )
    print(f"analysed {analysed}; artifacts not found locally: {missing}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
