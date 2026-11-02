"""Download OpenSSF and benign artifacts named in the manifest, via ``pipguard.fetch``.

    python -m scripts.eval.fetch_artifacts --artifacts ~/pipguard-data/artifacts

Downloads only: files are hashed and extracted with ``safe_extract`` to compute the payload
hash, never installed or imported. Resumable: rows that already have a SHA-256 are skipped.
The sdist is preferred (closest to the Datadog samples, which are source trees), else the wheel.
A failure is recorded as ``fetch-failed: ...`` in ``notes`` and the row becomes ``excluded``;
the OpenSSF rows that succeed are the "fetchable count" the report quotes.
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.request
from pathlib import Path

from pipguard.models import FetchedPackage, PackageSpec, normalize_name
from scripts.eval.build_manifest import finalize, hash_sample, sha256_file
from scripts.eval.manifest import MANIFEST_CSV, ManifestRow, read_manifest, write_manifest


def _latest_version(name: str) -> str:
    url = f"https://pypi.org/pypi/{normalize_name(name)}/json"
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.load(r)["info"]["version"]


def _fetch(spec: PackageSpec, dest: Path) -> FetchedPackage:
    """Adapter for Workstream A's ``pipguard.fetch.fetch(spec, dest)``; imported lazily."""
    from pipguard.fetch import fetch  # pyright: ignore[reportMissingImports]

    return fetch(spec, dest)


def fetch_row(row: ManifestRow, artifacts: Path, work_dir: Path) -> ManifestRow:
    """Fill version/artifact/sha256/hashes for one row; a failure goes into ``notes``."""
    notes = "; ".join(n for n in row.notes.split("; ") if n and not n.startswith("fetch-failed"))
    try:
        version = row.version or _latest_version(row.name)
        dest = artifacts / f"{normalize_name(row.name)}-{version}"
        pkg = _fetch(PackageSpec(name=row.name, version=version), dest)
        art = pkg.sdist or pkg.wheel
        if art is None:
            raise ValueError("no sdist or wheel")
        path = Path(art.path)
        if sha256_file(path) != art.sha256:
            raise ValueError("sha256 mismatch after download")
        rel = path.resolve().relative_to(artifacts.resolve()).as_posix()
        norm, group = hash_sample(path, work_dir, None)
    except Exception as e:
        failed = f"fetch-failed: {type(e).__name__}: {e}"[:300]
        return row.model_copy(update={"notes": "; ".join(filter(None, [notes, failed]))})
    return row.model_copy(
        update={
            "version": version,
            "artifact_filename": rel,
            "sha256": art.sha256,
            "normalized_source_sha256": norm,
            # Benign rows are grouped by name only; payload groups are a malicious-campaign idea.
            "campaign_group": group if row.label == "malicious" else "",
            "notes": notes,
        }
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--artifacts", type=Path, default=Path.home() / "pipguard-data" / "artifacts")
    p.add_argument("--work-dir", type=Path, default=Path.home() / "pipguard-data" / "quarantine")
    p.add_argument("--manifest", type=Path, default=MANIFEST_CSV)
    p.add_argument("--delay", type=float, default=1.0, help="seconds between PyPI requests")
    p.add_argument("--seed", type=int, default=0, help="must match build_manifest --seed")
    args = p.parse_args(argv)

    rows = read_manifest(args.manifest)
    todo = [i for i, r in enumerate(rows) if r.source != "datadog" and not r.sha256]
    for n, i in enumerate(todo, 1):
        rows[i] = fetch_row(rows[i], args.artifacts, args.work_dir)
        print(f"[{n}/{len(todo)}] {rows[i].name} {rows[i].version or '?'} {rows[i].notes}")
        if n % 25 == 0:  # checkpoint so an interrupted run resumes
            write_manifest(rows, args.manifest)
        time.sleep(args.delay)
    rows = finalize(rows, args.seed)
    write_manifest(rows, args.manifest)
    ok = sum(r.source == "openssf" and bool(r.sha256) for r in rows)
    print(f"fetchable OpenSSF artifacts: {ok} / {sum(r.source == 'openssf' for r in rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
