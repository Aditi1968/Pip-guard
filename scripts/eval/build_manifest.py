"""Build ``data/manifest.csv`` from local dataset checkouts (PRD: "Labelling and splitting").

    python -m scripts.eval.build_manifest --datadog ~/pipguard-data/datadog \\
        [--ossf ~/pipguard-data/ossf] [--random-names random.txt] [--work-dir DIR]

Safety: samples are only read as files. Encrypted Datadog zips are decrypted into a plain zip
inside the quarantine work dir and then extracted by ``pipguard.extract.safe_extract`` -- one
hardened extractor for every archive -- and nothing extracted is imported or executed. Hashing
uses ``ast.parse``/``ast.unparse``, which never runs code.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import random
import shutil
import tempfile
import zipfile
from collections import defaultdict
from pathlib import Path

from pipguard.models import normalize_name
from scripts.eval.manifest import DATA, MANIFEST_CSV, ManifestRow, write_manifest

DATADOG_PASSWORD = "infected"  # published in the Datadog dataset README
MAX_FILES = 20_000  # same ceilings as extract.py (DESIGN.md), enforced while decrypting
MAX_BYTES = 500 * 1024 * 1024
ARCHIVE_SUFFIXES = (".whl", ".zip", ".tar.gz", ".tgz", ".tar.bz2")
PAYLOAD_MIN_CHARS = 200  # smaller files (empty __init__.py, stubs) say nothing about a campaign
HOLDOUT_PERCENT = 20
N_FOLDS = 5
REVIEW_SAMPLE = 50
DEFAULT_BANDS = {"top-100": 100, "101-1000": 400, "1001-5000": 1000, "random": 500}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


# ------------------------------------------------------------------ extraction (never executes)


def _decrypt_to_plain_zip(src: Path, out: Path, password: bytes) -> None:
    """Re-pack an encrypted zip unencrypted so ``safe_extract`` can apply its own checks.

    Only bytes are copied: entry names and mode bits (symlink flags included) pass through
    unchanged for ``safe_extract`` to reject; the size and count caps stop a bomb here.
    """
    total = 0
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout:
        infos = [i for i in zin.infolist() if not i.is_dir()]
        if len(infos) > MAX_FILES:
            raise ValueError(f"{src.name}: {len(infos)} entries > {MAX_FILES}")
        for info in infos:
            copy = zipfile.ZipInfo(info.filename, info.date_time)
            copy.external_attr = info.external_attr
            copy.compress_type = zipfile.ZIP_DEFLATED
            with zin.open(info, pwd=password) as r, zout.open(copy, "w") as w:
                while chunk := r.read(1 << 20):
                    total += len(chunk)
                    if total > MAX_BYTES:
                        raise ValueError(f"{src.name}: more than {MAX_BYTES} bytes uncompressed")
                    w.write(chunk)


def extract_sample(path: Path, dest: Path, password: str | None = None) -> Path:
    """Extract one sample under ``dest`` (an empty quarantine dir); return the tree root.

    Depends on ``pipguard.extract.safe_extract`` (Workstream A), imported lazily. A sample
    that is itself a single wrapped archive (e.g. a zip holding one ``.tar.gz``) is unwrapped
    once more, through the same extractor.
    """
    from pipguard.extract import safe_extract  # pyright: ignore[reportMissingImports]

    dest.mkdir(parents=True, exist_ok=True)
    if password is not None:
        plain = dest / "decrypted.zip"
        _decrypt_to_plain_zip(path, plain, password.encode())
        root = safe_extract(plain, dest / "tree")
        plain.unlink()
    else:
        root = safe_extract(path, dest / "tree")
    files = [p for p in root.rglob("*") if p.is_file()]
    if len(files) == 1 and files[0].name.lower().endswith(ARCHIVE_SUFFIXES):
        root = safe_extract(files[0], dest / "inner")
    return root


# ------------------------------------------------------------------ hashing (never executes)


def _normalized(src: bytes) -> bytes:
    """Source with comments and formatting removed; raw bytes if it does not parse."""
    try:
        return ast.unparse(ast.parse(src)).encode()
    except (SyntaxError, ValueError, RecursionError):
        return src


def normalized_file_hashes(root: Path) -> list[tuple[str, int]]:
    """``(sha256, normalised length)`` per ``.py`` file, sorted by path."""
    out = []
    for p in sorted(root.rglob("*.py")):
        if p.is_file() and not p.is_symlink():
            norm = _normalized(p.read_bytes())
            out.append((hashlib.sha256(norm).hexdigest(), len(norm)))
    return out


def normalized_source_hash(root: Path) -> str:
    """Payload identity: hash of the sorted per-file normalised hashes, "" with no ``.py``.

    File paths are left out on purpose so a payload re-uploaded under a new package name
    (``foo/__init__.py`` -> ``bar/__init__.py``) still deduplicates.
    """
    hashes = sorted(h for h, _ in normalized_file_hashes(root))
    return hashlib.sha256("\n".join(hashes).encode()).hexdigest() if hashes else ""


def payload_group(root: Path) -> str:
    """Campaign heuristic: the hash of the largest normalised ``.py`` file.

    Campaigns re-publish the same payload file (usually ``setup.py`` or ``__init__.py``) under
    many names with small changes elsewhere, so samples sharing their biggest file are put in
    one group. ponytail: exact-match only; near-duplicate clustering (e.g. MinHash) if leakage
    between groups shows up in error analysis.
    """
    files = [(n, h) for h, n in normalized_file_hashes(root) if n >= PAYLOAD_MIN_CHARS]
    return f"payload-{max(files)[1][:16]}" if files else ""


def hash_sample(path: Path, work_dir: Path, password: str | None) -> tuple[str, str]:
    """``(normalized_source_sha256, campaign_group)`` for one artifact; temp tree deleted."""
    work_dir.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(dir=work_dir))
    try:
        root = extract_sample(path, tmp / "x", password)
        return normalized_source_hash(root), payload_group(root)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ------------------------------------------------------------------ sources


def datadog_rows(root: Path, work_dir: Path, password: str = DATADOG_PASSWORD) -> list[ManifestRow]:
    """Every ``samples/pypi/<category>/<name>/<version>/*.zip`` in the Datadog checkout."""
    base = root / "samples" / "pypi"
    rows = []
    for z in sorted(base.rglob("*.zip")):
        notes = f"datadog:{z.relative_to(base).parts[0]}"
        try:
            norm, group = hash_sample(z, work_dir, password)
        except Exception as e:  # fail closed: keep the row, say why it has no hash
            norm, group, notes = "", "", f"{notes}; hash-error: {type(e).__name__}: {e}"[:300]
        rows.append(
            ManifestRow(
                name=z.parent.parent.name,
                version=z.parent.name,
                artifact_filename=z.relative_to(root).as_posix(),
                sha256=sha256_file(z),
                label="malicious",
                source="datadog",
                campaign_group=group,
                normalized_source_sha256=norm,
                notes=notes,
            )
        )
    return rows


def ossf_rows(root: Path, known: set[tuple[str, str]]) -> tuple[list[ManifestRow], int]:
    """PyPI OSV reports with explicit versions; ``(rows, reports skipped for no versions)``.

    Rows start without an artifact; ``fetch_artifacts`` downloads the still-fetchable ones.
    """
    seen = set(known)
    rows, skipped = [], 0
    for f in sorted((root / "osv" / "malicious" / "pypi").rglob("*.json")):
        report = json.loads(f.read_text(encoding="utf-8"))
        for aff in report.get("affected", []):
            pkg = aff.get("package", {})
            if pkg.get("ecosystem") != "PyPI" or not pkg.get("name"):
                continue
            if not aff.get("versions"):
                skipped += 1
                continue
            for v in aff["versions"]:
                key = (normalize_name(pkg["name"]), v)
                if key not in seen:
                    seen.add(key)
                    rows.append(
                        ManifestRow(
                            name=pkg["name"],
                            version=v,
                            label="malicious",
                            source="openssf",
                            notes=f"osv:{report.get('id', f.stem)}",
                        )
                    )
    return rows, skipped


def benign_rows(
    snapshot_names: list[str], random_names: list[str], sizes: dict[str, int], seed: int
) -> list[ManifestRow]:
    """Stratified benign sample: three snapshot bands plus a random band beyond top 5,000."""
    top = {normalize_name(n) for n in snapshot_names[:5000]}
    beyond = sorted({n for n in random_names if normalize_name(n) not in top})
    pools = {
        "top-100": snapshot_names[:100],
        "101-1000": snapshot_names[100:1000],
        "1001-5000": snapshot_names[1000:5000],
        "random": beyond,
    }
    rng = random.Random(seed)
    rows = []
    for band, pool in pools.items():
        for name in sorted(rng.sample(pool, min(sizes[band], len(pool)))):
            rows.append(
                ManifestRow(
                    name=name,
                    label="benign",
                    source="random-pypi" if band == "random" else "top-pypi",
                    popularity_band=band,  # type: ignore[arg-type]
                )
            )
    return rows


# ------------------------------------------------------------------ dedup, groups, splits


def _h(*parts: object) -> int:
    return int(hashlib.sha256(":".join(map(str, parts)).encode()).hexdigest(), 16)


def _with_note(notes: str, reason: str | None) -> str:
    kept = [n for n in notes.split("; ") if n and not n.startswith("excluded:")]
    return "; ".join([*kept, f"excluded: {reason}"] if reason else kept)


def finalize(rows: list[ManifestRow], seed: int = 0) -> list[ManifestRow]:
    """Exclusions, payload dedup, grouped splits and the review sample. Idempotent.

    Splits: a union-find joins rows that share a package name or a campaign group; each
    connected component lands in exactly one split. Assignment hashes the component's
    smallest name with the seed, so it is deterministic and does not reshuffle when
    unrelated rows are added (the holdout stays frozen).
    """
    mal_names = {normalize_name(r.name) for r in rows if r.label == "malicious"}
    reason: dict[int, str | None] = {}
    kept_payload: set[str] = set()
    order = sorted(
        range(len(rows)),
        key=lambda i: (rows[i].source != "datadog", rows[i].name, rows[i].version, rows[i].sha256),
    )
    for i in order:
        r = rows[i]
        reason[i] = None
        if "fetch-failed" in r.notes:
            reason[i] = "artifact not fetchable"
        elif r.label == "benign" and normalize_name(r.name) in mal_names:
            reason[i] = "benign name present in a malicious set"
        elif r.label == "malicious" and r.normalized_source_sha256:
            if r.normalized_source_sha256 in kept_payload:
                reason[i] = "duplicate payload"
            kept_payload.add(r.normalized_source_sha256)

    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    live = [i for i in range(len(rows)) if reason[i] is None]
    for i in live:
        a = find("n:" + normalize_name(rows[i].name))
        if rows[i].campaign_group:
            parent[find("g:" + rows[i].campaign_group)] = a
    comp_key: dict[str, str] = {}
    for i in live:
        root, name = find("n:" + normalize_name(rows[i].name)), normalize_name(rows[i].name)
        comp_key[root] = min(comp_key.get(root, name), name)

    out = []
    for i, r in enumerate(rows):
        upd: dict[str, object] = {"notes": _with_note(r.notes, reason[i])}
        if reason[i] is not None:
            upd |= {"split": "excluded", "fold": None}
        else:
            h = _h(seed, comp_key[find("n:" + normalize_name(r.name))])
            holdout = h % 100 < HOLDOUT_PERCENT
            upd |= {
                "split": "holdout" if holdout else "train",
                "fold": None if holdout else (h // 100) % N_FOLDS,
            }
        out.append(r.model_copy(update=upd))

    if not any(r.manual_review for r in out):  # never overwrite a review in progress
        by_band: dict[str, list[int]] = defaultdict(list)
        for i in sorted(range(len(out)), key=lambda i: _h(seed, "review", out[i].name)):
            if out[i].label == "benign" and out[i].split != "excluded":
                by_band[out[i].popularity_band].append(i)
        picked: list[int] = []
        while len(picked) < REVIEW_SAMPLE and any(by_band.values()):
            for band in sorted(by_band):
                if by_band[band] and len(picked) < REVIEW_SAMPLE:
                    picked.append(by_band[band].pop(0))
        for i in picked:
            out[i] = out[i].model_copy(update={"manual_review": "unreviewed"})
    # model_copy skips validation; re-validate so a broken invariant fails here, not later.
    return [ManifestRow.model_validate(r.model_dump()) for r in out]


# ------------------------------------------------------------------ CLI


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--datadog", type=Path, required=True, help="Datadog dataset checkout")
    p.add_argument("--ossf", type=Path, help="OpenSSF malicious-packages checkout (optional)")
    p.add_argument("--top-pypi", type=Path, default=DATA / "top-pypi-5000.json")
    p.add_argument(
        "--random-names",
        type=Path,
        help="text file, one PyPI name per line, to draw the random band from (e.g. a "
        "sample of https://pypi.org/simple/); names in the top 5,000 are dropped",
    )
    for band, n in DEFAULT_BANDS.items():
        p.add_argument(f"--band-{band}", type=int, default=n, dest=f"band_{band}")
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--password", default=DATADOG_PASSWORD)
    p.add_argument(
        "--work-dir",
        type=Path,
        default=Path.home() / "pipguard-data" / "quarantine",
        help="quarantine dir for temporary extraction (outside the repo)",
    )
    p.add_argument("--out", type=Path, default=MANIFEST_CSV)
    p.add_argument("--force", action="store_true", help="overwrite a non-empty manifest")
    args = p.parse_args(argv)

    has_rows = args.out.exists() and len(args.out.read_text(encoding="utf-8").splitlines()) > 1
    if has_rows and not args.force:
        p.error(f"{args.out} already has rows (manual reviews?); pass --force to rebuild")

    snapshot = json.loads(args.top_pypi.read_text(encoding="utf-8"))
    randoms = args.random_names.read_text(encoding="utf-8").split() if args.random_names else []
    rows = datadog_rows(args.datadog, args.work_dir, args.password)
    skipped = 0
    if args.ossf:
        known = {(normalize_name(r.name), r.version) for r in rows}
        extra, skipped = ossf_rows(args.ossf, known)
        rows += extra
    sizes = {band: getattr(args, f"band_{band}") for band in DEFAULT_BANDS}
    rows += benign_rows(snapshot["names"], randoms, sizes, args.seed)
    rows = finalize(rows, args.seed)
    write_manifest(rows, args.out)
    print(f"wrote {len(rows)} rows to {args.out} (snapshot {snapshot['snapshot_date']})")
    print(f"OpenSSF reports without explicit versions (skipped): {skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
