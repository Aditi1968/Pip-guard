"""Safe archive extraction (FR-2.3). Archives are untrusted input; nothing here executes them.

Every entry is checked *before* anything is written: the path must stay inside ``dest``,
links/devices/fifos are refused, and entry count plus declared sizes are capped. Zip bytes
are then counted while streaming, because a zip's declared ``file_size`` can lie (zip bombs).
On any failure ``dest`` is removed, so a half-extracted tree is never mistaken for a clean one.
"""

from __future__ import annotations

import shutil
import stat
import tarfile
import zipfile
import zlib
from pathlib import Path, PurePosixPath

from pipguard.errors import ExtractionError
from pipguard.models import FetchedPackage

MAX_COMPRESSED_BYTES = 100 * 1024 * 1024
MAX_EXTRACTED_BYTES = 500 * 1024 * 1024
MAX_ENTRIES = 20_000
_CHUNK = 64 * 1024

_ZIP_SUFFIXES = (".whl", ".zip")
_TAR_SUFFIXES = (".tar.gz", ".tgz", ".tar.bz2", ".tar")


def _safe_member_path(name: str, dest: Path) -> Path:
    """Map an archive entry name to a path inside ``dest``, or raise.

    Rejects absolute paths, ``..``, backslashes, drive letters / ``:`` (also blocks NTFS
    alternate data streams) and NUL, then double-checks the resolved path is under ``dest``.
    """
    if not name or "\\" in name or ":" in name or "\x00" in name or name.startswith("/"):
        raise ExtractionError(f"unsafe entry name: {name!r}")
    parts = [p for p in PurePosixPath(name).parts if p not in ("", ".")]
    if not parts or ".." in parts:
        raise ExtractionError(f"unsafe entry name: {name!r}")
    target = dest.joinpath(*parts)
    if not target.resolve().is_relative_to(dest.resolve()):
        raise ExtractionError(f"entry escapes destination: {name!r}")
    return target


def _check_count(n: int) -> None:
    if n > MAX_ENTRIES:
        raise ExtractionError(f"archive has more than {MAX_ENTRIES} entries")


def _check_total(total: int) -> None:
    if total > MAX_EXTRACTED_BYTES:
        raise ExtractionError(f"archive expands beyond {MAX_EXTRACTED_BYTES} bytes")


def _extract_zip(archive: Path, dest: Path) -> None:
    with zipfile.ZipFile(archive) as zf:
        infos = zf.infolist()
        _check_count(len(infos))
        plan: list[tuple[zipfile.ZipInfo, Path]] = []
        declared = 0
        for info in infos:
            # Unix mode lives in the high 16 bits. Many tools write only permission bits, so a
            # file-type field of 0 counts as a regular file.
            kind = stat.S_IFMT(info.external_attr >> 16)
            if kind == stat.S_IFLNK:
                raise ExtractionError(f"symlink entry: {info.filename!r}")
            if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ExtractionError(f"special file entry: {info.filename!r}")
            declared += info.file_size
            _check_total(declared)
            plan.append((info, _safe_member_path(info.filename, dest)))

        written = 0
        for info, target in plan:
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as out:
                while chunk := src.read(_CHUNK):
                    written += len(chunk)
                    _check_total(written)
                    out.write(chunk)


def _extract_tar(archive: Path, dest: Path) -> None:
    with tarfile.open(archive, "r:*") as tf:
        members: list[tarfile.TarInfo] = []
        declared = 0
        for m in tf:  # iterate (not getmembers) so the count cap stops a header flood early
            members.append(m)
            _check_count(len(members))
            if m.issym() or m.islnk():
                raise ExtractionError(f"link entry: {m.name!r}")
            if not (m.isreg() or m.isdir()):
                raise ExtractionError(f"special file entry: {m.name!r}")
            _safe_member_path(m.name, dest)
            declared += m.size
            _check_total(declared)
        # Tar member sizes are exact byte counts in the stream, so the declared total is the
        # real total. filter='data' is a second, independent line of defence.
        tf.extractall(dest, members=members, filter="data")


def safe_extract(archive: Path, dest: Path) -> Path:
    """Extract ``archive`` into ``dest`` (created; must be empty) and return ``dest``."""
    name = archive.name.lower()
    if name.endswith(_ZIP_SUFFIXES):
        extractor = _extract_zip
    elif name.endswith(_TAR_SUFFIXES):
        extractor = _extract_tar
    else:
        raise ExtractionError(f"unsupported archive type: {archive.name!r}")
    try:
        size = archive.stat().st_size
    except OSError as e:
        raise ExtractionError(f"cannot read archive {archive.name!r}: {e}") from e
    if size > MAX_COMPRESSED_BYTES:
        raise ExtractionError(f"archive is larger than {MAX_COMPRESSED_BYTES} bytes")
    if dest.exists() and any(dest.iterdir()):
        raise ExtractionError(f"destination is not empty: {dest}")
    dest.mkdir(parents=True, exist_ok=True)
    try:
        extractor(archive, dest)
    except ExtractionError:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    except (zipfile.BadZipFile, tarfile.TarError, zlib.error, EOFError, OSError, ValueError) as e:
        shutil.rmtree(dest, ignore_errors=True)
        raise ExtractionError(f"corrupt or unsafe archive {archive.name!r}: {e}") from e
    return dest


def extract_package(pkg: FetchedPackage, dest_root: Path) -> FetchedPackage:
    """Extract every scanned artifact (not ``declared_deps``) under ``dest_root``."""
    artifacts = [
        a.model_copy(
            update={"extracted_path": str(safe_extract(Path(a.path), dest_root / a.filename))}
        )
        for a in pkg.artifacts
    ]
    return pkg.model_copy(update={"artifacts": artifacts})
