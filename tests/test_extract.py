import io
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from pipguard import extract
from pipguard.errors import ExtractionError
from pipguard.extract import _safe_member_path, extract_package, safe_extract
from pipguard.models import Artifact, ArtifactKind, FetchedPackage, PackageMetadata, PackageSpec
from scripts.make_wheel import build_wheel


def _zip(path: Path, entries: dict[str, bytes], mode: int = 0o100644) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zi = zipfile.ZipInfo(name)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = mode << 16
            zf.writestr(zi, data)
    return path


def _tar(path: Path, members: list[tuple[tarfile.TarInfo, bytes | None]]) -> Path:
    with tarfile.open(path, "w:gz") as tf:
        for info, data in members:
            if data is not None:
                info.size = len(data)
            tf.addfile(info, io.BytesIO(data) if data is not None else None)
    return path


def _info(name: str, kind: bytes = tarfile.REGTYPE, linkname: str = "") -> tarfile.TarInfo:
    ti = tarfile.TarInfo(name)
    ti.type = kind
    ti.linkname = linkname
    return ti


def test_happy_wheel(tmp_path: Path) -> None:
    whl = build_wheel(tmp_path, "demo", "1.0", {"demo/__init__.py": "X = 1\n"})
    out = safe_extract(whl, tmp_path / "out")
    assert (out / "demo" / "__init__.py").read_text() == "X = 1\n"
    assert (out / "demo-1.0.dist-info" / "METADATA").exists()


def test_happy_sdist(tmp_path: Path) -> None:
    sdist = _tar(
        tmp_path / "demo-1.0.tar.gz",
        [
            (_info("demo-1.0", tarfile.DIRTYPE), None),
            (_info("demo-1.0/setup.py"), b"print('never run')\n"),
        ],
    )
    out = safe_extract(sdist, tmp_path / "out")
    assert (out / "demo-1.0" / "setup.py").read_bytes() == b"print('never run')\n"


@pytest.mark.parametrize(
    "name", ["../evil", "/abs", "C:\\evil", "C:/evil", "a/../../b", "a\\..\\b"]
)
def test_zip_traversal_rejected(tmp_path: Path, name: str) -> None:
    arc = _zip(tmp_path / "x.zip", {"ok.txt": b"ok", name: b"evil"})
    dest = tmp_path / "out"
    with pytest.raises(ExtractionError):
        safe_extract(arc, dest)
    assert not dest.exists()  # nothing left behind to be trusted later
    assert not (tmp_path / "evil").exists()


@pytest.mark.parametrize("name", ["../evil", "/abs", "a/../../b"])
def test_tar_traversal_rejected(tmp_path: Path, name: str) -> None:
    arc = _tar(tmp_path / "x.tar.gz", [(_info(name), b"evil")])
    with pytest.raises(ExtractionError):
        safe_extract(arc, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_zip_symlink_rejected(tmp_path: Path) -> None:
    arc = _zip(tmp_path / "x.whl", {"link": b"/etc/passwd"}, mode=stat.S_IFLNK | 0o777)
    with pytest.raises(ExtractionError, match="symlink"):
        safe_extract(arc, tmp_path / "out")


def test_zip_fifo_rejected(tmp_path: Path) -> None:
    arc = _zip(tmp_path / "x.zip", {"pipe": b""}, mode=stat.S_IFIFO | 0o644)
    with pytest.raises(ExtractionError, match="special"):
        safe_extract(arc, tmp_path / "out")


def test_zip_without_unix_mode_is_fine(tmp_path: Path) -> None:
    arc = _zip(tmp_path / "x.zip", {"a.txt": b"a"}, mode=0)
    assert (safe_extract(arc, tmp_path / "out") / "a.txt").read_bytes() == b"a"


@pytest.mark.parametrize(
    ("member", "match"),
    [
        (_info("link", tarfile.SYMTYPE, "/etc/passwd"), "link"),
        (_info("hard", tarfile.LNKTYPE, "a.txt"), "link"),
        (_info("dev", tarfile.CHRTYPE), "special"),
        (_info("blk", tarfile.BLKTYPE), "special"),
        (_info("fifo", tarfile.FIFOTYPE), "special"),
    ],
)
def test_tar_links_and_devices_rejected(
    tmp_path: Path, member: tarfile.TarInfo, match: str
) -> None:
    arc = _tar(tmp_path / "x.tar.gz", [(_info("a.txt"), b"a"), (member, None)])
    with pytest.raises(ExtractionError, match=match):
        safe_extract(arc, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_too_many_entries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(extract, "MAX_ENTRIES", 3)
    files = {f"f{i}": b"x" for i in range(4)}
    with pytest.raises(ExtractionError, match="entries"):
        safe_extract(_zip(tmp_path / "x.zip", files), tmp_path / "a")
    arc = _tar(tmp_path / "x.tar", [(_info(n), d) for n, d in files.items()])
    with pytest.raises(ExtractionError, match="entries"):
        safe_extract(arc, tmp_path / "b")


def test_zip_bomb_declared_size(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(extract, "MAX_EXTRACTED_BYTES", 1_000_000)
    arc = _zip(tmp_path / "bomb.zip", {"zeros": b"\0" * 2_000_000})
    assert arc.stat().st_size < 50_000  # highly compressible
    with pytest.raises(ExtractionError, match="expands"):
        safe_extract(arc, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_zip_bomb_lying_declared_size(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Central directory claims 10 bytes; the stream holds 2 MB. Must never be trusted."""
    monkeypatch.setattr(extract, "MAX_EXTRACTED_BYTES", 1_000_000)
    arc = _zip(tmp_path / "bomb.zip", {"zeros": b"\0" * 2_000_000})
    raw = bytearray(arc.read_bytes())
    real = (2_000_000).to_bytes(4, "little")
    # Patch uncompressed size in both the local header and the central directory.
    assert raw.count(real) == 2
    arc.write_bytes(bytes(raw).replace(real, (10).to_bytes(4, "little")))
    with zipfile.ZipFile(arc) as zf:
        assert zf.infolist()[0].file_size == 10
    with pytest.raises(ExtractionError):
        safe_extract(arc, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_streamed_bytes_are_counted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Even if declared sizes passed, the running byte count enforces the cap."""
    arc = _zip(tmp_path / "x.zip", {"a": b"a" * 100_000})
    real_check = extract._check_total
    calls: list[int] = []

    def check(total: int) -> None:
        calls.append(total)
        if len(calls) > 1:  # let the declared-size pass through, trip on streaming
            monkeypatch.setattr(extract, "MAX_EXTRACTED_BYTES", 10)
        real_check(total)

    monkeypatch.setattr(extract, "_check_total", check)
    with pytest.raises(ExtractionError, match="expands"):
        safe_extract(arc, tmp_path / "out")


def test_tar_bomb_declared_size(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(extract, "MAX_EXTRACTED_BYTES", 1_000)
    arc = _tar(tmp_path / "x.tgz", [(_info("big"), b"\0" * 2_000)])
    with pytest.raises(ExtractionError, match="expands"):
        safe_extract(arc, tmp_path / "out")


def test_compressed_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(extract, "MAX_COMPRESSED_BYTES", 10)
    arc = _zip(tmp_path / "x.zip", {"a": b"a"})
    with pytest.raises(ExtractionError, match="larger"):
        safe_extract(arc, tmp_path / "out")


def test_corrupt_and_unsupported(tmp_path: Path) -> None:
    bad = tmp_path / "bad.whl"
    bad.write_bytes(b"not a zip")
    with pytest.raises(ExtractionError, match="corrupt"):
        safe_extract(bad, tmp_path / "out")
    assert not (tmp_path / "out").exists()
    with pytest.raises(ExtractionError, match="unsupported"):
        safe_extract(tmp_path / "x.rar", tmp_path / "out")


def test_refuses_non_empty_dest(tmp_path: Path) -> None:
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "keep").write_text("mine")
    with pytest.raises(ExtractionError, match="not empty"):
        safe_extract(_zip(tmp_path / "x.zip", {"a": b"a"}), tmp_path / "out")
    assert (tmp_path / "out" / "keep").exists()


def test_extract_package(tmp_path: Path) -> None:
    whl = build_wheel(tmp_path / "dl", "demo", "1.0", {"demo/__init__.py": ""})
    art = Artifact(
        filename=whl.name, kind=ArtifactKind.WHEEL, sha256="0" * 64, size=1, path=str(whl)
    )
    pkg = FetchedPackage(
        spec=PackageSpec(name="demo", version="1.0"),
        artifacts=[art],
        metadata=PackageMetadata(),
        origin="pypi",
    )
    out = extract_package(pkg, tmp_path / "x")
    assert pkg.artifacts[0].extracted_path is None  # original untouched (frozen models)
    extracted = out.artifacts[0].extracted_path
    assert extracted and (Path(extracted) / "demo" / "__init__.py").exists()


@settings(max_examples=300, deadline=None)
@given(st.text(alphabet=st.sampled_from(list("ab./\\:C\x00 ")), min_size=0, max_size=20))
def test_entry_names_never_escape(tmp_path_factory: pytest.TempPathFactory, name: str) -> None:
    dest = tmp_path_factory.getbasetemp() / "hyp"
    try:
        target = _safe_member_path(name, dest)
    except ExtractionError:
        return
    assert target.resolve().is_relative_to(dest.resolve())
    assert target.resolve() != dest.resolve()
