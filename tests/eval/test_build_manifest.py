import json
import zipfile
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from scripts.eval import build_manifest as bm
from scripts.eval.manifest import ManifestRow

PAYLOAD = "import os\n" + "\n".join(f"x{i} = os.environ.get('K{i}')" for i in range(20)) + "\n"


def _tree(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


# ------------------------------------------------------------------ hashing


def test_hash_stable_under_comments_whitespace_and_paths(tmp_path: Path) -> None:
    a = _tree(tmp_path / "a", {"foo/__init__.py": "x = 1\ny = [1,2]\n"})
    b = _tree(tmp_path / "b", {"bar/__init__.py": "# hi\nx   =   1  # c\n\ny = [1,\n  2]\n"})
    c = _tree(tmp_path / "c", {"foo/__init__.py": "x = 2\ny = [1,2]\n"})
    assert bm.normalized_source_hash(a) == bm.normalized_source_hash(b)
    assert bm.normalized_source_hash(a) != bm.normalized_source_hash(c)
    assert bm.normalized_source_hash(_tree(tmp_path / "d", {"README": "x"})) == ""


def test_hash_never_executes(tmp_path: Path) -> None:
    root = _tree(
        tmp_path / "t",
        {
            "setup.py": "raise SystemExit('executed!')\n",
            "boom.py": "import os\nos._exit(3)\n",
            "bad.py": "def (:\n",  # syntax error falls back to raw bytes
        },
    )
    assert len(bm.normalized_source_hash(root)) == 64
    assert len(bm.normalized_file_hashes(root)) == 3


def test_payload_group(tmp_path: Path) -> None:
    a = _tree(tmp_path / "a", {"a/setup.py": PAYLOAD, "a/__init__.py": ""})
    b = _tree(tmp_path / "b", {"b/setup.py": "# copy\n" + PAYLOAD, "b/x.py": "y = 2\n"})
    assert bm.payload_group(a) == bm.payload_group(b) != ""
    assert bm.payload_group(_tree(tmp_path / "c", {"c.py": "x = 1\n"})) == ""


# ------------------------------------------------------------------ extraction


def _zip(path: Path, entries: dict[str, bytes], symlink: str | None = None) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = 0o120777 << 16
            zf.writestr(info, "/etc/passwd")
    return path


def test_decrypt_repack_preserves_names_and_link_bits(tmp_path: Path) -> None:
    src = _zip(tmp_path / "s.zip", {"pkg/a.py": b"x = 1\n", "../evil.py": b"y"}, symlink="lnk")
    out = tmp_path / "plain.zip"
    bm._decrypt_to_plain_zip(src, out, b"infected")
    with zipfile.ZipFile(out) as zf:
        infos = {i.filename: i for i in zf.infolist()}
        assert set(infos) == {"pkg/a.py", "../evil.py", "lnk"}
        assert not any(i.flag_bits & 0x1 for i in infos.values())  # not encrypted
        assert infos["lnk"].external_attr >> 16 == 0o120777  # safe_extract still sees the link
        assert zf.read("pkg/a.py") == b"x = 1\n"
    assert not (tmp_path / "evil.py").exists()  # nothing written outside the zip


def test_decrypt_repack_size_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bm, "MAX_BYTES", 10)
    src = _zip(tmp_path / "s.zip", {"a.py": b"x" * 100})
    with pytest.raises(ValueError, match="bytes"):
        bm._decrypt_to_plain_zip(src, tmp_path / "o.zip", b"pw")


def test_decrypt_repack_count_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bm, "MAX_FILES", 1)
    src = _zip(tmp_path / "s.zip", {"a.py": b"", "b.py": b""})
    with pytest.raises(ValueError, match="entries"):
        bm._decrypt_to_plain_zip(src, tmp_path / "o.zip", b"pw")


def test_extract_sample_goes_through_safe_extract(tmp_path: Path, fake_extract: list) -> None:
    inner = _zip(tmp_path / "pkg-1.0.whl", {"pkg/__init__.py": b"x = 1\n"})
    outer = _zip(tmp_path / "s.zip", {"pkg-1.0.whl": inner.read_bytes()})
    root = bm.extract_sample(outer, tmp_path / "q", password="infected")
    assert (root / "pkg" / "__init__.py").is_file()  # wrapped archive unwrapped once
    assert len(fake_extract) == 2
    assert not (tmp_path / "q" / "decrypted.zip").exists()


def test_extract_sample_requires_extract_module(tmp_path: Path, monkeypatch) -> None:
    import sys

    monkeypatch.setitem(sys.modules, "pipguard.extract", None)
    with pytest.raises(ImportError):
        bm.extract_sample(_zip(tmp_path / "s.zip", {"a.py": b""}), tmp_path / "q")


# ------------------------------------------------------------------ sources


def test_datadog_rows(tmp_path: Path, fake_extract: list) -> None:
    base = tmp_path / "dd" / "samples" / "pypi" / "malicious_intent"
    (base / "evil" / "1.0").mkdir(parents=True)
    (base / "evil2" / "0.1").mkdir(parents=True)
    _zip(base / "evil" / "1.0" / "2023-evil-v1.0.zip", {"evil/setup.py": PAYLOAD.encode()})
    (base / "evil2" / "0.1" / "broken.zip").write_bytes(b"not a zip")
    rows = bm.datadog_rows(tmp_path / "dd", tmp_path / "q")
    assert [(r.name, r.version) for r in rows] == [("evil", "1.0"), ("evil2", "0.1")]
    ok, broken = rows
    assert ok.artifact_filename == "samples/pypi/malicious_intent/evil/1.0/2023-evil-v1.0.zip"
    assert ok.campaign_group.startswith("payload-") and len(ok.normalized_source_sha256) == 64
    assert "hash-error" in broken.notes and broken.normalized_source_sha256 == ""  # kept


def test_ossf_rows(tmp_path: Path) -> None:
    d = tmp_path / "osv" / "malicious" / "pypi" / "x"
    d.mkdir(parents=True)
    report = {
        "id": "MAL-1",
        "affected": [
            {"package": {"ecosystem": "PyPI", "name": "Evil_Pkg"}, "versions": ["1.0", "2.0"]},
            {"package": {"ecosystem": "PyPI", "name": "noversions"}},
            {"package": {"ecosystem": "npm", "name": "js"}, "versions": ["1"]},
        ],
    }
    (d / "MAL-1.json").write_text(json.dumps(report), encoding="utf-8")
    rows, skipped = bm.ossf_rows(tmp_path, known={("evil-pkg", "1.0")})
    assert [(r.name, r.version, r.source) for r in rows] == [("Evil_Pkg", "2.0", "openssf")]
    assert skipped == 1 and rows[0].notes == "osv:MAL-1"


def test_benign_rows_stratified_and_deterministic() -> None:
    names = [f"p{i}" for i in range(5000)]
    randoms = ["p3", "r1", "r2", "r3"]  # p3 is in the top 5,000 and must be dropped
    sizes = {"top-100": 10, "101-1000": 20, "1001-5000": 30, "random": 5}
    rows = bm.benign_rows(names, randoms, sizes, seed=1)
    assert rows == bm.benign_rows(names, randoms, sizes, seed=1)
    by = {b: [r.name for r in rows if r.popularity_band == b] for b in sizes}
    assert [len(v) for v in by.values()] == [10, 20, 30, 3]
    assert all(int(n[1:]) < 100 for n in by["top-100"])
    assert all(1000 <= int(n[1:]) < 5000 for n in by["1001-5000"])
    assert set(by["random"]) == {"r1", "r2", "r3"}
    assert {r.source for r in rows if r.popularity_band == "random"} == {"random-pypi"}


# ------------------------------------------------------------------ finalize


def _mal(name: str, group: str = "", norm: str = "", source: str = "datadog") -> ManifestRow:
    return ManifestRow(
        name=name,
        version="1",
        sha256=f"{abs(hash((name, group, norm))):064x}"[-64:],
        label="malicious",
        source=source,  # type: ignore[arg-type]
        campaign_group=group,
        normalized_source_sha256=norm,
    )


def _ben(name: str, band: str = "top-100") -> ManifestRow:
    return ManifestRow(name=name, label="benign", source="top-pypi", popularity_band=band)  # type: ignore[arg-type]


def test_finalize_exclusions_and_dedup() -> None:
    n = "c" * 64
    rows = [
        _mal("evil", norm=n),
        _mal("other", norm=n, source="openssf"),
        _ben("Evil"),  # same normalised name as a malicious row
        _ben("fine").model_copy(update={"notes": "fetch-failed: 404"}),
        _ben("good"),
    ]
    out = bm.finalize(rows)
    assert out[0].split != "excluded"
    assert (out[1].split, out[1].notes) == ("excluded", "excluded: duplicate payload")
    assert out[2].split == "excluded" and "malicious set" in out[2].notes
    assert out[3].split == "excluded" and out[3].notes.startswith("fetch-failed")
    assert out[4].split in ("train", "holdout")
    assert bm.finalize(out) == out  # idempotent


def test_finalize_review_sample_kept() -> None:
    rows = [_ben(f"b{i}", band) for i in range(40) for band in ("top-100", "random")]
    out = bm.finalize(rows)
    picked = [r for r in out if r.manual_review == "unreviewed"]
    assert len(picked) == 50
    assert {r.popularity_band for r in picked} == {"top-100", "random"}
    reviewed = [r.model_copy(update={"manual_review": "ok"}) if r.manual_review else r for r in out]
    assert sum(r.manual_review == "ok" for r in bm.finalize(reviewed)) == 50


def test_finalize_deterministic_and_frozen() -> None:
    rows = [_mal(f"m{i}", group=f"g{i % 7}") for i in range(30)] + [
        _ben(f"b{i}") for i in range(60)
    ]
    a = bm.finalize(rows, seed=3)
    assert a == bm.finalize(list(rows), seed=3)
    assert a != bm.finalize(rows, seed=4)
    # Adding unrelated rows does not move existing ones.
    b = bm.finalize([*rows, _ben("newcomer")], seed=3)
    assert [(r.split, r.fold) for r in b[: len(rows)]] == [(r.split, r.fold) for r in a]
    assert {r.split for r in a} == {"train", "holdout"}
    assert {r.fold for r in a if r.split == "train"} == set(range(5))


@settings(max_examples=60, deadline=None)
@given(
    st.lists(
        st.tuples(st.sampled_from("abcdefgh"), st.sampled_from(["", "g1", "g2", "g3", "g4"])),
        min_size=1,
        max_size=40,
    ),
    st.integers(0, 5),
)
def test_grouped_split_never_leaks(pairs: list[tuple[str, str]], seed: int) -> None:
    rows = [
        ManifestRow(
            name=name, version=str(i), label="malicious", source="datadog", campaign_group=g
        )
        for i, (name, g) in enumerate(pairs)
    ]
    out = [r for r in bm.finalize(rows, seed) if r.split != "excluded"]
    for key in ("name", "campaign_group"):
        where: dict[str, set] = {}
        for r in out:
            k = getattr(r, key)
            if k:
                where.setdefault(k, set()).add((r.split, r.fold))
        assert all(len(v) == 1 for v in where.values()), where
