import ast
import csv
import subprocess
import sys
import zipfile
from datetime import date
from pathlib import Path

import pytest

from pipguard.models import (
    ArtifactKind,
    ArtifactStaticFeatures,
    PackageMetadata,
    PackageSpec,
    StaticFeatures,
    TyposquatResult,
)
from scripts.eval import batch_static
from scripts.eval.manifest import ManifestRow

ROOT = Path(__file__).resolve().parents[2]


def _row(name: str, sha: str, source: str = "top-pypi", split: str = "holdout") -> ManifestRow:
    return ManifestRow(
        name=name,
        version="1.0",
        artifact_filename=f"{name}.zip",
        sha256=sha,
        label="benign" if source == "top-pypi" else "malicious",
        source=source,  # type: ignore[arg-type]
        split=split,  # type: ignore[arg-type]
        fold=0 if split == "train" else None,
    )


def _fake_features(root: Path, row: ManifestRow) -> StaticFeatures:
    if row.name == "bad":
        raise RuntimeError("analysis blew up")
    return StaticFeatures(
        spec=PackageSpec(name=row.name, version=row.version),
        artifacts=[
            ArtifactStaticFeatures(
                filename=row.artifact_filename,
                sha256=row.sha256,
                kind=ArtifactKind.SDIST,
                py_file_count=len(list(root.rglob("*.py"))),
            )
        ],
        typosquat=TyposquatResult(snapshot_date=date(2026, 11, 1)),
        metadata=PackageMetadata(),
    )


def _read(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def test_errors_recorded_not_dropped_and_resumable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_extract: list
) -> None:
    monkeypatch.setattr(batch_static, "_static_features_for", _fake_features)
    arts = tmp_path / "arts"
    arts.mkdir()
    for name in ("good", "bad"):
        with zipfile.ZipFile(arts / f"{name}.zip", "w") as zf:
            zf.writestr(f"{name}/__init__.py", "x = 1\n")
    rows = [
        _row("good", "1" * 64),
        _row("bad", "2" * 64, split="train"),
        _row("absent", "3" * 64),  # artifact not downloaded
        _row("skipme", "4" * 64, split="excluded"),
    ]
    results = tmp_path / "res.csv"
    assert batch_static.run(rows, None, arts, tmp_path / "q", results) == (2, 1)
    recs = {r["sha256"]: r for r in _read(results)}
    assert recs["1" * 64]["status"] == "ok" and recs["1" * 64]["py_file_count"] == "1.0"
    assert recs["2" * 64]["status"] == "error" and "blew up" in recs["2" * 64]["error"]
    assert recs["2" * 64]["label"] == "benign"  # error rows keep their label untouched
    assert float(recs["1" * 64]["seconds"]) >= 0
    StaticFeatures.model_validate_json(recs["1" * 64]["static_features_json"])
    assert list(recs["1" * 64]) == batch_static.COLUMNS
    # Second run: nothing new, nothing duplicated.
    assert batch_static.run(rows, None, arts, tmp_path / "q", results) == (0, 1)
    assert len(_read(results)) == 2
    assert not list((tmp_path / "q").iterdir())  # temporary trees deleted


def test_extraction_failure_is_an_error_row(tmp_path: Path, fake_extract: list) -> None:
    arts = tmp_path / "arts"
    arts.mkdir()
    (arts / "junk.zip").write_bytes(b"not a zip")
    results = tmp_path / "res.csv"
    batch_static.run([_row("junk", "5" * 64)], None, arts, tmp_path / "q", results)
    assert _read(results)[0]["status"] == "error"


def test_locate() -> None:
    dd, arts = Path("/dd"), Path("/arts")
    path, pw = batch_static.locate(_row("x", "1" * 64, source="datadog"), dd, arts)
    assert path == dd / "x.zip" and pw == "infected"
    assert batch_static.locate(_row("x", "1" * 64), dd, arts) == (arts / "x.zip", None)


def test_static_adapter_uses_static_module(tmp_path: Path) -> None:
    static = pytest.importorskip("pipguard.static")
    (tmp_path / "m.py").write_text("x = 1\n", encoding="utf-8")
    if not hasattr(static, "analyze_dir"):
        pytest.skip("pipguard.static.analyze_dir not available")
    sf = batch_static._static_features_for(tmp_path, _row("requests", "1" * 64))
    assert sf.metadata == PackageMetadata() and len(sf.artifacts) == 1


def test_never_imports_sandbox() -> None:
    code = (
        "import sys, scripts.eval.batch_static, scripts.eval.build_manifest;"
        "assert not [m for m in sys.modules if m.startswith('pipguard.sandbox')]"
    )
    subprocess.run([sys.executable, "-c", code], cwd=ROOT, check=True)
    for mod in ("batch_static", "build_manifest", "fetch_artifacts", "train"):
        src = (ROOT / "scripts" / "eval" / f"{mod}.py").read_text(encoding="utf-8")
        names = [
            n.module if isinstance(n, ast.ImportFrom) else a.name
            for n in ast.walk(ast.parse(src))
            if isinstance(n, ast.Import | ast.ImportFrom)
            for a in n.names
        ]
        assert not [n for n in names if n and "sandbox" in n], mod


@pytest.mark.parametrize("flag", ["--sandbox", "--dynamic", "--run"])
def test_no_dynamic_option(flag: str) -> None:
    with pytest.raises(SystemExit) as e:
        batch_static.main([flag])
    assert e.value.code == 2
