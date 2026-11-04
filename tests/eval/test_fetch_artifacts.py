import hashlib
import zipfile
from pathlib import Path

import pytest

from pipguard.models import (
    Artifact,
    ArtifactKind,
    FetchedPackage,
    PackageMetadata,
    PackageSpec,
)
from scripts.eval import fetch_artifacts as fa
from scripts.eval.manifest import ManifestRow


def _row(**kw) -> ManifestRow:
    return ManifestRow.model_validate(
        {"name": "Some_Pkg", "label": "benign", "source": "top-pypi"} | kw
    )


def test_fetch_row_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_extract) -> None:
    arts = tmp_path / "arts"

    def fake_fetch(spec: PackageSpec, dest: Path) -> FetchedPackage:
        dest.mkdir(parents=True)
        path = dest / "some_pkg-2.0.zip"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("some_pkg/__init__.py", "x = 1\n")
        sha = hashlib.sha256(path.read_bytes()).hexdigest()
        art = Artifact(
            filename=path.name, kind=ArtifactKind.SDIST, sha256=sha, size=1, path=str(path)
        )
        return FetchedPackage(spec=spec, artifacts=[art], metadata=PackageMetadata(), origin="pypi")

    monkeypatch.setattr(fa, "_latest_version", lambda name: "2.0")
    monkeypatch.setattr(fa, "_fetch", fake_fetch)
    out = fa.fetch_row(_row(notes="fetch-failed: old"), arts, tmp_path / "q")
    assert out.version == "2.0" and out.artifact_filename == "some-pkg-2.0/some_pkg-2.0.zip"
    assert len(out.sha256) == 64 and len(out.normalized_source_sha256) == 64
    assert out.notes == "" and out.campaign_group == ""


def test_fetch_row_failure_recorded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(spec: PackageSpec, dest: Path) -> FetchedPackage:
        raise OSError("404 yanked")

    monkeypatch.setattr(fa, "_fetch", boom)
    out = fa.fetch_row(_row(version="1.0", label="malicious", source="openssf"), tmp_path, tmp_path)
    assert out.sha256 == "" and out.notes.startswith("fetch-failed: OSError: 404 yanked")
