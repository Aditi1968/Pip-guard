"""Stand-ins for parallel workstreams' modules, so these tests run without them."""

from __future__ import annotations

import sys
import tarfile
import types
import zipfile
from pathlib import Path

import pytest


def _fake_safe_extract(archive: Path, dest: Path) -> Path:
    # Test-made archives only; the real safe_extract does the hardening.
    dest.mkdir(parents=True, exist_ok=True)
    if archive.name.endswith((".zip", ".whl")):
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(dest)
    else:
        with tarfile.open(archive) as tf:
            tf.extractall(dest, filter="data")
    return dest


@pytest.fixture
def fake_extract(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    """Install a fake ``pipguard.extract``; returns the list of archives it was given."""
    calls: list[Path] = []
    mod = types.ModuleType("pipguard.extract")

    def safe_extract(archive: Path, dest: Path) -> Path:
        calls.append(archive)
        return _fake_safe_extract(archive, dest)

    mod.safe_extract = safe_extract  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "pipguard.extract", mod)
    return calls
