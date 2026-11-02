import json
from pathlib import Path

from sandbox.seed_credentials import seed

MANIFEST = Path(__file__).parents[1] / "sandbox" / "manifest.json"


def test_seeds_every_manifest_file_without_marker(tmp_path: Path) -> None:
    written = seed(tmp_path)
    manifest = json.loads(MANIFEST.read_text())
    home = manifest["home"]
    assert sorted(p.relative_to(tmp_path).as_posix() for p in written) == sorted(
        f.removeprefix(home + "/") for f in manifest["files"]
    )
    for p in written:
        text = p.read_text()
        # FR-4.3: the word "fake" lives in the manifest, never in the values.
        assert "fake" not in text.lower()
    assert "AKIA" in (tmp_path / ".aws/credentials").read_text()


def test_values_differ_per_build(tmp_path: Path) -> None:
    a = seed(tmp_path / "a")[0].read_text()
    b = seed(tmp_path / "b")[0].read_text()
    assert a != b
