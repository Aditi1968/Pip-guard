import hashlib
import zipfile
from pathlib import Path

from scripts.make_wheel import build_wheel


def test_wheel_layout_and_determinism(tmp_path: Path) -> None:
    files: dict[str, str | bytes] = {"pkg/__init__.py": "X = 1\n"}
    w1 = build_wheel(tmp_path / "a", "my-pkg", "1.0", files, requires=["dep==2"])
    w2 = build_wheel(tmp_path / "b", "my-pkg", "1.0", files, requires=["dep==2"])
    assert w1.name == "my_pkg-1.0-py3-none-any.whl"
    assert hashlib.sha256(w1.read_bytes()).digest() == hashlib.sha256(w2.read_bytes()).digest()
    with zipfile.ZipFile(w1) as zf:
        names = set(zf.namelist())
        meta = zf.read("my_pkg-1.0.dist-info/METADATA").decode()
        top = zf.read("my_pkg-1.0.dist-info/top_level.txt").decode()
    assert {"pkg/__init__.py", "my_pkg-1.0.dist-info/RECORD"} <= names
    assert "Requires-Dist: dep==2" in meta
    assert top == "pkg\n"
