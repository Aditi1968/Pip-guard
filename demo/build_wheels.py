"""Build the demo's planted wheels into DEST (default: demo/template/vendor/wheels).

    uv run python -m demo.build_wheels [DEST]

Wheels are built with scripts/make_wheel.py: zipping files runs no package code.
"""

from __future__ import annotations

import sys
from pathlib import Path

from scripts.make_wheel import build_wheel

HERE = Path(__file__).parent
PLANTED = {"requets": "2.31.0", "sleepy": "1.0.0"}


def build(dest: Path) -> list[Path]:
    out = []
    for name, version in PLANTED.items():
        src = HERE / "planted" / name
        files: dict[str, str | bytes] = {
            p.relative_to(src).as_posix(): p.read_bytes() for p in sorted(src.rglob("*.py"))
        }
        out.append(build_wheel(dest, name, version, files))
    return out


if __name__ == "__main__":
    dest = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "template" / "vendor" / "wheels"
    for wheel in build(dest):
        print(wheel)
