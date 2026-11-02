"""Build a minimal pure-Python wheel from an in-memory file map, with no build backend.

Used by the week-1 spike and by test fixtures, so fixture wheels are produced
deterministically without running any setup.py. Writing a zip runs no package code.

    python scripts/make_wheel.py OUT_DIR NAME VERSION SRC_DIR [--requires REQ ...]
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import zipfile
from pathlib import Path

# Fixed timestamp so the same inputs always give the same wheel bytes and SHA-256.
_EPOCH = (2020, 1, 1, 0, 0, 0)


def _record_hash(data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return f"sha256={digest}"


def build_wheel(
    out_dir: Path,
    name: str,
    version: str,
    files: dict[str, str | bytes],
    requires: list[str] | None = None,
    top_level: list[str] | None = None,
) -> Path:
    """Write ``{name}-{version}-py3-none-any.whl`` into ``out_dir`` and return its path."""
    dist = name.replace("-", "_")
    info = f"{dist}-{version}.dist-info"
    meta = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
    meta += "".join(f"Requires-Dist: {r}\n" for r in requires or [])
    if top_level is None:
        top_level = sorted(
            {p.split("/")[0].removesuffix(".py") for p in files if "/" in p or p.endswith(".py")}
        )
    entries: dict[str, bytes] = {
        path: (data.encode() if isinstance(data, str) else data) for path, data in files.items()
    }
    entries[f"{info}/METADATA"] = meta.encode()
    entries[f"{info}/WHEEL"] = (
        b"Wheel-Version: 1.0\nGenerator: pipguard-make-wheel\nRoot-Is-Purelib: true\n"
        b"Tag: py3-none-any\n"
    )
    entries[f"{info}/top_level.txt"] = "".join(f"{t}\n" for t in top_level).encode()
    record = "".join(f"{p},{_record_hash(d)},{len(d)}\n" for p, d in entries.items())
    record += f"{info}/RECORD,,\n"
    entries[f"{info}/RECORD"] = record.encode()

    out_dir.mkdir(parents=True, exist_ok=True)
    wheel = out_dir / f"{dist}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, data in entries.items():
            zi = zipfile.ZipInfo(path, _EPOCH)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o644 << 16
            zf.writestr(zi, data)
    return wheel


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("out_dir", type=Path)
    ap.add_argument("name")
    ap.add_argument("version")
    ap.add_argument("src_dir", type=Path, help="directory whose files become the wheel contents")
    ap.add_argument("--requires", nargs="*", default=[])
    a = ap.parse_args()
    files: dict[str, str | bytes] = {
        p.relative_to(a.src_dir).as_posix(): p.read_bytes()
        for p in sorted(a.src_dir.rglob("*"))
        if p.is_file() and "__pycache__" not in p.parts
    }
    print(build_wheel(a.out_dir, a.name, a.version, files, a.requires))


if __name__ == "__main__":
    main()
