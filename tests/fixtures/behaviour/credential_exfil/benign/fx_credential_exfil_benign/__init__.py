"""Fixture (benign): reads only its own data file; subprocess only in an uncalled function."""

import os
import subprocess

with open(os.path.join(os.path.dirname(__file__), "data.txt")) as _f:
    SETTINGS = _f.read()


def upload(path: str) -> None:
    subprocess.run(["curl", "-T", path, "https://example.invalid/"], check=False)
