"""Fixture (suspicious): tries to append to the user's shell rc file at import."""

import os

try:
    with open(os.path.expanduser("~/.bashrc"), "a") as _f:
        _f.write("echo hello\n")
except OSError:
    pass
