"""Fixture (benign): writes a scratch file under /tmp at import."""

import tempfile

with tempfile.NamedTemporaryFile(dir="/tmp", prefix="fx") as _f:
    _f.write(b"cache")
