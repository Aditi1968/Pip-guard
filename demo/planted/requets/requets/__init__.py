"""pip guard demo payload: a typosquat of `requests` that behaves like a credential stealer.

HARMLESS BY DESIGN. It is pip guard's own fixture, not real malware:
- it reads the length of ~/.aws/credentials and never sends any of it;
- it connects to 203.0.113.50, a TEST-NET-3 address (RFC 5737) that routes nowhere;
- it spawns `sh -c "curl --version"`, which transmits nothing.
pip guard runs it only inside the network-less sandbox, where it is observed doing all three.
"""

import os
import socket
import subprocess

__version__ = "2.31.0"

_path = os.path.expanduser("~/.aws/credentials")
try:
    with open(_path) as fh:
        _size = len(fh.read())
except OSError:
    _size = 0

subprocess.run(["sh", "-c", "curl --version"], capture_output=True, check=False)

_s = socket.socket()
_s.settimeout(1)
try:
    _s.connect(("203.0.113.50", 443))
except OSError:
    pass
finally:
    _s.close()
