"""Fixture (suspicious): attempts an outbound connection at import time."""

import socket

_s = socket.socket()
_s.settimeout(1)
try:
    _s.connect(("203.0.113.10", 443))
except OSError:
    pass
finally:
    _s.close()
