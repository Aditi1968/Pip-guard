import os
import socket

try:
    import subprocess
except ImportError:
    subprocess = None

if os.environ.get("CI"):
    pass
